use crate::persistor::{MemoryPersistor, PERSISTOR, Persistor};
use crate::{session_persistor_for, sync_error, sync_heap_read, sync_is_node, SESSIONS, NULL, SYNC_NODE_TAG, Word};
use crate::evaluator as s7;
use libc;
use lru::LruCache;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::Mutex;

const STRICT_EVAL_CACHE_CAPACITY: usize = 4096;

#[derive(Clone)]
struct StrictEvalCache {
    // The persistor holds the actual cached outputs. The LRU only tracks
    // which input-node keys should remain rooted there.
    entries: LruCache<Word, ()>,
    persistor: MemoryPersistor,
}

impl StrictEvalCache {
    fn new() -> Self {
        Self {
            entries: LruCache::new(
                NonZeroUsize::new(STRICT_EVAL_CACHE_CAPACITY)
                    .expect("Strict eval cache capacity must be non-zero"),
            ),
            persistor: MemoryPersistor::new(),
        }
    }
}

static STRICT_EVAL_CACHE: Lazy<Mutex<StrictEvalCache>> =
    Lazy::new(|| Mutex::new(StrictEvalCache::new()));

#[derive(Clone)]
pub(crate) struct OverlayPersistor {
    pub(crate) primary: MemoryPersistor,
    pub(crate) overlay: Option<MemoryPersistor>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolveSource {
    Session,
    Overlay,
    Global,
}

pub(crate) enum ResolvedNode {
    Branch((Word, Word, Word), ResolveSource),
    Leaf(Vec<u8>, ResolveSource),
    Stump(Word, ResolveSource),
}

impl Persistor for OverlayPersistor {
    fn root_list(&self) -> Vec<Word> {
        self.primary.root_list()
    }

    fn root_new(
        &self,
        handle: Word,
        root: Word,
    ) -> Result<Word, crate::persistor::PersistorAccessError> {
        self.primary.root_new(handle, root)
    }

    fn root_temp(&self, root: Word) -> Result<Word, crate::persistor::PersistorAccessError> {
        self.primary.root_temp(root)
    }

    fn root_get(&self, handle: Word) -> Result<Word, crate::persistor::PersistorAccessError> {
        self.primary.root_get(handle)
    }

    fn root_set(
        &self,
        handle: Word,
        old: Word,
        new: Word,
        source: &dyn Persistor,
    ) -> Result<Word, crate::persistor::PersistorAccessError> {
        self.primary.root_set(handle, old, new, source)
    }

    fn root_delete(&self, handle: Word) -> Result<(), crate::persistor::PersistorAccessError> {
        self.primary.root_delete(handle)
    }

    fn branch_set(
        &self,
        left: Word,
        right: Word,
        digest: Word,
    ) -> Result<Word, crate::persistor::PersistorAccessError> {
        self.primary.branch_set(left, right, digest)
    }

    fn branch_get(
        &self,
        branch: Word,
    ) -> Result<(Word, Word, Word), crate::persistor::PersistorAccessError> {
        if let Ok(found) = self.primary.branch_get(branch) {
            Ok(found)
        } else if let Some(overlay) = &self.overlay {
            overlay.branch_get(branch)
        } else {
            Err(crate::persistor::PersistorAccessError(format!(
                "Branch {:?} not found",
                branch
            )))
        }
    }

    fn leaf_set(&self, content: Vec<u8>) -> Result<Word, crate::persistor::PersistorAccessError> {
        self.primary.leaf_set(content)
    }

    fn leaf_get(&self, leaf: Word) -> Result<Vec<u8>, crate::persistor::PersistorAccessError> {
        if let Ok(found) = self.primary.leaf_get(leaf) {
            Ok(found)
        } else if let Some(overlay) = &self.overlay {
            overlay.leaf_get(leaf)
        } else {
            Err(crate::persistor::PersistorAccessError(format!(
                "Leaf {:?} not found",
                leaf
            )))
        }
    }

    fn stump_set(&self, digest: Word) -> Result<Word, crate::persistor::PersistorAccessError> {
        self.primary.stump_set(digest)
    }

    fn stump_get(&self, stump: Word) -> Result<Word, crate::persistor::PersistorAccessError> {
        if let Ok(found) = self.primary.stump_get(stump) {
            Ok(found)
        } else if let Some(overlay) = &self.overlay {
            overlay.stump_get(stump)
        } else {
            Err(crate::persistor::PersistorAccessError(format!(
                "Stump {:?} not found",
                stump
            )))
        }
    }
}

fn strict_session_overlay_handle(sc: *mut s7::s7_scheme, root: Word) -> Word {
    let mut hasher = Sha256::new();
    hasher.update(b"strict-session-overlay-root");
    hasher.update((sc as usize).to_le_bytes());
    hasher.update(root);
    hasher.finalize().into()
}

pub(crate) unsafe fn strict_cache_get(
    sc: *mut s7::s7_scheme,
    key: Word,
) -> Option<s7::s7_pointer> {
    unsafe {
        let mut cache = STRICT_EVAL_CACHE
            .lock()
            .expect("Failed to lock strict sync-eval cache");
        cache.entries.get(&key)?;
        let persistor = cache.persistor.clone();
        drop(cache);
        Some(strict_cache_materialize(sc, key, &persistor))
    }
}

pub(crate) unsafe fn strict_cache_put(
    sc: *mut s7::s7_scheme,
    key: Word,
    result: s7::s7_pointer,
) -> s7::s7_pointer {
    unsafe {
        if s7::s7_is_procedure(result) || s7::s7_is_macro(sc, result) {
            return sync_error(
                sc,
                "Strict sync-eval cannot cache procedure or macro results",
            );
        }

        if result == s7::s7_unspecified(sc) {
            return sync_error(sc, "Strict sync-eval cannot cache unspecified results");
        }

        let session_persistor = session_persistor_for(sc);

        let mut cache = STRICT_EVAL_CACHE
            .lock()
            .expect("Failed to lock strict sync-eval cache");

        if cache.entries.get(&key).is_some() {
            let persistor = cache.persistor.clone();
            drop(cache);
            return strict_cache_materialize(sc, key, &persistor);
        }

        if sync_is_node(result) {
            let result_word = sync_heap_read(s7::s7_c_object_value(result));
            if let Err(err) =
                strict_cache_store_node(&cache.persistor, key, result_word, &session_persistor)
            {
                return sync_error(
                    sc,
                    format!("Strict sync-eval failed to persist cached node: {}", err.0).as_str(),
                );
            }
        } else if s7::s7_is_byte_vector(result) {
            let mut bytes = Vec::with_capacity(s7::s7_vector_length(result) as usize);
            for i in 0..s7::s7_vector_length(result) {
                bytes.push(s7::s7_byte_vector_ref(result, i as i64));
            }

            if let Err(err) = strict_cache_store_byte_vector(&cache.persistor, key, bytes) {
                return sync_error(
                    sc,
                    format!("Strict sync-eval failed to persist cached byte-vector: {}", err.0)
                        .as_str(),
                );
            }
        } else {
            return sync_error(
                sc,
                "Strict sync-eval must return a sync-node or byte-vector",
            );
        }
        let node_result = sync_is_node(result);

        if let Some((evicted, ())) = cache.entries.push(key, ()) {
            let _ = cache.persistor.root_delete(evicted);
        }

        let persistor = cache.persistor.clone();
        drop(cache);
        if node_result {
            result
        } else {
            strict_cache_materialize(sc, key, &persistor)
        }
    }
}

fn strict_cache_ensure_root(
    cache_persistor: &MemoryPersistor,
    handle: Word,
) -> Result<Word, crate::persistor::PersistorAccessError> {
    match cache_persistor.root_get(handle) {
        Ok(root) => Ok(root),
        Err(_) => {
            cache_persistor.root_new(handle, NULL)?;
            Ok(NULL)
        }
    }
}

fn strict_cache_store_node(
    cache_persistor: &MemoryPersistor,
    handle: Word,
    result_word: Word,
    source: &dyn Persistor,
) -> Result<(), crate::persistor::PersistorAccessError> {
    let old_root = strict_cache_ensure_root(cache_persistor, handle)?;
    cache_persistor.root_set(handle, old_root, result_word, source)?;
    Ok(())
}

fn strict_cache_store_byte_vector(
    cache_persistor: &MemoryPersistor,
    handle: Word,
    bytes: Vec<u8>,
) -> Result<(), crate::persistor::PersistorAccessError> {
    let leaf = cache_persistor.leaf_set(bytes)?;
    let old_root = strict_cache_ensure_root(cache_persistor, handle)?;
    cache_persistor.root_set(handle, old_root, leaf, cache_persistor)?;
    Ok(())
}

unsafe fn strict_cache_materialize(
    sc: *mut s7::s7_scheme,
    handle: Word,
    cache_persistor: &MemoryPersistor,
) -> s7::s7_pointer {
    unsafe {
        let root = match cache_persistor.root_get(handle) {
            Ok(root) => root,
            Err(err) => {
                return sync_error(
                    sc,
                    format!("Strict sync-eval cache root missing: {}", err.0).as_str(),
                );
            }
        };
        if let Ok(content) = cache_persistor.leaf_get(root) {
            let bv =
                s7::s7_make_byte_vector(sc, content.len() as i64, 1, std::ptr::null_mut());
            for (i, byte) in content.iter().enumerate() {
                s7::s7_byte_vector_set(bv, i as i64, *byte);
            }
            return bv;
        }

        // Node hits stay in the cache persistor and are pinned into the session by
        // attaching a session-scoped overlay root rather than replaying the graph.
        let overlay_handle = strict_session_overlay_handle(sc, root);
        let attached = {
            let session = SESSIONS.read().expect("Failed to acquire sessions lock");
            session
                .get(&(sc as usize))
                .expect("Session not found in sessions map")
                .strict_overlay_handles
                .contains(&overlay_handle)
        };
        if !attached {
            if let Err(err) = cache_persistor.root_new(overlay_handle, root) {
                match cache_persistor.root_get(overlay_handle) {
                    Ok(existing) if existing == root => {}
                    _ => {
                        return sync_error(
                            sc,
                            format!(
                                "Strict sync-eval failed to attach cache overlay root: {}",
                                err.0
                            )
                            .as_str(),
                        );
                    }
                }
            }
            let mut sessions = SESSIONS.write().expect("Failed to acquire sessions lock");
            let session = sessions
                .get_mut(&(sc as usize))
                .expect("Session not found in sessions map");
            session.strict_overlay_persistor = Some(cache_persistor.clone());
            session.strict_overlay_handles.insert(overlay_handle);
        }
        s7::s7_make_c_object(sc, SYNC_NODE_TAG, sync_heap_make(root))
    }
}

pub(crate) fn resolve_branch_with(
    persistor: &MemoryPersistor,
    overlay: Option<&MemoryPersistor>,
    word: Word,
) -> Option<((Word, Word, Word), ResolveSource)> {
    persistor
        .branch_get(word)
        .ok()
        .map(|branch| (branch, ResolveSource::Session))
        .or_else(|| {
            overlay
                .and_then(|overlay| overlay.branch_get(word).ok())
                .map(|branch| (branch, ResolveSource::Overlay))
        })
        .or_else(|| {
            PERSISTOR
                .branch_get(word)
                .ok()
                .map(|branch| (branch, ResolveSource::Global))
        })
}

pub(crate) fn resolve_leaf_with(
    persistor: &MemoryPersistor,
    overlay: Option<&MemoryPersistor>,
    word: Word,
) -> Option<(Vec<u8>, ResolveSource)> {
    persistor
        .leaf_get(word)
        .ok()
        .map(|content| (content, ResolveSource::Session))
        .or_else(|| {
            overlay
                .and_then(|overlay| overlay.leaf_get(word).ok())
                .map(|content| (content, ResolveSource::Overlay))
        })
        .or_else(|| {
            PERSISTOR
                .leaf_get(word)
                .ok()
                .map(|content| (content, ResolveSource::Global))
        })
}

pub(crate) fn resolve_stump_with(
    persistor: &MemoryPersistor,
    overlay: Option<&MemoryPersistor>,
    word: Word,
) -> Option<(Word, ResolveSource)> {
    persistor
        .stump_get(word)
        .ok()
        .map(|digest| (digest, ResolveSource::Session))
        .or_else(|| {
            overlay
                .and_then(|overlay| overlay.stump_get(word).ok())
                .map(|digest| (digest, ResolveSource::Overlay))
        })
        .or_else(|| {
            PERSISTOR
                .stump_get(word)
                .ok()
                .map(|digest| (digest, ResolveSource::Global))
        })
}

pub(crate) fn resolve_node_with(
    persistor: &MemoryPersistor,
    overlay: Option<&MemoryPersistor>,
    word: Word,
) -> Option<ResolvedNode> {
    resolve_branch_with(persistor, overlay, word)
        .map(|(branch, source)| ResolvedNode::Branch(branch, source))
        .or_else(|| {
            resolve_leaf_with(persistor, overlay, word)
                .map(|(content, source)| ResolvedNode::Leaf(content, source))
        })
        .or_else(|| {
            resolve_stump_with(persistor, overlay, word)
                .map(|(digest, source)| ResolvedNode::Stump(digest, source))
        })
}

unsafe fn sync_heap_make(sync: Word) -> *mut libc::c_void {
    let boxed = Box::new(sync);
    Box::into_raw(boxed) as *mut libc::c_void
}

#[cfg(test)]
mod tests {
    use super::{OverlayPersistor, strict_cache_store_byte_vector, strict_cache_store_node};
    use crate::NULL;
    use crate::persistor::{MemoryPersistor, Persistor};
    use crate::{SIZE, Word};

    fn word(byte: u8) -> Word {
        [byte; SIZE]
    }

    #[test]
    fn test_overlay_persistor_supports_commit_from_overlay_source() {
        let target = MemoryPersistor::new();
        let session = MemoryPersistor::new();
        let overlay = MemoryPersistor::new();
        let handle = word(1);
        let zeros = NULL;

        let left = overlay.leaf_set(vec![1]).expect("left leaf");
        let right = overlay.leaf_set(vec![2]).expect("right leaf");
        let branch = overlay.branch_set(left, right, zeros).expect("overlay branch");

        target.root_new(handle, zeros).expect("target root");
        let source = OverlayPersistor {
            primary: session,
            overlay: Some(overlay),
        };

        target
            .root_set(handle, zeros, branch, &source)
            .expect("commit through overlay source");

        assert_eq!(target.root_get(handle).expect("target root get"), branch);
        assert_eq!(
            target.branch_get(branch).expect("target branch get"),
            (left, right, zeros)
        );
        assert_eq!(target.leaf_get(left).expect("left leaf get"), vec![1]);
        assert_eq!(target.leaf_get(right).expect("right leaf get"), vec![2]);
    }

    #[test]
    fn test_strict_cache_stores_byte_vector_as_leaf_root() {
        let cache = MemoryPersistor::new();
        let key = word(2);
        let bytes = vec![9, 8, 7, 6];

        strict_cache_store_byte_vector(&cache, key, bytes.clone()).expect("store byte-vector");

        let root = cache.root_get(key).expect("root get");
        assert_eq!(cache.leaf_get(root).expect("leaf get"), bytes);
    }

    #[test]
    fn test_strict_cache_stores_node_as_rooted_graph() {
        let cache = MemoryPersistor::new();
        let source = MemoryPersistor::new();
        let key = word(3);
        let zeros = NULL;

        let left = source.leaf_set(vec![4]).expect("left leaf");
        let right = source.leaf_set(vec![5]).expect("right leaf");
        let branch = source.branch_set(left, right, zeros).expect("source branch");

        strict_cache_store_node(&cache, key, branch, &source).expect("store node");

        assert_eq!(cache.root_get(key).expect("root get"), branch);
        assert_eq!(
            cache.branch_get(branch).expect("branch get"),
            (left, right, zeros)
        );
    }
}
