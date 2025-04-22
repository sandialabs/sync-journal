use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use sha2::{Sha256, Digest};
use rand::prelude::SliceRandom;
use crate::config::Config;
use rand::RngCore;

use rocksdb::{DB, Options, ColumnFamilyDescriptor};

pub static PERSISTOR: Lazy<Box<dyn Persistor + Send + Sync>> = Lazy::new(|| {
    let config = Config::new();
    match config.database.as_str() {
        "" => Box::new(MemoryPersistor::new()),
        path => Box::new(DatabasePersistor::new(path)),
    }
});

/// Size, in bytes, of the global hash algorithm (currently SHA-256)
pub const SIZE: usize = 32;

/// Byte array describing a hash pointer (currently SHA-256)
pub type Word = [u8; SIZE];

#[allow(dead_code)]
#[derive(Debug)]
pub struct PersistorAccessError(pub String);

pub trait Persistor {
    fn root_list(&self) -> Vec<Word>;
    fn root_new(&self, handle: Word, root: Word) -> Result<Word, PersistorAccessError>;
    fn root_temp(&self, root: Word) -> Result<Word, PersistorAccessError>;
    fn root_get(&self, handle: Word) -> Result<Word, PersistorAccessError> ;
    fn root_set(&self, handle: Word, old: Word, new: Word) -> Result<Word, PersistorAccessError>;
    fn root_delete(&self, handle: Word) -> Result<(), PersistorAccessError>;
    fn branch_set(&self, left: Word, right: Word) -> Result<Word, PersistorAccessError>;
    fn branch_get(&self, branch: Word) -> Result<(Word, Word), PersistorAccessError>;
    fn leaf_set(&self, content: Vec<u8>) -> Result<Word, PersistorAccessError>;
    fn leaf_get(&self, leaf: Word) -> Result<Vec<u8>, PersistorAccessError>;
}

#[derive(Clone)]
pub struct MemoryPersistor {
    roots: Arc<Mutex<HashMap<Word, (Word, bool)>>>,
    branches: Arc<Mutex<HashMap<Word, (Word, Word)>>>,
    leaves: Arc<Mutex<HashMap<Word, Vec<u8>>>>,
    references: Arc<Mutex<HashMap<Word, usize>>>,
}

impl MemoryPersistor {
    pub fn new() -> Self {
        Self {
            roots: Arc::new(Mutex::new(HashMap::new())),
            branches: Arc::new(Mutex::new(HashMap::new())),
            leaves: Arc::new(Mutex::new(HashMap::new())),
            references: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn reference_increment(&self, node: Word) {
        let mut references = self.references.lock().unwrap();
        match references.get(&node) {
            Some(count) => {
                let count_ = *count;
                references.insert(node, count_ + 1);
            },
            None => { references.insert(node, 1); },
        };
    }

    fn reference_decrement(&self, node: Word) {
        let mut references = self.references.lock().unwrap();
        match references.get(&node) {
            Some(count_old) => {
                let count_new = *count_old - 1;
                if count_new > 0 {
                    references.insert(node, count_new);
                } else {
                    references.remove(&node);
                    let mut branches = self.branches.lock().unwrap();
                    if let Some((left, right)) = branches.get(&node) {
                        let left_ = *left;
                        let right_ = *right;
                        branches.remove(&node);
                        drop(references);
                        drop(branches);
                        self.reference_decrement(left_);
                        self.reference_decrement(right_);
                    } else {
                        let mut leaves = self.leaves.lock().unwrap();
                        if let Some(_) = leaves.get(&node) {
                            leaves.remove(&node);
                        }
                    }
                }
            },
            None => {},
        };
    }
}

impl Persistor for MemoryPersistor {
    fn root_list(&self) -> Vec<Word> {
        let mut keys: Vec<Word> = self.roots.lock().unwrap().iter()
            .filter(|&(_, &(_, is_persistent))| is_persistent)
            .map(|(key, _)| key)
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    fn root_new(&self, handle: Word, root: Word) -> Result<Word, PersistorAccessError> {
        let mut roots = self.roots.lock().unwrap();
        match roots.get(&handle) {
            Some(_) => Err(PersistorAccessError(format!("Handle {:?} already exists", handle))),
            None => {
                self.reference_increment(root);
                roots.insert(handle, (root, true));
                Ok(handle)
            },
        }
    }

    fn root_temp(&self, root: Word) -> Result<Word, PersistorAccessError> {
        let mut roots = self.roots.lock().unwrap();
        let mut handle: Word = [0 as u8; 32];
        rand::thread_rng().fill_bytes(&mut handle);
        match roots.get(&handle) {
            Some(_) => Err(PersistorAccessError(format!("Handle {:?} already exists", handle))),
            None => {
                self.reference_increment(root);
                roots.insert(handle, (root, false));
                Ok(handle)
            },
        }
    }

    fn root_get(&self, handle: Word) -> Result<Word, PersistorAccessError> {
        match self.roots.lock().unwrap().get(&handle) {
            Some((root, _)) => Ok(*root),
            None => Err(PersistorAccessError(format!("Handle {:?} not found", handle))),
        }
    }

    fn root_set(&self, handle: Word, old: Word, new: Word) -> Result<Word, PersistorAccessError> {
        let mut roots = self.roots.lock().unwrap();
        match roots.get(&handle) {
            Some((root, true)) if *root == old => {
                self.reference_increment(new);
                self.reference_decrement(old);
                roots.insert(handle, (new, true));
                Ok(handle)
            },
            Some((_, false)) => Err(PersistorAccessError(format!("Handle {:?} is temporary", handle))),
            Some((_, true)) => Err(PersistorAccessError(format!("Handle {:?} changed since compare", handle))),
            None => Err(PersistorAccessError(format!("Handle {:?} not found", handle))),
        }
    }

    fn root_delete(&self, handle: Word) -> Result<(), PersistorAccessError> {
        let mut roots = self.roots.lock().unwrap();
        match roots.get(&handle) {
            Some((old, _)) => {
                self.reference_decrement(*old);
                roots.remove(&handle);
                Ok(())
            },
            None => Err(PersistorAccessError(format!("Handle {:?} not found", handle))),
        }
    }

    fn branch_set(&self, left: Word, right: Word) -> Result<Word, PersistorAccessError> {
        let mut joined = [0 as u8; SIZE * 2];
        joined[..SIZE].copy_from_slice(&left);
        joined[SIZE..].copy_from_slice(&right);

        let branch = Sha256::digest(joined);
        self.branches.lock().unwrap().insert(branch.into(), (left, right));
        self.reference_increment(left);
        self.reference_increment(right);
        Ok(Word::from(branch))
    }

    fn branch_get(&self, branch: Word) -> Result<(Word, Word), PersistorAccessError> {
        let branches = self.branches.lock().unwrap();
        match branches.get(&branch) {
            Some((left, right)) => {
                let mut joined = [0 as u8; SIZE * 2];
                joined[..SIZE].copy_from_slice(left);
                joined[SIZE..].copy_from_slice(right);
                assert!(Vec::from(branch) == Sha256::digest(joined).to_vec());
                Ok((*left, *right))
            },
            None => Err(PersistorAccessError(format!("Branch {:?} not found", branch))),
        }
    }

    fn leaf_set(&self, content: Vec<u8>) -> Result<Word, PersistorAccessError> {
        let leaf = Word::from(Sha256::digest(Sha256::digest(&content)));
        self.leaves.lock().unwrap().insert(leaf, content);
        Ok(leaf)
    }

    fn leaf_get(&self, leaf: Word) -> Result<Vec<u8>, PersistorAccessError> {
        let leaves = self.leaves.lock().unwrap();
        match leaves.get(&leaf) {
            Some(content) => {
                assert!(Vec::from(leaf) == Sha256::digest(Sha256::digest(content)).to_vec());
                Ok(content.to_vec())
            }
            None => Err(PersistorAccessError(format!("Leaf {:?} not found", leaf))),
        }
    }
}

pub struct DatabasePersistor {
    db: Mutex<DB>,
}

impl DatabasePersistor {
    pub fn new(path: &str) -> Self {

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new("roots", Options::default()),
            ColumnFamilyDescriptor::new("branches", Options::default()),
            ColumnFamilyDescriptor::new("leaves", Options::default()),
            ColumnFamilyDescriptor::new("references", Options::default()),
        ];

        let persistor = Self {
            db: Mutex::new(DB::open_cf_descriptors(&opts, path, cfs).unwrap()),
        };

        {
            let mut handles: Vec<Word> = Vec::new();
            let db = persistor.db.lock().unwrap();
            let mut iter = db.raw_iterator_cf(db.cf_handle("roots").unwrap());
            iter.seek_to_first();
            while iter.valid() {
                if (*iter.value().unwrap())[SIZE] == false as u8 {
                    handles.push((*iter.key().unwrap()).try_into().unwrap());
                }
                iter.next();
            }
            for handle in handles {
                db.delete_cf(db.cf_handle("roots").unwrap(), handle).unwrap();
            }
        }

        persistor
    }

    fn reference_increment(&self, node: Word) {
        let db = self.db.lock().unwrap();
        let references = db.cf_handle("references").unwrap();
        match db.get_cf(references, node) {
            Ok(Some(count)) => {
                db.put_cf(
                    references,
                    node,
                    (usize::from_ne_bytes(count.try_into().unwrap()) + 1).to_ne_bytes(),
                ).unwrap();
            },
            Ok(None) => { db.put_cf(references, node, (1 as usize).to_ne_bytes()).unwrap() },
            Err(e) => { panic!{"{}", e} },
        };
    }

    fn reference_decrement(&self, node: Word) {
        let db = self.db.lock().unwrap();
        let branches = db.cf_handle("branches").unwrap();
        let leaves = db.cf_handle("leaves").unwrap();
        let references = db.cf_handle("references").unwrap();
        match db.get_cf(references, node).unwrap() {
            Some(count_old) => {
                let count_new = usize::from_ne_bytes(count_old.try_into().unwrap()) - 1;
                if count_new > 0 {
                    db.put_cf(references, node, count_new.to_ne_bytes()).unwrap();
                } else {
                    db.delete_cf(references, node).unwrap();
                    if let Some(value) = db.get_cf(branches, node).unwrap() {
                        let left = &value[..SIZE].try_into().unwrap();
                        let right = &value[SIZE..].try_into().unwrap();
                        db.delete_cf(branches, node).unwrap();
                        drop(db);
                        self.reference_decrement(*left);
                        self.reference_decrement(*right);
                    } else {
                        if let Some(_) = db.get_cf(leaves, node).unwrap() {
                            db.delete_cf(leaves, node).unwrap();
                        }
                    }
                }
            },
            None => {},
        };
    }
}

impl Persistor for DatabasePersistor {
    fn root_list(&self) -> Vec<Word> {
        let mut handles: Vec<Word> = Vec::new();
        let db = self.db.lock().unwrap();
        let roots = db.cf_handle("roots").unwrap();
        let mut iter = db.raw_iterator_cf(roots);
        iter.seek_to_first();
        while iter.valid() {
            if (*iter.value().unwrap())[SIZE] != false as u8 {
                handles.push((*iter.key().unwrap()).try_into().unwrap());
            }
            iter.next();
        }
        
        handles.shuffle(&mut rand::thread_rng());
        handles
    }

    fn root_new(&self, handle: Word, root: Word) -> Result<Word, PersistorAccessError> {
        let mut root_marked = [0 as u8; SIZE + 1];
        root_marked[..SIZE].copy_from_slice(&root);
        root_marked[SIZE] = true as u8;

        let db = self.db.lock().unwrap();
        let roots = db.cf_handle("roots").unwrap();
        match db.get_cf(roots, handle) {
            Ok(Some(_)) => Err(PersistorAccessError(format!("Handle {:?} already exists", handle))),
            Ok(None) => {
                db.put_cf(roots, handle, root_marked).unwrap();
                drop(db);
                self.reference_increment(root);
                Ok(handle)
            },
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn root_temp(&self, root: Word) -> Result<Word, PersistorAccessError> {
        let mut root_marked = [0 as u8; SIZE + 1];
        root_marked[..SIZE].copy_from_slice(&root);
        root_marked[SIZE] = false as u8;

        let mut handle: Word = [0 as u8; 32];
        rand::thread_rng().fill_bytes(&mut handle);
        let db = self.db.lock().unwrap();
        let roots = db.cf_handle("roots").unwrap();
        match db.get_cf(roots, handle) {
            Ok(Some(_)) => Err(PersistorAccessError(format!("Handle {:?} already exists", handle))),
            Ok(None) => {
                db.put_cf(roots, handle, root_marked).unwrap();
                drop(db);
                self.reference_increment(root);
                Ok(handle)
            },
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn root_get(&self, handle: Word) -> Result<Word, PersistorAccessError> {    
        let db = self.db.lock().unwrap();
        let roots = db.cf_handle("roots").unwrap();
        match db.get_cf(roots, handle) {
            Ok(Some(root_marked)) => Ok(((*root_marked)[..SIZE]).try_into().unwrap()),
            Ok(None) => Err(PersistorAccessError(format!("Handle {:?} not found", handle))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn root_set(&self, handle: Word, old: Word, new: Word) -> Result<Word, PersistorAccessError> {
        let db = self.db.lock().unwrap();
        let roots = db.cf_handle("roots").unwrap();
        match db.get_cf(roots, handle) {
            Ok(Some(root_marked)) => match root_marked[SIZE] != false as u8 {
                true => match root_marked[..SIZE] == old.to_vec() {
                    true => {
                        let mut new_marked = [0 as u8; SIZE + 1];
                        new_marked[..SIZE].copy_from_slice(&new);
                        new_marked[SIZE] = true as u8;
                        db.put_cf(roots, handle, new_marked).unwrap();
                        drop(db);
                        self.reference_increment(new);
                        self.reference_decrement(old);
                        Ok(handle)
                    },
                    false => Err(PersistorAccessError(format!("Handle {:?} changed since compare", handle))),
                },
                false => Err(PersistorAccessError(format!("Handle {:?} is temporary", handle))),
            },
            Ok(None) => Err(PersistorAccessError(format!("Handle {:?} not found", handle))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn root_delete(&self, handle: Word) -> Result<(), PersistorAccessError> {
        let db = self.db.lock().unwrap();
        let roots = db.cf_handle("roots").unwrap();
        match db.get_cf(roots, handle) {
            Ok(Some(root_marked)) => {
                db.delete_cf(roots, handle).unwrap();
                drop(db);
                self.reference_decrement(root_marked[..SIZE].try_into().unwrap());
                Ok(())
            },
            Ok(None) => Err(PersistorAccessError(format!("Handle {:?} not found", handle))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn branch_set(&self, left: Word, right: Word) -> Result<Word, PersistorAccessError> {
        let mut joined = [0 as u8; SIZE * 2];
        joined[..SIZE].copy_from_slice(&left);
        joined[SIZE..].copy_from_slice(&right);

        let branch = Sha256::digest(joined);

        let db = self.db.lock().unwrap();
        let branches = db.cf_handle("branches").unwrap();
        db.put_cf(branches, branch, joined).unwrap();
        drop(db);
        self.reference_increment(left);
        self.reference_increment(right);

        Ok(Word::from(branch))
    }

    fn branch_get(&self, branch: Word) -> Result<(Word, Word), PersistorAccessError> {        
        let db = self.db.lock().unwrap();
        let branches = db.cf_handle("branches").unwrap();
        match db.get_cf(branches, branch) {
            Ok(Some(value)) => {
                assert!(Vec::from(branch) == Sha256::digest(value.clone()).to_vec());
                let left = &value[..SIZE].try_into().unwrap();
                let right = &value[SIZE..].try_into().unwrap();
                Ok((*left, *right))
            },
            Ok(None) => Err(PersistorAccessError(format!("Branch {:?} not found", branch))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }    
    }

    fn leaf_set(&self, content: Vec<u8>) -> Result<Word, PersistorAccessError> {
        let leaf = Word::from(Sha256::digest(Sha256::digest(&content)));
        let db = self.db.lock().unwrap();
        let leaves = db.cf_handle("leaves").unwrap();
        db.put_cf(leaves, leaf, content.clone()).unwrap();
        Ok(leaf)
    }

    fn leaf_get(&self, leaf: Word) -> Result<Vec<u8>, PersistorAccessError> {
        let db = self.db.lock().unwrap();
        let leaves = db.cf_handle("leaves").unwrap();
        match db.get_cf(leaves, leaf) {
            Ok(Some(content)) => {
                assert!(leaf == *Sha256::digest(Sha256::digest(content.clone())));
                Ok(content.to_vec())
            },
            Ok(None) => Err(PersistorAccessError(format!("Leaf {:?} not found", leaf))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use super::{Word, SIZE, Persistor, MemoryPersistor, DatabasePersistor};
    use rocksdb::{DB, IteratorMode};
    use std::sync::Mutex;

    fn test_persistence(persistor: Box<dyn Persistor>) {
        let zeros: Word = [0 as u8; SIZE];

        assert!(
            persistor.root_delete(
                persistor.root_temp(
                    zeros,
                ).unwrap(),
            ).unwrap() == ()
        );

        assert!(
            persistor.root_get(
                persistor.root_set(
                    persistor.root_new(
                        zeros,
                        zeros,
                    ).unwrap(),
                    zeros,
                    zeros,
                ).unwrap(),
            ).unwrap() == zeros
        );

        assert!(
            persistor.branch_get(
                persistor.branch_set(
                    zeros,
                    zeros,
                ).unwrap(),
            ).unwrap() == (zeros, zeros)
        );

        assert!(
            persistor.leaf_get(
                persistor.leaf_set(
                    vec!(0),
                ).unwrap(),
            ).unwrap() == vec!(0)
        );
    }

    #[test]
    fn test_memory_persistence() {
        test_persistence(Box::new(MemoryPersistor::new()));
    }

    #[test]
    fn test_database_persistence() {
        let db = ".test-database-persistence";
        let _ = fs::remove_dir_all(db);
        test_persistence(Box::new(DatabasePersistor::new(db)));
        let _ = fs::remove_dir_all(db);
    }

    #[test]
    fn test_memory_garbage() {
        let persistor = MemoryPersistor::new();

        let handle: Word = [0 as u8; SIZE];
        let leaf_0 = persistor.leaf_set(vec![0]).unwrap();
        let leaf_1 = persistor.leaf_set(vec![1]).unwrap();
        let leaf_2 = persistor.leaf_set(vec![2]).unwrap();

        let branch_a = persistor.branch_set(leaf_0, leaf_1).unwrap();
        let branch_b = persistor.branch_set(branch_a, leaf_2).unwrap();

        persistor.root_new(handle, branch_b).unwrap();

        assert!(persistor.roots.lock().unwrap().len() == 1);
        assert!(persistor.branches.lock().unwrap().len() == 2);
        assert!(persistor.leaves.lock().unwrap().len() == 3);
        assert!(persistor.references.lock().unwrap().len() == 5);

        let leaf_3 = persistor.leaf_set(vec![3]).unwrap();
        let branch_c = persistor.branch_set(leaf_2, leaf_3).unwrap();
        persistor.root_set(handle, branch_b, branch_c).unwrap();

        assert!(persistor.roots.lock().unwrap().len() == 1);
        assert!(persistor.branches.lock().unwrap().len() == 1);
        assert!(persistor.leaves.lock().unwrap().len() == 2);
        assert!(persistor.references.lock().unwrap().len() == 3);
    }

    #[test]
    fn test_database_garbage() {
        let db = ".test-database-garbage";
        let _ = fs::remove_dir_all(db);
        let persistor = DatabasePersistor::new(db);

        let handle: Word = [0 as u8; SIZE];
        let leaf_0 = persistor.leaf_set(vec![0]).unwrap();
        let leaf_1 = persistor.leaf_set(vec![1]).unwrap();
        let leaf_2 = persistor.leaf_set(vec![2]).unwrap();

        let branch_a = persistor.branch_set(leaf_0, leaf_1).unwrap();
        let branch_b = persistor.branch_set(branch_a, leaf_2).unwrap();

        persistor.root_new(handle, branch_b).unwrap();

        let cf_count = | mdb: &Mutex<DB>, cf | {
            let db_ = mdb.lock().unwrap();
            db_.iterator_cf(db_.cf_handle(cf).unwrap(), IteratorMode::Start).count()
        };

        {
            assert!(cf_count(&persistor.db, "roots") == 1);
            assert!(cf_count(&persistor.db, "branches") == 2);
            assert!(cf_count(&persistor.db, "leaves") == 3);
            assert!(cf_count(&persistor.db, "references") == 5);
        }

        let leaf_3 = persistor.leaf_set(vec![3]).unwrap();
        let branch_c = persistor.branch_set(leaf_2, leaf_3).unwrap();
        persistor.root_set(handle, branch_b, branch_c).unwrap();

        {
            assert!(cf_count(&persistor.db, "roots") == 1);
            assert!(cf_count(&persistor.db, "branches") == 1);
            assert!(cf_count(&persistor.db, "leaves") == 2);
            assert!(cf_count(&persistor.db, "references") == 3);
        }

        let _ = fs::remove_dir_all(db);
    }
}
