use crate::config::Config;
use once_cell::sync::Lazy;
use rand::RngCore;
use rand::prelude::SliceRandom;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use rocksdb::{ColumnFamilyDescriptor, DB, Options, WriteBatch};

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
    fn root_get(&self, handle: Word) -> Result<Word, PersistorAccessError>;
    fn root_set(
        &self,
        handle: Word,
        old: Word,
        new: Word,
        source: &dyn Persistor,
    ) -> Result<Word, PersistorAccessError>;
    fn root_delete(&self, handle: Word) -> Result<(), PersistorAccessError>;
    fn branch_set(
        &self,
        left: Word,
        right: Word,
        digest: Word,
    ) -> Result<Word, PersistorAccessError>;
    fn branch_get(&self, branch: Word) -> Result<(Word, Word, Word), PersistorAccessError>;
    fn leaf_set(&self, content: Vec<u8>) -> Result<Word, PersistorAccessError>;
    fn leaf_get(&self, leaf: Word) -> Result<Vec<u8>, PersistorAccessError>;
    fn stump_set(&self, digest: Word) -> Result<Word, PersistorAccessError>;
    fn stump_get(&self, stump: Word) -> Result<Word, PersistorAccessError>;
}

#[derive(Clone)]
pub struct MemoryPersistor {
    roots: Arc<RwLock<HashMap<Word, (Word, bool)>>>,
    branches: Arc<RwLock<HashMap<Word, (Word, Word, Word)>>>,
    leaves: Arc<RwLock<HashMap<Word, Vec<u8>>>>,
    stumps: Arc<RwLock<HashMap<Word, Word>>>,
    references: Arc<RwLock<HashMap<Word, usize>>>,
}

impl MemoryPersistor {
    pub fn new() -> Self {
        Self {
            roots: Arc::new(RwLock::new(HashMap::new())),
            branches: Arc::new(RwLock::new(HashMap::new())),
            leaves: Arc::new(RwLock::new(HashMap::new())),
            stumps: Arc::new(RwLock::new(HashMap::new())),
            references: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn reference_increment(&self, node: Word) {
        let mut references = self.references.write().expect("Failed to lock references");
        match references.get(&node) {
            Some(count) => {
                let count_ = *count;
                references.insert(node, count_ + 1);
            }
            None => {
                references.insert(node, 1);
            }
        };
    }

    fn reference_decrement(&self, node: Word) {
        let mut references = self.references.write().expect("Failed to lock references");
        match references.get(&node) {
            Some(count_old) => {
                let count_new = *count_old - 1;
                if count_new > 0 {
                    references.insert(node, count_new);
                } else {
                    references.remove(&node);
                    let mut branches = self.branches.write().expect("Failed to lock branches");
                    if let Some((left, right, _)) = branches.get(&node) {
                        let left_ = *left;
                        let right_ = *right;
                        branches.remove(&node);
                        drop(references);
                        drop(branches);
                        self.reference_decrement(left_);
                        self.reference_decrement(right_);
                    } else {
                        let mut leaves = self.leaves.write().expect("Failed to lock leaves");
                        let mut stumps = self.stumps.write().expect("Failed to lock stumps");
                        if let Some(_) = leaves.get(&node) {
                            leaves.remove(&node);
                        } else if let Some(_) = stumps.get(&node) {
                            stumps.remove(&node);
                        }
                    }
                }
            }
            None => {}
        };
    }

    fn merged_branch(
        &self,
        node: Word,
        plan: &MergePlan,
    ) -> Result<Option<(Word, Word, Word)>, PersistorAccessError> {
        if let Some(branch) = plan.branches.get(&node) {
            return Ok(Some(*branch));
        }

        match self
            .branches
            .read()
            .expect("Failed to lock branches")
            .get(&node)
        {
            Some((left, right, digest)) => Ok(Some((*left, *right, *digest))),
            None => Ok(None),
        }
    }

    fn base_refcount(&self, node: Word) -> isize {
        self.references
            .read()
            .expect("Failed to lock references")
            .get(&node)
            .copied()
            .unwrap_or(0) as isize
    }

    fn merge_collect(
        &self,
        source: &dyn Persistor,
        node: Word,
        plan: &mut MergePlan,
        seen: &mut HashSet<Word>,
    ) -> Result<(), PersistorAccessError> {
        if node == [0 as u8; SIZE] || !seen.insert(node) {
            return Ok(());
        }

        if plan.branches.contains_key(&node)
            || plan.leaves.contains_key(&node)
            || plan.stumps.contains_key(&node)
        {
            return Ok(());
        }

        if self
            .leaves
            .read()
            .expect("Failed to lock leaves")
            .contains_key(&node)
            || self
                .stumps
                .read()
                .expect("Failed to lock stumps")
                .contains_key(&node)
            || self
                .branches
                .read()
                .expect("Failed to lock branches")
                .contains_key(&node)
        {
            return Ok(());
        }

        if let Ok(content) = source.leaf_get(node) {
            plan.leaves.insert(node, content);
            return Ok(());
        }

        if let Ok(digest) = source.stump_get(node) {
            plan.stumps.insert(node, digest);
            return Ok(());
        }

        if let Ok((left, right, digest)) = source.branch_get(node) {
            self.merge_collect(source, left, plan, seen)?;
            self.merge_collect(source, right, plan, seen)?;
            plan.branches.insert(node, (left, right, digest));
            plan.delta_add(left, 1);
            plan.delta_add(right, 1);
            return Ok(());
        }

        Ok(())
    }

    fn release_plan(&self, node: Word, plan: &mut MergePlan) -> Result<(), PersistorAccessError> {
        if node == [0 as u8; SIZE] {
            return Ok(());
        }

        let effective = self.base_refcount(node) + plan.deltas.get(&node).copied().unwrap_or(0);
        if effective <= 0 {
            return Ok(());
        }

        plan.delta_add(node, -1);

        if effective == 1 {
            if !plan.deletes.insert(node) {
                return Ok(());
            }

            if let Some((left, right, _)) = self.merged_branch(node, plan)? {
                self.release_plan(left, plan)?;
                self.release_plan(right, plan)?;
            }
        }

        Ok(())
    }
}

impl Persistor for MemoryPersistor {
    fn root_list(&self) -> Vec<Word> {
        let mut keys: Vec<Word> = self
            .roots
            .read()
            .expect("Failed to get locked roots")
            .iter()
            .filter(|&(_, &(_, is_persistent))| is_persistent)
            .map(|(key, _)| key)
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    fn root_new(&self, handle: Word, root: Word) -> Result<Word, PersistorAccessError> {
        let mut roots = self.roots.write().expect("Failed to lock roots map");
        match roots.get(&handle) {
            Some(_) => Err(PersistorAccessError(format!(
                "Handle {:?} already exists",
                handle
            ))),
            None => {
                self.reference_increment(root);
                roots.insert(handle, (root, true));
                Ok(handle)
            }
        }
    }

    fn root_temp(&self, root: Word) -> Result<Word, PersistorAccessError> {
        let mut roots = self.roots.write().expect("Failed to lock roots map");
        let mut handle_: Word = [0 as u8; 32];
        rand::thread_rng().fill_bytes(&mut handle_);
        match roots.get(&handle_) {
            Some(_) => Err(PersistorAccessError(format!(
                "Handle {:?} already exists",
                handle_
            ))),
            None => {
                self.reference_increment(root);
                roots.insert(handle_, (root, false));
                Ok(handle_)
            }
        }
    }

    fn root_get(&self, handle: Word) -> Result<Word, PersistorAccessError> {
        match self
            .roots
            .read()
            .expect("Failed to lock roots map")
            .get(&handle)
        {
            Some((root, _)) => Ok(*root),
            None => Err(PersistorAccessError(format!(
                "Handle {:?} not found",
                handle
            ))),
        }
    }

    fn root_set(
        &self,
        handle: Word,
        old: Word,
        new: Word,
        source: &dyn Persistor,
    ) -> Result<Word, PersistorAccessError> {
        let status = {
            let roots = self.roots.write().expect("Failed to lock roots map");
            match roots.get(&handle) {
                Some((root, true)) if *root == old => 0,
                Some((_, false)) => 1,
                Some((_, true)) => 2,
                None => 3,
            }
        };

        match status {
            0 => {
                let mut plan = MergePlan::new();
                let mut seen = HashSet::new();
                self.merge_collect(source, new, &mut plan, &mut seen)?;
                plan.delta_add(new, 1);
                self.release_plan(old, &mut plan)?;

                {
                    let mut leaves = self.leaves.write().expect("Failed to lock leaves");
                    for (node, content) in plan.leaves.iter() {
                        leaves.insert(*node, content.clone());
                    }
                    for node in plan.deletes.iter() {
                        leaves.remove(node);
                    }
                }

                {
                    let mut stumps = self.stumps.write().expect("Failed to lock stumps");
                    for (node, digest) in plan.stumps.iter() {
                        stumps.insert(*node, *digest);
                    }
                    for node in plan.deletes.iter() {
                        stumps.remove(node);
                    }
                }

                {
                    let mut branches = self.branches.write().expect("Failed to lock branches");
                    for (node, branch) in plan.branches.iter() {
                        branches.insert(*node, *branch);
                    }
                    for node in plan.deletes.iter() {
                        branches.remove(node);
                    }
                }

                {
                    let mut references = self.references.write().expect("Failed to lock references");
                    for (node, delta) in plan.deltas.iter() {
                        let base = references.get(node).copied().unwrap_or(0) as isize;
                        let next = base + delta;
                        if next > 0 {
                            references.insert(*node, next as usize);
                        } else {
                            references.remove(node);
                        }
                    }
                }

                let mut roots = self.roots.write().expect("Failed to lock roots map");
                roots.insert(handle, (new, true));
                Ok(handle)
            }
            1 => Err(PersistorAccessError(format!(
                "Handle {:?} is temporary",
                handle
            ))),
            2 => Err(PersistorAccessError(format!(
                "Handle {:?} changed since compare",
                handle
            ))),
            _ => Err(PersistorAccessError(format!(
                "Handle {:?} not found",
                handle
            ))),
        }
    }

    fn root_delete(&self, handle: Word) -> Result<(), PersistorAccessError> {
        let mut roots = self.roots.write().expect("Failed to lock roots map");
        match roots.get(&handle) {
            Some((old, _)) => {
                let old_ = *old;
                roots.remove(&handle);
                self.reference_decrement(old_);
                Ok(())
            }
            None => Err(PersistorAccessError(format!(
                "Handle {:?} not found",
                handle
            ))),
        }
    }

    fn branch_set(
        &self,
        left: Word,
        right: Word,
        digest: Word,
    ) -> Result<Word, PersistorAccessError> {
        let mut joined = [0 as u8; SIZE * 3];
        joined[..SIZE].copy_from_slice(&left);
        joined[SIZE..SIZE * 2].copy_from_slice(&right);
        joined[SIZE * 2..].copy_from_slice(&digest);

        let branch = Sha256::digest(joined);
        let mut branches = self.branches.write().expect("Failed to lock branches map");
        branches.insert(branch.into(), (left, right, digest));
        drop(branches);
        self.reference_increment(left);
        self.reference_increment(right);
        Ok(Word::from(branch))
    }

    fn branch_get(&self, branch: Word) -> Result<(Word, Word, Word), PersistorAccessError> {
        let branches = self.branches.read().expect("Failed to lock branches map");
        match branches.get(&branch) {
            Some((left, right, digest)) => {
                let mut joined = [0 as u8; SIZE * 3];
                joined[..SIZE].copy_from_slice(left);
                joined[SIZE..SIZE * 2].copy_from_slice(right);
                joined[SIZE * 2..].copy_from_slice(digest);
                assert!(Vec::from(branch) == Sha256::digest(joined).to_vec());
                Ok((*left, *right, *digest))
            }
            None => Err(PersistorAccessError(format!(
                "Branch {:?} not found",
                branch
            ))),
        }
    }

    fn leaf_set(&self, content: Vec<u8>) -> Result<Word, PersistorAccessError> {
        let leaf = Word::from(Sha256::digest(Sha256::digest(&content)));
        self.leaves
            .write()
            .expect("Failed to lock leaves map")
            .insert(leaf, content);
        Ok(leaf)
    }

    fn leaf_get(&self, leaf: Word) -> Result<Vec<u8>, PersistorAccessError> {
        let leaves = self.leaves.read().expect("Failed to lock leaves map");
        match leaves.get(&leaf) {
            Some(content) => {
                assert!(Vec::from(leaf) == Sha256::digest(Sha256::digest(content)).to_vec());
                Ok(content.to_vec())
            }
            None => Err(PersistorAccessError(format!("Leaf {:?} not found", leaf))),
        }
    }

    fn stump_set(&self, digest: Word) -> Result<Word, PersistorAccessError> {
        let stump = Sha256::digest(digest);
        self.stumps
            .write()
            .expect("Failed to lock stump map")
            .insert(stump.into(), digest);
        Ok(Word::from(stump))
    }

    fn stump_get(&self, stump: Word) -> Result<Word, PersistorAccessError> {
        let stumps = self.stumps.read().expect("Failed to lock stumps map");
        match stumps.get(&stump) {
            Some(digest) => {
                assert!(Vec::from(stump) == Sha256::digest(Vec::from(digest)).to_vec());
                Ok(*digest)
            }
            None => Err(PersistorAccessError(format!("Stump {:?} not found", stump))),
        }
    }
}

pub struct DatabasePersistor {
    db: RwLock<DB>,
}

struct MergePlan {
    branches: HashMap<Word, (Word, Word, Word)>,
    leaves: HashMap<Word, Vec<u8>>,
    stumps: HashMap<Word, Word>,
    deltas: HashMap<Word, isize>,
    deletes: HashSet<Word>,
}

impl MergePlan {
    fn new() -> Self {
        Self {
            branches: HashMap::new(),
            leaves: HashMap::new(),
            stumps: HashMap::new(),
            deltas: HashMap::new(),
            deletes: HashSet::new(),
        }
    }

    fn delta_add(&mut self, node: Word, amount: isize) {
        let next = self.deltas.get(&node).copied().unwrap_or(0) + amount;
        if next == 0 {
            self.deltas.remove(&node);
        } else {
            self.deltas.insert(node, next);
        }
    }
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
            ColumnFamilyDescriptor::new("stumps", Options::default()),
            ColumnFamilyDescriptor::new("references", Options::default()),
        ];
        let persistor = Self {
            db: RwLock::new(
                DB::open_cf_descriptors(&opts, path, cfs).expect("Failed to open database"),
            ),
        };

        // TODO: clear this due to memory leakage
        {
            let mut handles: Vec<Word> = Vec::new();
            let db = persistor
                .db
                .read()
                .expect("Failed to acquire database lock");
            let mut iter = db.raw_iterator_cf(
                db.cf_handle("roots")
                    .expect("Failed to get roots column family"),
            );
            iter.seek_to_first();
            while iter.valid() {
                if (*iter.value().expect("Failed to get iterator value"))[SIZE] == false as u8 {
                    handles.push(
                        (*iter.key().expect("Failed to get iterator key"))
                            .try_into()
                            .expect("Failed to convert key to Word"),
                    );
                }
                iter.next();
            }
            for handle in handles {
                db.delete_cf(
                    db.cf_handle("roots")
                        .expect("Failed to get roots column family"),
                    handle,
                )
                .expect("Failed to delete value from roots");
            }
        }

        persistor
    }

    fn reference_increment(&self, db: &DB, node: Word) {
        let references = db
            .cf_handle("references")
            .expect("Failed to get references handle");
        match db.get_cf(references, node) {
            Ok(Some(count)) => {
                let count_old =
                    usize::from_ne_bytes(count.try_into().expect("Invalid count bytes"));
                let count_new = count_old + 1;
                db.put_cf(references, node, count_new.to_ne_bytes())
                    .expect("Failed to increment reference count");
            }
            Ok(None) => {
                db.put_cf(references, node, (1 as usize).to_ne_bytes())
                    .expect("Failed to set initial reference count");
            }
            Err(e) => {
                panic! {"{}", e}
            }
        };
    }

    fn reference_decrement(&self, db: &DB, node: Word) {
        let branches = db
            .cf_handle("branches")
            .expect("Failed to get branches handle");
        let leaves = db.cf_handle("leaves").expect("Failed to get leaves handle");
        let stumps = db.cf_handle("stumps").expect("Failed to get stumps handle");
        let references = db
            .cf_handle("references")
            .expect("Failed to get references handle");
        match db
            .get_cf(references, node)
            .expect("Failed to get reference count")
        {
            Some(count_old) => {
                let count_old =
                    usize::from_ne_bytes(count_old.try_into().expect("Invalid count bytes"));
                let count_new = count_old - 1;
                if count_new > 0 {
                    db.put_cf(references, node, count_new.to_ne_bytes())
                        .expect("Failed to update reference count");
                } else {
                    db.delete_cf(references, node)
                        .expect("Failed to delete reference");
                    if let Some(value) = db.get_cf(branches, node).expect("Failed to get branch") {
                        let left: Word = value[..SIZE].try_into().expect("Invalid left node bytes");
                        let right: Word = value[SIZE..SIZE * 2]
                            .try_into()
                            .expect("Invalid right node bytes");
                        db.delete_cf(branches, node)
                            .expect("Failed to delete branch");
                        self.reference_decrement(db, left);
                        self.reference_decrement(db, right);
                    } else {
                        if let Some(_) = db.get_cf(leaves, node).expect("Failed to get leaf") {
                            db.delete_cf(leaves, node).expect("Failed to delete leaf");
                        } else if let Some(_) =
                            db.get_cf(stumps, node).expect("Failed to get stump")
                        {
                            db.delete_cf(stumps, node).expect("Failed to delete stump");
                        }
                    }
                }
            }
            None => {}
        };
    }

    fn merge_collect(
        &self,
        db: &DB,
        source: &dyn Persistor,
        node: Word,
        plan: &mut MergePlan,
        seen: &mut HashSet<Word>,
    ) -> Result<(), PersistorAccessError> {
        if node == [0 as u8; SIZE] || !seen.insert(node) {
            return Ok(());
        }

        let branches = db
            .cf_handle("branches")
            .expect("Failed to get branches handle");
        let leaves = db.cf_handle("leaves").expect("Failed to get leaves handle");
        let stumps = db.cf_handle("stumps").expect("Failed to get stumps handle");

        if plan.branches.contains_key(&node)
            || plan.leaves.contains_key(&node)
            || plan.stumps.contains_key(&node)
        {
            return Ok(());
        }

        if db.get_cf(leaves, node).expect("Failed to get leaf").is_some()
            || db.get_cf(stumps, node).expect("Failed to get stump").is_some()
            || db.get_cf(branches, node).expect("Failed to get branch").is_some()
        {
            return Ok(());
        }

        if let Ok(content) = source.leaf_get(node) {
            plan.leaves.insert(node, content);
            return Ok(());
        }

        if let Ok(digest) = source.stump_get(node) {
            plan.stumps.insert(node, digest);
            return Ok(());
        }

        if let Ok((left, right, digest)) = source.branch_get(node) {
            self.merge_collect(db, source, left, plan, seen)?;
            self.merge_collect(db, source, right, plan, seen)?;
            plan.branches.insert(node, (left, right, digest));
            plan.delta_add(left, 1);
            plan.delta_add(right, 1);
            return Ok(());
        }

        Ok(())
    }

    fn merged_branch(
        &self,
        db: &DB,
        node: Word,
        plan: &MergePlan,
    ) -> Result<Option<(Word, Word, Word)>, PersistorAccessError> {
        if let Some(branch) = plan.branches.get(&node) {
            return Ok(Some(*branch));
        }

        let branches = db
            .cf_handle("branches")
            .expect("Failed to get branches handle");
        match db.get_cf(branches, node) {
            Ok(Some(value)) => {
                let left = value[..SIZE].try_into().expect("Invalid left branch size");
                let right = value[SIZE..SIZE * 2]
                    .try_into()
                    .expect("Invalid right branch size");
                let digest = value[SIZE * 2..]
                    .try_into()
                    .expect("Invalid digest branch size");
                Ok(Some((left, right, digest)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn base_refcount(&self, db: &DB, node: Word) -> Result<isize, PersistorAccessError> {
        let references = db
            .cf_handle("references")
            .expect("Failed to get references handle");
        match db.get_cf(references, node) {
            Ok(Some(count)) => Ok(
                usize::from_ne_bytes(count.try_into().expect("Invalid count bytes")) as isize,
            ),
            Ok(None) => Ok(0),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn release_plan(
        &self,
        db: &DB,
        node: Word,
        plan: &mut MergePlan,
    ) -> Result<(), PersistorAccessError> {
        if node == [0 as u8; SIZE] {
            return Ok(());
        }

        let effective = self.base_refcount(db, node)? + plan.deltas.get(&node).copied().unwrap_or(0);
        if effective <= 0 {
            return Ok(());
        }

        plan.delta_add(node, -1);

        if effective == 1 {
            if !plan.deletes.insert(node) {
                return Ok(());
            }

            if let Some((left, right, _)) = self.merged_branch(db, node, plan)? {
                self.release_plan(db, left, plan)?;
                self.release_plan(db, right, plan)?;
            }
        }

        Ok(())
    }
}

impl Persistor for DatabasePersistor {
    fn root_list(&self) -> Vec<Word> {
        let mut handles: Vec<Word> = Vec::new();
        let db = self.db.read().expect("Failed to acquire db lock");
        let roots = db
            .cf_handle("roots")
            .expect("Failed to get roots column family");
        let mut iter = db.raw_iterator_cf(roots);
        iter.seek_to_first();
        while iter.valid() {
            if (*iter.value().expect("Failed to get iterator value"))[SIZE] != false as u8 {
                handles.push(
                    (*iter.key().expect("Failed to get iterator key"))
                        .try_into()
                        .expect("Failed to convert key to Word"),
                );
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

        let db = self.db.write().expect("Failed to acquire db lock");
        let roots = db
            .cf_handle("roots")
            .expect("Failed to get roots column family");
        match db.get_cf(roots, handle) {
            Ok(Some(_)) => Err(PersistorAccessError(format!(
                "Handle {:?} already exists",
                handle
            ))),
            Ok(None) => {
                self.reference_increment(&db, root);
                db.put_cf(roots, handle, root_marked)
                    .expect("Failed to put root in db");
                Ok(handle)
            }
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn root_temp(&self, root: Word) -> Result<Word, PersistorAccessError> {
        let db = self.db.write().expect("Failed to acquire db lock");
        let roots = db
            .cf_handle("roots")
            .expect("Failed to get roots column family");
        let mut root_marked = [0 as u8; SIZE + 1];
        root_marked[..SIZE].copy_from_slice(&root);
        root_marked[SIZE] = false as u8;

        let mut handle_: Word = [0 as u8; 32];
        rand::thread_rng().fill_bytes(&mut handle_);

        match db.get_cf(roots, handle_) {
            Ok(Some(_)) => Err(PersistorAccessError(format!(
                "Handle {:?} already exists",
                handle_
            ))),
            Ok(None) => {
                self.reference_increment(&db, root);
                db.put_cf(roots, handle_, root_marked)
                    .expect("Failed to put root in db");
                Ok(handle_)
            }
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn root_get(&self, handle: Word) -> Result<Word, PersistorAccessError> {
        let db = self.db.read().expect("Failed to acquire db lock");
        let roots = db.cf_handle("roots").expect("Failed to get roots handle");
        match db.get_cf(roots, handle) {
            Ok(Some(root_marked)) => Ok(((*root_marked)[..SIZE])
                .try_into()
                .expect("Invalid root size")),
            Ok(None) => Err(PersistorAccessError(format!(
                "Handle {:?} not found",
                handle
            ))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn root_set(
        &self,
        handle: Word,
        old: Word,
        new: Word,
        source: &dyn Persistor,
    ) -> Result<Word, PersistorAccessError> {
        let db = self.db.write().expect("Failed to acquire db lock");
        let roots = db.cf_handle("roots").expect("Failed to get roots handle");
        match db.get_cf(roots, handle) {
            Ok(Some(root_marked)) => match root_marked[SIZE] != false as u8 {
                true => match root_marked[..SIZE] == old.to_vec() {
                    true => {
                        let mut plan = MergePlan::new();
                        let mut seen = HashSet::new();
                        self.merge_collect(&db, source, new, &mut plan, &mut seen)?;
                        plan.delta_add(new, 1);
                        self.release_plan(&db, old, &mut plan)?;

                        let mut new_marked = [0 as u8; SIZE + 1];
                        new_marked[..SIZE].copy_from_slice(&new);
                        new_marked[SIZE] = true as u8;

                        let branches = db
                            .cf_handle("branches")
                            .expect("Failed to get branches handle");
                        let leaves = db.cf_handle("leaves").expect("Failed to get leaves handle");
                        let stumps = db.cf_handle("stumps").expect("Failed to get stumps handle");
                        let references = db
                            .cf_handle("references")
                            .expect("Failed to get references handle");

                        let mut batch = WriteBatch::default();

                        for (node, content) in plan.leaves.iter() {
                            batch.put_cf(leaves, node, content);
                        }

                        for (node, digest) in plan.stumps.iter() {
                            batch.put_cf(stumps, node, digest);
                        }

                        for (node, (left, right, digest)) in plan.branches.iter() {
                            let mut joined = [0 as u8; SIZE * 3];
                            joined[..SIZE].copy_from_slice(left);
                            joined[SIZE..SIZE * 2].copy_from_slice(right);
                            joined[SIZE * 2..].copy_from_slice(digest);
                            batch.put_cf(branches, node, joined);
                        }

                        for (node, delta) in plan.deltas.iter() {
                            let base = self.base_refcount(&db, *node)?;
                            let next = base + delta;
                            if next > 0 {
                                batch.put_cf(references, node, (next as usize).to_ne_bytes());
                            } else {
                                batch.delete_cf(references, node);
                            }
                        }

                        for node in plan.deletes.iter() {
                            if plan.branches.contains_key(node)
                                || db.get_cf(branches, node).expect("Failed to get branch").is_some()
                            {
                                batch.delete_cf(branches, node);
                            } else if plan.leaves.contains_key(node)
                                || db.get_cf(leaves, node).expect("Failed to get leaf").is_some()
                            {
                                batch.delete_cf(leaves, node);
                            } else if plan.stumps.contains_key(node)
                                || db.get_cf(stumps, node).expect("Failed to get stump").is_some()
                            {
                                batch.delete_cf(stumps, node);
                            }
                        }

                        batch.put_cf(roots, handle, new_marked);
                        db.write(batch).expect("Failed to apply root merge batch");
                        Ok(handle)
                    }
                    false => Err(PersistorAccessError(format!(
                        "Handle {:?} changed since compare",
                        handle
                    ))),
                },
                false => Err(PersistorAccessError(format!(
                    "Handle {:?} is temporary",
                    handle
                ))),
            },
            Ok(None) => Err(PersistorAccessError(format!(
                "Handle {:?} not found",
                handle
            ))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn root_delete(&self, handle: Word) -> Result<(), PersistorAccessError> {
        let db = self.db.write().expect("Failed to acquire db lock");
        let roots = db.cf_handle("roots").expect("Failed to get roots handle");
        match db.get_cf(roots, handle) {
            Ok(Some(root_marked)) => {
                let root: Word = root_marked[..SIZE].try_into().expect("Invalid root size");
                db.delete_cf(roots, handle).expect("Failed to delete root");
                self.reference_decrement(&db, root);
                Ok(())
            }
            Ok(None) => Err(PersistorAccessError(format!(
                "Handle {:?} not found",
                handle
            ))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn branch_set(
        &self,
        left: Word,
        right: Word,
        digest: Word,
    ) -> Result<Word, PersistorAccessError> {
        let mut joined = [0 as u8; SIZE * 3];
        joined[..SIZE].copy_from_slice(&left);
        joined[SIZE..SIZE * 2].copy_from_slice(&right);
        joined[SIZE * 2..].copy_from_slice(&digest);

        let branch = Sha256::digest(joined);

        let db = self.db.write().expect("Failed to acquire db lock");
        let branches = db
            .cf_handle("branches")
            .expect("Failed to get branches handle");
        db.put_cf(branches, branch, joined)
            .expect("Failed to put branch");
        self.reference_increment(&db, left);
        self.reference_increment(&db, right);

        Ok(Word::from(branch))
    }

    fn branch_get(&self, branch: Word) -> Result<(Word, Word, Word), PersistorAccessError> {
        let db = self.db.read().expect("Failed to acquire db lock");
        let branches = db
            .cf_handle("branches")
            .expect("Failed to get branches handle");
        match db.get_cf(branches, branch) {
            Ok(Some(value)) => {
                assert!(Vec::from(branch) == Sha256::digest(value.clone()).to_vec());
                let left = &value[..SIZE].try_into().expect("Invalid left branch size");
                let right = &value[SIZE..SIZE * 2]
                    .try_into()
                    .expect("Invalid right branch size");
                let digest = &value[SIZE * 2..]
                    .try_into()
                    .expect("Invalid digest branch size");
                Ok((*left, *right, *digest))
            }
            Ok(None) => Err(PersistorAccessError(format!(
                "Branch {:?} not found",
                branch
            ))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn leaf_set(&self, content: Vec<u8>) -> Result<Word, PersistorAccessError> {
        let leaf = Word::from(Sha256::digest(Sha256::digest(&content)));
        let db = self.db.write().expect("Failed to acquire db lock");
        let leaves = db.cf_handle("leaves").expect("Failed to get leaves handle");
        db.put_cf(leaves, leaf, content.clone())
            .expect("Failed to put leaf");
        Ok(leaf)
    }

    fn leaf_get(&self, leaf: Word) -> Result<Vec<u8>, PersistorAccessError> {
        let db = self.db.read().expect("Failed to acquire db lock");
        let leaves = db.cf_handle("leaves").expect("Failed to get leaves handle");
        match db.get_cf(leaves, leaf) {
            Ok(Some(content)) => {
                assert!(leaf == *Sha256::digest(Sha256::digest(content.clone())));
                Ok(content.to_vec())
            }
            Ok(None) => Err(PersistorAccessError(format!("Leaf {:?} not found", leaf))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }

    fn stump_set(&self, digest: Word) -> Result<Word, PersistorAccessError> {
        let stump = Word::from(Sha256::digest(Vec::from(digest)));
        let db = self.db.write().expect("Failed to acquire db lock");
        let stumps = db.cf_handle("stumps").expect("Failed to get stumps handle");
        db.put_cf(stumps, stump, digest)
            .expect("Failed to put stump");
        Ok(stump)
    }

    fn stump_get(&self, stump: Word) -> Result<Word, PersistorAccessError> {
        let db = self.db.read().expect("Failed to acquire db lock");
        let stumps = db.cf_handle("stumps").expect("Failed to get stumps handle");
        match db.get_cf(stumps, stump) {
            Ok(Some(digest)) => {
                assert!(stump == *Sha256::digest(digest.clone()));
                Ok((&(*digest)[..SIZE])
                    .try_into()
                    .expect("Invalid left node bytes"))
            }
            Ok(None) => Err(PersistorAccessError(format!(
                "Stumps {:?} not found",
                stump
            ))),
            Err(e) => Err(PersistorAccessError(format!("{}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DatabasePersistor, MemoryPersistor, Persistor, SIZE, Word};
    use rocksdb::{DB, IteratorMode};
    use std::fs;
    use std::sync::RwLock;

    fn test_persistence(persistor: Box<dyn Persistor>) {
        let zeros: Word = [0 as u8; SIZE];
        let handle = persistor
            .root_new(zeros, zeros)
            .expect("Failed to create new root");

        assert!(
            persistor
                .root_delete(
                    persistor
                        .root_temp(zeros)
                        .expect("Failed to create temp root")
                )
                .expect("Failed to delete root")
                == ()
        );

        assert!(
            persistor
                .root_get(
                    persistor
                        .root_set(handle, zeros, zeros, persistor.as_ref())
                        .expect("Failed to set root"),
                )
                .expect("Failed to get root")
                == zeros
        );

        assert!(
            persistor
                .branch_get(
                    persistor
                        .branch_set(zeros, zeros, zeros)
                        .expect("Failed to set branch"),
                )
                .expect("Failed to get branch")
                == (zeros, zeros, zeros)
        );

        assert!(
            persistor
                .leaf_get(persistor.leaf_set(vec!(0)).expect("Failed to set leaf"),)
                .expect("Failed to get leaf")
                == vec!(0)
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
        let zeros: Word = [0 as u8; SIZE];
        let handle: Word = [0 as u8; SIZE];

        let leaf_0 = persistor.leaf_set(vec![0]).expect("Failed to set leaf 0");
        let leaf_1 = persistor.leaf_set(vec![1]).expect("Failed to set leaf 1");
        let leaf_2 = persistor.leaf_set(vec![2]).expect("Failed to set leaf 2");

        let stump_0 = persistor
            .stump_set([0 as u8; SIZE])
            .expect("Failed to set stump 0");

        let branch_a = persistor
            .branch_set(leaf_0, leaf_1, zeros)
            .expect("Failed to set branch A");
        let branch_b = persistor
            .branch_set(branch_a, leaf_2, zeros)
            .expect("Failed to set branch B");
        let branch_c = persistor
            .branch_set(branch_b, stump_0, zeros)
            .expect("Failed to set branch B");

        persistor
            .root_new(handle, branch_c)
            .expect("Failed to create new root");

        assert!(persistor.roots.read().expect("Failed to lock roots").len() == 1);
        assert!(
            persistor
                .branches
                .read()
                .expect("Failed to lock branches")
                .len()
                == 3
        );
        assert!(
            persistor
                .leaves
                .read()
                .expect("Failed to lock leaves")
                .len()
                == 3
        );
        assert!(
            persistor
                .stumps
                .read()
                .expect("Failed to lock leaves")
                .len()
                == 1
        );
        assert!(
            persistor
                .references
                .read()
                .expect("Failed to lock references")
                .len()
                == 7
        );

        let leaf_3 = persistor.leaf_set(vec![3]).expect("Failed to set leaf 3");
        let branch_d = persistor
            .branch_set(leaf_2, leaf_3, zeros)
            .expect("Failed to set branch D");
        persistor
            .root_set(handle, branch_c, branch_d, &persistor)
            .expect("Failed to set root");

        assert!(persistor.roots.read().expect("Failed to lock roots").len() == 1);
        assert!(
            persistor
                .branches
                .read()
                .expect("Failed to lock branches")
                .len()
                == 1
        );
        assert!(
            persistor
                .leaves
                .read()
                .expect("Failed to lock leaves")
                .len()
                == 2
        );
        assert!(
            persistor
                .stumps
                .read()
                .expect("Failed to lock stumps")
                .len()
                == 0
        );
        assert!(
            persistor
                .references
                .read()
                .expect("Failed to lock references")
                .len()
                == 3
        );
    }

    #[test]
    fn test_database_garbage() {
        let db = ".test-database-garbage";
        let _ = fs::remove_dir_all(db);
        let persistor = DatabasePersistor::new(db);
        let zeros: Word = [0 as u8; SIZE];
        let handle: Word = [0 as u8; SIZE];
        let leaf_0 = persistor.leaf_set(vec![0]).expect("Failed to set leaf 0");
        let leaf_1 = persistor.leaf_set(vec![1]).expect("Failed to set leaf 1");
        let leaf_2 = persistor.leaf_set(vec![2]).expect("Failed to set leaf 2");

        let stump_0 = persistor
            .stump_set([0 as u8; SIZE])
            .expect("Failed to set stump 0");

        let branch_a = persistor
            .branch_set(leaf_0, leaf_1, zeros)
            .expect("Failed to set branch A");
        let branch_b = persistor
            .branch_set(branch_a, leaf_2, zeros)
            .expect("Failed to set branch B");
        let branch_c = persistor
            .branch_set(branch_b, stump_0, zeros)
            .expect("Failed to set branch C");

        persistor
            .root_new(handle, branch_c)
            .expect("Failed to create new root");

        let cf_count = |db: &RwLock<DB>, cf| {
            let db_ = db.read().expect("Failed to lock database");
            db_.iterator_cf(
                db_.cf_handle(cf).expect("Failed to get CF handle"),
                IteratorMode::Start,
            )
            .count()
        };

        {
            assert!(cf_count(&persistor.db, "roots") == 1);
            assert!(cf_count(&persistor.db, "branches") == 3);
            assert!(cf_count(&persistor.db, "leaves") == 3);
            assert!(cf_count(&persistor.db, "stumps") == 1);
            assert!(cf_count(&persistor.db, "references") == 7);
        }

        let leaf_3 = persistor.leaf_set(vec![3]).expect("Failed to set leaf 3");
        let branch_d = persistor
            .branch_set(leaf_2, leaf_3, zeros)
            .expect("Failed to set branch D");
        persistor
            .root_set(handle, branch_c, branch_d, &persistor)
            .expect("Failed to set root");

        {
            assert!(cf_count(&persistor.db, "roots") == 1);
            assert!(cf_count(&persistor.db, "branches") == 1);
            assert!(cf_count(&persistor.db, "leaves") == 2);
            assert!(cf_count(&persistor.db, "stumps") == 0);
            assert!(cf_count(&persistor.db, "references") == 3);
        }

        let _ = fs::remove_dir_all(db);
    }

    fn test_root_set_merge_from_source(persistor: Box<dyn Persistor>) {
        let zeros: Word = [0 as u8; SIZE];
        let handle: Word = [1 as u8; SIZE];
        let target = Box::new(MemoryPersistor::new());

        let leaf_0 = persistor.leaf_set(vec![0]).expect("Failed to set leaf 0");
        let leaf_1 = persistor.leaf_set(vec![1]).expect("Failed to set leaf 1");
        let branch = persistor
            .branch_set(leaf_0, leaf_1, zeros)
            .expect("Failed to set source branch");

        target
            .root_new(handle, zeros)
            .expect("Failed to create target root");
        target
            .root_set(handle, zeros, branch, persistor.as_ref())
            .expect("Failed to merge root from source");

        assert!(target.root_get(handle).expect("Failed to get target root") == branch);
        assert!(target.branch_get(branch).expect("Failed to get merged branch") == (leaf_0, leaf_1, zeros));
        assert!(target.leaf_get(leaf_0).expect("Failed to get merged leaf 0") == vec![0]);
        assert!(target.leaf_get(leaf_1).expect("Failed to get merged leaf 1") == vec![1]);
    }

    #[test]
    fn test_memory_root_set_merge_from_source() {
        test_root_set_merge_from_source(Box::new(MemoryPersistor::new()));
    }

    #[test]
    fn test_database_root_set_merge_from_source() {
        let db = ".test-database-root-set-merge-from-source";
        let _ = fs::remove_dir_all(db);
        test_root_set_merge_from_source(Box::new(DatabasePersistor::new(db)));
        let _ = fs::remove_dir_all(db);
    }

    #[test]
    fn test_memory_root_set_merge_from_source_garbage() {
        let zeros: Word = [0 as u8; SIZE];
        let handle: Word = [0 as u8; SIZE];
        let target = MemoryPersistor::new();
        let source = MemoryPersistor::new();

        let leaf_0 = target.leaf_set(vec![0]).expect("Failed to set target leaf 0");
        let leaf_1 = target.leaf_set(vec![1]).expect("Failed to set target leaf 1");
        let leaf_2 = target.leaf_set(vec![2]).expect("Failed to set target leaf 2");
        let stump_0 = target
            .stump_set([0 as u8; SIZE])
            .expect("Failed to set target stump 0");
        let branch_a = target
            .branch_set(leaf_0, leaf_1, zeros)
            .expect("Failed to set target branch A");
        let branch_b = target
            .branch_set(branch_a, leaf_2, zeros)
            .expect("Failed to set target branch B");
        let branch_c = target
            .branch_set(branch_b, stump_0, zeros)
            .expect("Failed to set target branch C");
        target
            .root_new(handle, branch_c)
            .expect("Failed to create target root");

        let leaf_2_source = source.leaf_set(vec![2]).expect("Failed to set source leaf 2");
        let leaf_3_source = source.leaf_set(vec![3]).expect("Failed to set source leaf 3");
        let branch_d = source
            .branch_set(leaf_2_source, leaf_3_source, zeros)
            .expect("Failed to set source branch D");

        target
            .root_set(handle, branch_c, branch_d, &source)
            .expect("Failed to merge source root into target");

        assert!(target.roots.read().expect("Failed to lock roots").len() == 1);
        assert!(target.branches.read().expect("Failed to lock branches").len() == 1);
        assert!(target.leaves.read().expect("Failed to lock leaves").len() == 2);
        assert!(target.stumps.read().expect("Failed to lock stumps").len() == 0);
        assert!(target.references.read().expect("Failed to lock references").len() == 3);
    }
}
