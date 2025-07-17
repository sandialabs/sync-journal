#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use libc;
use std::time::Instant;
use log::{info, debug};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use once_cell::sync::Lazy;
pub use crate::config::Config;
pub use crate::persistor::{Word, SIZE};
use crate::persistor::{PERSISTOR, MemoryPersistor, Persistor, PersistorAccessError};
use crate::evaluator::{Evaluator, Primitive, Type, to_str_or_err};
use crate::extensions::crypto::{
    primitive_s7_crypto_generate,
    primitive_s7_crypto_sign,
    primitive_s7_crypto_verify,
};

use sha2::{Sha256, Digest};
use evaluator as s7;
use std::ffi::{CString, CStr};

mod config;
mod evaluator;
mod persistor;
mod extensions {
    pub mod crypto;
}

pub static JOURNAL: Lazy<Journal> = Lazy::new(|| Journal::new());

static SESSION_COUNT: AtomicUsize = AtomicUsize::new(0);

const SYNC_PAIR_TAG: i64 = 0;

const GENESIS_STR: &str = "(lambda (*sync-state* query) (cons (eval query) *sync-state*))";

pub const NULL: Word = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
];

struct Session {
    record: Word,
    persistor: MemoryPersistor,
    cache: Arc<Mutex<HashMap<(String, String, Vec<u8>), Vec<u8>>>>,
}

impl Session {
    fn new(
        record: Word,
        persistor: MemoryPersistor,
        cache: Arc<Mutex<HashMap<(String, String, Vec<u8>), Vec<u8>>>>,
    ) -> Self {
        Self { record, persistor, cache }
    }
}

static SESSIONS: Lazy<Mutex<HashMap<usize, Session>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

struct CallOnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for CallOnDrop<F> {
  fn drop(&mut self) {
    (self.0)();
  }
}

#[derive(Debug)]
pub struct JournalAccessError(pub Word);

static LOCK: Mutex<()> = Mutex::new(());
static RUNS: usize = 3;

/// Journals are the primary way that application developers
/// interact with the synchronic web.
///
/// Conceptually, a Journal is a
/// service that interacts with users and other Journals (nodes) to
/// persist synchronic web state. Behind the schemes, it is
/// responsible for two capabilities:
///
/// * __Persistence__: managing bytes on the global hash graph
/// 
/// * __Evaluation__: executing code in the global Lisp environment
///
/// __Records__ are the primary way that developers interface with
/// Journals. A Record is a mapping between a constant identifier and
/// mutable state. Both identifiers and state are represented as
/// fixed-size __Words__ that the outputs of a cryptographic hash
/// function. When a new record is created, the Journal returns a
/// record secret that is the second hash preimage of the identifier.
/// This is intended to be used so that applications can bootstrap
/// records into increasingly sophisticated notions of identity.
pub struct Journal {}

impl Journal {
    fn new() -> Self {
        match PERSISTOR.root_new(
            NULL,
            PERSISTOR.branch_set(
                PERSISTOR.leaf_set(GENESIS_STR.as_bytes().to_vec()).expect("Failed to create genesis leaf"),
                NULL,
            ).expect("Failed to create genesis branch"),
        ) {
            Ok(_) => Self {},
            Err(_) => Self {},
        }
    }

    /// Evaluate a Lisp expression within a Record
    ///
    /// # Examples
    /// ```
    /// use journal_sdk::JOURNAL;
    ///
    /// // Simple expression
    /// let output = JOURNAL.evaluate("(+ 1 2)");
    /// assert!(output == "3");
    ///
    /// // Complex expression
    /// let output = JOURNAL.evaluate(
    ///     "(begin (define (add2 x) (+ x 2)) (add2 1))",
    /// );
    /// assert!(output == "3");
    pub fn evaluate(&self, query: &str) -> String {
        self.evaluate_record(NULL, query)
    }

    fn evaluate_record(&self, record: Word, query: &str) -> String {
        let mut runs = 0;
        let cache = Arc::new(Mutex::new(HashMap::new()));

        let start = Instant::now();
        debug!(
            "Evaluating ({})",
            query.chars().take(128).collect::<String>(),
        );

        loop {
            let _lock1 = if runs >= RUNS {
                Some(LOCK.lock().expect("Failed to acquire concurrency lock"))
            } else {
                None
            };

            let genesis_func = PERSISTOR.leaf_get(
                PERSISTOR.branch_get(
                    PERSISTOR.root_get(record).expect("Failed to get root record")
                ).expect("Failed to get genesis branch").0
            ).expect("Failed to get genesis function").to_vec();

            let genesis_str = String::from_utf8_lossy(&genesis_func);

            let state_old = PERSISTOR.root_get(record).expect("Failed to get current state");

            let record_temp = PERSISTOR.root_temp(state_old).expect("Failed to create temporary record");

            let _record_dropper = CallOnDrop(|| {
                PERSISTOR.root_delete(record_temp).expect("Failed to delete temporary record");
            });

            let state_str = format!(
                "#u({})",
                state_old.iter().map(|&num| num.to_string()).collect::<Vec<String>>().join(" "),
            );

            let evaluator = Evaluator::new(
                vec![
                    (SYNC_PAIR_TAG, type_s7_sync_pair()),
                ].into_iter().collect(),
                vec![
                    primitive_s7_sync_hash(),
                    primitive_s7_sync_pair(),
                    primitive_s7_sync_is_pair(),
                    primitive_s7_sync_null(),
                    primitive_s7_sync_is_null(),
                    primitive_s7_sync_pair_to_bytes(),
                    primitive_s7_sync_cons(),
                    primitive_s7_sync_car(),
                    primitive_s7_sync_cdr(),
                    primitive_s7_sync_create(),
                    primitive_s7_sync_delete(),
                    primitive_s7_sync_all(),
                    primitive_s7_sync_call(),
                    primitive_s7_sync_remote(),
                    primitive_s7_sync_http(),
                    primitive_s7_crypto_generate(),
                    primitive_s7_crypto_sign(),
                    primitive_s7_crypto_verify(),
                ],
            );

            SESSIONS.lock().expect("Failed to acquire sessions lock").insert(
                evaluator.sc as usize,
                Session::new(record, MemoryPersistor::new(), cache.clone()),
            );
            let count = SESSION_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
            info!("Session added to SESSIONS, total active sessions: {}", count);

            let _session_dropper = CallOnDrop(|| {
                let mut session = SESSIONS.lock().expect("Failed to acquire sessions lock for cleanup");
                session.remove(&(evaluator.sc as usize));
                let count = SESSION_COUNT.fetch_sub(1, Ordering::SeqCst) - 1;
                info!("Session removed from SESSIONS, total active sessions: {}", count);
            });

            let expr = format!("((eval {}) (sync-pair {}) (quote {}))", genesis_str, state_str, query);

            let result = evaluator.evaluate(expr.as_str());
            runs += 1;

            let persistor = {
                let session = SESSIONS.lock().expect("Failed to acquire sessions lock");
                &session.get(&(evaluator.sc as usize)).expect("Session not found in SESSIONS map").persistor.clone()
            };

            let (output, state_new) = match result.starts_with("(error '") {
                true => (result, state_old),
                false => {
                    match result.rfind('.') {
                        Some(index) => match *&result[(index + 16)..(result.len() - 3)]
                            .split(' ').collect::<Vec<&str>>()
                            .iter().map(|x| x.parse::<u8>().expect("Failed to parse state byte")).collect::<Vec<u8>>()
                            .try_into() {
                                Ok(state_new) => (
                                    String::from(&result[1..(index - 1)]),
                                    state_new,
                                ),
                                Err(_) => (
                                    String::from("(error 'sync-format \"Invalid return format\")"),
                                    state_old,
                                )
                            },
                        None => (
                            String::from("(error 'sync-format \"Invalid return format\")"),
                            state_old,
                        ),
                    }
                },
            };

            match state_old == state_new {
                true => {
                    debug!(
                        "Completed ({:?}) {} -> {}",
                        start.elapsed(), query.chars().take(128).collect::<String>(), output,
                    );
                    return output
                },
                false => match state_old == PERSISTOR.root_get(record).expect("Failed to get record state for comparison") {
                    true => {
                        fn recurse(source: &MemoryPersistor, node: Word) -> Result<(), PersistorAccessError> {
                            if node == NULL {
                                Ok(())
                            } else if let Ok(_) = PERSISTOR.leaf_get(node) {
                                Ok(())
                            } else if let Ok(_) = PERSISTOR.branch_get(node) {
                                Ok(())
                            } else if let Ok(content) = source.leaf_get(node) {
                                PERSISTOR.leaf_set(content).expect("Failed to set leaf content");
                                Ok(())
                            } else if let Ok((left, right)) = source.branch_get(node) {
                                PERSISTOR.branch_set(left, right).expect("Failed to set branch");
                                match recurse(&source, left) {
                                    Ok(_) => recurse(&source, right),
                                    err => err,
                                }
                            } else {
                                Err(PersistorAccessError(format!("Dangling branch {:?}", node)))
                            }
                        }

                        {
                            let _lock2 = match _lock1 {
                                Some(_) => None,
                                None => Some(LOCK.lock().expect("Failed to acquire secondary lock")),
                            };
                            
                            match recurse(&persistor, state_new) {
                                Ok(_) => {
                                    match PERSISTOR.root_set(record, state_old, state_new) {
                                        Ok(_) => {
                                            debug!(
                                                "Completed ({:?}) {} -> {}",
                                                start.elapsed(), query.chars().take(128).collect::<String>(), output,
                                            );
                                            return output
                                        },
                                        Err(_) => {
                                            info!("Rerunning (x{}) due to concurrency collision: {}", runs, query);
                                            continue
                                        }
                                    }
                                },
                                Err(err) =>  {
                                    panic!("{:?}", err);
                                }
                            }
                        }
                    },
                    false => {
                        info!("Rerunning (x{}) due to concurrency collision: {}", runs, query);
                        continue
                    }
                }
            }
        }
    }
}

unsafe fn sync_error(sc: *mut s7::s7_scheme) -> s7::s7_pointer {
    s7::s7_error(
        sc,
        s7::s7_make_symbol(sc, c"sync-web-error".as_ptr()),
        s7::s7_list(sc, 1, s7::s7_make_string(
            sc,
            c"journal encountered unexpected error".as_ptr(),
        )),
    )
}

fn type_s7_sync_pair() -> Type {
    unsafe extern "C" fn free(_sc: *mut s7::s7_scheme, obj: s7::s7_pointer) -> s7::s7_pointer {
        sync_heap_free(s7::s7_c_object_value(obj));
        std::ptr::null_mut()
    }

    unsafe extern "C" fn mark(_sc: *mut s7::s7_scheme, _obj: s7::s7_pointer) -> s7::s7_pointer {
        std::ptr::null_mut()
    }

    unsafe extern "C" fn is_equal(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        match sync_is_pair(s7::s7_cadr(args)) {
            true => {
                let word1 = sync_heap_read(s7::s7_c_object_value(s7::s7_car(args)));
                let word2 = sync_heap_read(s7::s7_c_object_value(s7::s7_cadr(args)));
                s7::s7_make_boolean(sc, word1 == word2)
            },
            false => {
                s7::s7_wrong_type_arg_error(
                    sc, c"equal?".as_ptr(), 2, s7::s7_cadr(args),
                    c"a sync-pair".as_ptr(),
                )
            }
        }
    }

    unsafe extern "C" fn to_string(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        string_to_s7(sc, format!(
            "(sync-pair #u({}))",
            sync_heap_read(s7::s7_c_object_value(s7::s7_car(args)))
                .iter()
                .map(|&byte| byte.to_string())
                .collect::<Vec<String>>().join(" "),
        ).as_str())
    }

    Type::new(
        c"sync-pair",
        free,
        mark,
        is_equal,
        to_string,
    )
}

fn primitive_s7_sync_hash() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let data_bv = s7::s7_car(args);

        // check the input arguments
        if !s7::s7_is_byte_vector(data_bv) {
            return s7::s7_wrong_type_arg_error(
                sc, c"sync-hash".as_ptr(), 1, data_bv,
                c"a byte-vector".as_ptr(),
            )
        }

        // convert to rust data types
        let mut data = vec![];
        for i in 0..s7::s7_vector_length(data_bv) {
            data.push(s7::s7_byte_vector_ref(data_bv, i as i64))
        }

        let digest = Sha256::digest(data).to_vec();
        let digest_bv = s7::s7_make_byte_vector(sc, SIZE as i64, 1, std::ptr::null_mut());
        for i in 0..SIZE { s7::s7_byte_vector_set(digest_bv, i as i64, digest[i]); }
        digest_bv
    }

    Primitive::new(
        code,
        c"sync-hash",
        c"(sync-hash bv) compute the SHA-256 digest of a byte vector",
        1, 0, false,
    )
}

fn primitive_s7_sync_pair() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let digest = s7::s7_car(args);

        if !s7::s7_is_byte_vector(digest) || s7::s7_vector_length(digest) as usize != SIZE {
            return s7::s7_wrong_type_arg_error(
                sc, c"sync-pair".as_ptr(), 1, digest,
                c"a hash-sized byte-vector".as_ptr(),
            )
        }

        let mut word = [0 as u8; SIZE];
        for i in 0..SIZE { word[i] = s7::s7_byte_vector_ref(digest, i as i64); }

        let persistor = {
            let session = SESSIONS.lock().expect("Failed to acquire sessions lock");
            &session.get(&(sc as usize)).expect("Session not found for sync-pair").persistor.clone()
        };

        if word == NULL || persistor.branch_get(word).is_ok() || PERSISTOR.branch_get(word).is_ok() {
            s7::s7_make_c_object(sc, SYNC_PAIR_TAG, sync_heap_make(word))
        } else {
            sync_error(sc)
        }
    }

    Primitive::new(
        code,
        c"sync-pair",
        c"(sync-pair digest) returns the sync pair defined by the digest",
        1, 0, false,
    )
}

fn primitive_s7_sync_is_pair() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        s7::s7_make_boolean(sc, sync_is_pair(s7::s7_car(args)))
    }

    Primitive::new(
        code,
        c"sync-pair?",
        c"(sync-pair?) returns whether the object is a sync pair",
        1, 0, false,
    )
}

fn primitive_s7_sync_null() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, _args: s7::s7_pointer) -> s7::s7_pointer {
        s7::s7_make_c_object(sc, SYNC_PAIR_TAG, sync_heap_make(NULL))
    }

    Primitive::new(
        code,
        c"sync-null",
        c"(sync-null) returns the null synchronic pair",
        0, 0, false,
    )
}

fn primitive_s7_sync_is_null() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        match sync_is_pair(s7::s7_car(args)) {
            false => s7::s7_wrong_type_arg_error(
                sc, c"sync-null?".as_ptr(), 1, s7::s7_car(args),
                c"a sync-pair".as_ptr(),
            ),
            true => {
                let word = sync_heap_read(s7::s7_c_object_value(s7::s7_car(args)));
                for i in 0..SIZE {
                    if word[i] != 0 {
                        return s7::s7_make_boolean(sc, false);
                    }
                }
                s7::s7_make_boolean(sc, true)
            },
        }
    }

    Primitive::new(
        code,
        c"sync-null?",
        c"(sync-null? sp) returns a boolean indicating whether sp is equal to sync-null",
        1, 0, false,
    )
}

fn primitive_s7_sync_pair_to_bytes() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        match sync_is_pair(s7::s7_car(args)) {
            false => {
                s7::s7_wrong_type_arg_error(
                    sc, c"sync-pair->byte-vector".as_ptr(), 1, s7::s7_car(args),
                    c"a sync-pair".as_ptr(),
                )
            }
            true => {
                let word = sync_heap_read(s7::s7_c_object_value(s7::s7_car(args)));
                let bv = s7::s7_make_byte_vector(sc, SIZE as i64, 1, std::ptr::null_mut());
                for i in 0..SIZE { s7::s7_byte_vector_set(bv, i as i64, word[i]); }
                bv
            },
        }
    }

    Primitive::new(
        code,
        c"sync-pair->byte-vector",
        c"(sync-pair->byte-vector sp) returns the byte-vector digest of a sync pair)",
        1, 0, false,
    )
}

fn primitive_s7_sync_cons() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let persistor = {
            let session = SESSIONS.lock().expect("Failed to acquire sessions lock");
            &session.get(&(sc as usize)).expect("Session not found for sync-cons").persistor.clone()
        };

        let handle_arg = | obj, number | {
            if sync_is_pair(obj) {
                Ok(sync_heap_read(s7::s7_c_object_value(obj)))
            } else if s7::s7_is_byte_vector(obj) {
                let mut content = vec![];
                for i in 0..s7::s7_vector_length(obj) {
                    content.push(s7::s7_byte_vector_ref(obj, i as i64))
                }
                match persistor.leaf_set(content) {
                    Ok(atom) => Ok(atom),
                    Err(_) => Err(sync_error(sc)),
                }
            } else {
                Err(s7::s7_wrong_type_arg_error(
                    sc, c"sync-cons".as_ptr(), number, obj,
                    c"a byte vector or a sync pair".as_ptr(),
                ))
            }
        };

        match (handle_arg(s7::s7_car(args), 1), handle_arg(s7::s7_cadr(args), 2)) {
            (Ok(left), Ok(right)) => match persistor.branch_set(left, right) {
                Ok(pair) => s7::s7_make_c_object(sc, SYNC_PAIR_TAG, sync_heap_make(pair)),
                Err(_) => sync_error(sc),
            },
            (Err(left), Ok(_)) => left,
            (Ok(_), Err(right)) => right,
            (Err(left), Err(_)) => left,
        }
    }

    Primitive::new(
        code,
        c"sync-cons",
        c"(sync-cons first rest) construct a lisp pair",
        2, 0, false,
    )
}

fn primitive_s7_sync_car() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        if !sync_is_pair(s7::s7_car(args)) {
            return s7::s7_wrong_type_arg_error(
                sc, c"sync-car".as_ptr(), 1, s7::s7_car(args),
                c"a sync-pair".as_ptr(),
            )
        }
        sync_cxr(sc, args, c"sync-car", | children | { children.0 })
    }

    Primitive::new(
        code,
        c"sync-car",
        c"(sync-car pair) retrieve the first element of a pair",
        1, 0, false,
    )
}

fn primitive_s7_sync_cdr() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        if !sync_is_pair(s7::s7_car(args)) {
            return s7::s7_wrong_type_arg_error(
                sc, c"sync-cdr".as_ptr(), 1, s7::s7_car(args),
                c"a sync-pair".as_ptr(),
            )
        }
        sync_cxr(sc, args, c"sync-cdr", | children | { children.1 })
    }

    Primitive::new(
        code,
        c"sync-cdr",
        c"(sync-car pair) retrieve the second element of a pair",
        1, 0, false,
    )
}

fn primitive_s7_sync_create() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let id = s7::s7_car(args);

        if !s7::s7_is_byte_vector(id) || s7::s7_vector_length(id) as usize != SIZE {
            return s7::s7_wrong_type_arg_error(
                sc, c"sync-create".as_ptr(), 1, id,
                c"a hash-sized byte-vector".as_ptr(),
            )
        }

        let mut record: Word = [0 as u8; SIZE];

        for i in 0..SIZE {
            record[i as usize] = s7::s7_byte_vector_ref(id, i as i64)
        }

        debug!("Adding record: {}", hex::encode(record));

        match PERSISTOR.root_new(
            record,
            PERSISTOR.branch_set(
                PERSISTOR.leaf_set(GENESIS_STR.as_bytes().to_vec()).expect("Failed to create genesis leaf for new record"),
                NULL,
            ).expect("Failed to create genesis branch for new record"),
        ) {
            Ok(_) => {
                s7::s7_make_boolean(sc, true)
            },
            Err(_) => s7::s7_error(
                sc,
                s7::s7_make_symbol(sc, c"sync-web-error".as_ptr()),
                s7::s7_list(sc, 1, s7::s7_make_string(
                    sc,
                    c"record ID is already in use".as_ptr(),
                )),
            ),
        }
    }

    Primitive::new(
        code,
        c"sync-create",
        c"(sync-create id) create a new synchronic record with the given 32-byte ID",
        1, 0, false,
    )
}

fn primitive_s7_sync_delete() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let id = s7::s7_car(args);

        if !s7::s7_is_byte_vector(id) || s7::s7_vector_length(id) as usize != SIZE {
            return s7::s7_wrong_type_arg_error(
                sc, c"sync-delete".as_ptr(), 1, id,
                c"a hash-sized byte-vector".as_ptr(),
            )
        }

        let mut record: Word = [0 as u8; SIZE];

        for i in 0..s7::s7_vector_length(id) {
            record[i as usize] = s7::s7_byte_vector_ref(id, i as i64)
        }

        if record == NULL {
            return s7::s7_error(
                sc,
                s7::s7_make_symbol(sc, c"sync-web-error".as_ptr()),
                s7::s7_list(sc, 1, s7::s7_make_string(
                    sc,
                    c"cannot delete the root record".as_ptr(),
                )),
            )
        }

        debug!("Deleting record: {}", hex::encode(record));

        match PERSISTOR.root_delete(record) {
            Ok(_) => {
                s7::s7_make_boolean(sc, true)
            },
            Err(_) => s7::s7_error(
                sc,
                s7::s7_make_symbol(sc, c"sync-web-error".as_ptr()),
                s7::s7_list(sc, 1, s7::s7_make_string(
                    sc,
                    c"record ID does not exist".as_ptr(),
                )),
            ),
        }
    }

    Primitive::new(
        code,
        c"sync-delete",
        c"(sync-delete id) delete the synchronic record with the given 32-byte ID",
        1, 0, false,
    )
}

fn primitive_s7_sync_all() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, _args: s7::s7_pointer) -> s7::s7_pointer {
        let mut list = s7::s7_list(sc, 0);

        for record in PERSISTOR.root_list().into_iter().rev() {
            let bv = s7::s7_make_byte_vector(sc, SIZE as i64, 1, std::ptr::null_mut());
            for i in 0..SIZE { s7::s7_byte_vector_set(bv, i as i64, record[i]); }

            list = s7::s7_cons(sc, bv, list)
        }

        list
    }

    Primitive::new(
        code,
        c"sync-all",
        c"(sync-all) list all synchronic record IDs in ascending order",
        0, 0, false,
    )
}

fn primitive_s7_sync_call() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let message_expr = s7::s7_car(args);
        let blocking = s7::s7_cadr(args);

        if !s7::s7_is_boolean(blocking) {
            return s7::s7_wrong_type_arg_error(
                sc, c"sync-call".as_ptr(), 2, blocking,
                c"a boolean".as_ptr(),
            )
        }

        let record = match s7::s7_is_null(sc, s7::s7_cddr(args)) {
            true => {
                let session = SESSIONS.lock().unwrap();
                session.get(&(sc as usize)).unwrap().record
            },
            false => {
                let bv = s7::s7_caddr(args);
                // check the input arguments
                if !s7::s7_is_byte_vector(bv) || s7::s7_vector_length(bv) as usize != SIZE {
                    return s7::s7_wrong_type_arg_error(
                        sc, c"sync-call".as_ptr(), 3, bv,
                        c"a hash-sized byte-vector".as_ptr(),
                    )
                }

                let mut record = [0 as u8; SIZE];
                for i in 0..SIZE { record[i] = s7::s7_byte_vector_ref(bv, i as i64); }
                record
            }
        };

        match PERSISTOR.root_get(record) {
            Ok(_) => {
                let message = to_str_or_err(
                    CStr::from_ptr(s7::s7_object_to_c_string(sc, message_expr)));
                if s7::s7_boolean(sc, blocking) {
                    let result = JOURNAL.evaluate_record(record, message.as_str());
                    let c_result = CString::new(format!("(quote {})", result)).unwrap();
                    s7::s7_eval_c_string(sc, c_result.as_ptr())
                } else {
                    tokio::spawn(async move {
                        JOURNAL.evaluate_record(record, message.as_str());
                    });
                    s7::s7_make_boolean(sc, true)
                }
            }
            Err(_) => {
                s7::s7_error(
                    sc,
                    s7::s7_make_symbol(sc, c"sync-web-error".as_ptr()),
                    s7::s7_list(
                        sc, 1,
                        s7::s7_make_string(sc, c"record ID does not exist".as_ptr()),
                    ),
                )
            }
        }
    }

    Primitive::new(
        code,
        c"sync-call",
        c"(sync-call query blocking? id) query the provided record ID or self if ID not provided",
        2, 1, false,
    )
}

fn primitive_s7_sync_http() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let obj2str = | obj | {
            CStr::from_ptr(s7::s7_object_to_c_string(sc, obj)).to_str().unwrap().to_owned()
        };

        let vec2s7 = | vector: Vec<u8> | {
            let bv = s7::s7_make_byte_vector(sc, vector.len() as i64, 1, std::ptr::null_mut());
            for i in 0..vector.len() { s7::s7_byte_vector_set(bv, i as i64, vector[i]); }
            bv
        };

        let method = obj2str(s7::s7_car(args));
        let url = obj2str(s7::s7_cadr(args));

        let body = if s7::s7_list_length(sc, args) >= 3 {
            obj2str(s7::s7_caddr(args))
        } else {
            String::from("")
        };

        let cache_mutex = {
            let session = SESSIONS.lock().unwrap();
            &session.get(&(sc as usize)).unwrap().cache.clone()
        };

        let mut cache = cache_mutex.lock().unwrap();

        let key = (method.clone(), url.clone(), body.as_bytes().to_vec());

        match cache.get(&key) {
            Some(bytes) => {
                debug!("Cache hit on key {:?}", key);
                vec2s7(bytes.to_vec())
            },
            None => {
                let result = tokio::task::block_in_place(move || {
                    tokio::runtime::Handle::current().block_on(async move {
                        match method.to_lowercase() {
                            method if method == "get" => {
                                reqwest::Client::new().get(&url[1..url.len() -1]).send().
                                    await.unwrap().bytes().await
                            }
                            method if method == "post" => {
                                reqwest::Client::new()
                                    .post(&url[1..url.len() -1])
                                    .body(String::from(&body[1..body.len() -1]))
                                    .send().await.unwrap().bytes().await
                            }
                            _ => {
                                panic!("Unsupported HTTP method")
                            }
                        }
                    })
                });

                match result {
                    Ok(vector) => {
                        cache.insert(key, vector.to_vec());
                        vec2s7(vector.to_vec())
                    }
                    Err(_) => sync_error(sc),
                }
            }
        }
    }

    Primitive::new(
        code,
        c"sync-http",
        c"(sync-http method url . data) make an http request where method is 'get or 'post",
        2, 2, false,
    )
}

fn primitive_s7_sync_remote() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let obj2str = | obj | {
            CStr::from_ptr(s7::s7_object_to_c_string(sc, obj)).to_str().unwrap().to_owned()
        };

        let vec2s7 = | mut vector: Vec<u8> | {
            vector.insert(0, 39); // add quote character so that it evaluates correctly
            vector.push(0);
            let c_string = CString::from_vec_with_nul(vector).unwrap();
            s7::s7_eval_c_string(sc, c_string.as_ptr())
        };

        let url = obj2str(s7::s7_car(args));

        let body = obj2str(s7::s7_cadr(args));

        let cache_mutex = {
            let session = SESSIONS.lock().unwrap();
            &session.get(&(sc as usize)).unwrap().cache.clone()
        };

        let mut cache = cache_mutex.lock().unwrap();

        let key = (String::from("post"), url.clone(), body.as_bytes().to_vec());

        match cache.get(&key) {
            Some(bytes) => {
                debug!("Cache hit on key {:?}", key);
                vec2s7(bytes.to_vec())
            },
            None => {
                let result = tokio::task::block_in_place(move || {
                    tokio::runtime::Handle::current().block_on(async move {
                        reqwest::Client::new()
                            .post(&url[1..url.len() -1])
                            .body(body)
                            .send().await.unwrap().bytes().await
                    })
                });

                match result {
                    Ok(bytes) => {
                        cache.insert(key, bytes.to_vec());
                        vec2s7(bytes.to_vec())
                    },
                    Err(_) => sync_error(sc),
                }
            }
        }
    }

    Primitive::new(
        code,
        c"sync-remote",
        c"(sync-remote url data) make a post http request with the data payload)",
        2, 0, false,
    )
}

unsafe fn string_to_s7(sc: *mut s7::s7_scheme, string: &str) -> s7::s7_pointer {
    let c_string = CString::new(string).unwrap();
    let s7_string = s7::s7_make_string(sc, c_string.as_ptr());
    s7::s7_object_to_string(sc, s7_string, false)
}

unsafe fn sync_heap_make(word: Word) -> *mut libc::c_void {
    let ptr = libc::malloc(SIZE);
    let array: &mut [u8] = std::slice::from_raw_parts_mut(ptr as *mut u8, SIZE);
    for i in 0..SIZE { array[i] = word[i] as u8; }
    ptr
}

unsafe fn sync_heap_read(ptr: *mut libc::c_void) -> Word {
    std::slice::from_raw_parts_mut(ptr as *mut u8, SIZE).try_into().unwrap()
}

unsafe fn sync_heap_free(ptr: *mut libc::c_void) {
    libc::free(ptr);
}

unsafe fn sync_is_pair(obj: s7::s7_pointer) -> bool {
    s7::s7_is_c_object(obj) && s7::s7_c_object_type(obj) == SYNC_PAIR_TAG
}

unsafe fn sync_cxr(
    sc: *mut s7::s7_scheme,
    args: s7::s7_pointer,
    name: &CStr,
    selector: fn((Word, Word)) -> Word,
) -> s7::s7_pointer {
    let pair = s7::s7_car(args);
    let word = sync_heap_read(s7::s7_c_object_value(pair));

    let persistor = {
        let session = SESSIONS.lock().unwrap();
        &session.get(&(sc as usize)).unwrap().persistor.clone()
    };

    let child_return = | word | {
        let pair_return = | word | {
            s7::s7_make_c_object(sc, SYNC_PAIR_TAG, sync_heap_make(word))
        };

        let vector_return = | vector: Vec<u8> | {
            let bv = s7::s7_make_byte_vector(sc, vector.len() as i64, 1, std::ptr::null_mut());
            for i in 0..vector.len() { s7::s7_byte_vector_set(bv, i as i64, vector[i]); }
            bv
        };

        if word == NULL {
            pair_return(word)
        } else if let Ok(_) = persistor.branch_get(word) {
            pair_return(word)
        } else if let Ok(_) = PERSISTOR.branch_get(word) {
            pair_return(word)
        } else if let Ok(content) = persistor.leaf_get(word) {
            vector_return(content)
        } else if let Ok(content) = PERSISTOR.leaf_get(word) {
            vector_return(content)
        } else {
            sync_error(sc)
        }
    };

    match sync_is_pair(pair) {
        true => match persistor.branch_get(word) {
            Ok(children) => child_return(selector(children)),
            Err(_) => match PERSISTOR.branch_get(word) {
                Ok(children) => child_return(selector(children)),
                Err(_) => sync_error(sc),
            }
        },
        false => s7::s7_wrong_type_arg_error(
            sc, name.as_ptr(), 1, pair,
            c"a sync-pair".as_ptr(),
        )
    }
}

