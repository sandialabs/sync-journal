#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(warnings)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use libc::free;
use log::info;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt::Write;
use std::num::ParseIntError;
use std::os::raw::c_char;
use std::time::{SystemTime, UNIX_EPOCH};

type PrimitiveFunction = unsafe extern "C" fn(*mut s7_scheme, s7_pointer) -> s7_pointer;

#[derive(Clone)]
pub struct Primitive {
    code: PrimitiveFunction,
    name: &'static CStr,
    description: &'static CStr,
    args_required: usize,
    args_optional: usize,
    args_rest: bool,
}

impl Primitive {
    pub fn new(
        code: PrimitiveFunction,
        name: &'static CStr,
        description: &'static CStr,
        args_required: usize,
        args_optional: usize,
        args_rest: bool,
    ) -> Self {
        Self {
            code,
            name,
            description,
            args_required,
            args_optional,
            args_rest,
        }
    }
}

pub struct Type {
    name: &'static CStr,
    free: PrimitiveFunction,
    mark: PrimitiveFunction,
    is_equal: PrimitiveFunction,
    to_string: PrimitiveFunction,
}

impl Type {
    pub fn new(
        name: &'static CStr,
        free: PrimitiveFunction,
        mark: PrimitiveFunction,
        is_equal: PrimitiveFunction,
        to_string: PrimitiveFunction,
    ) -> Self {
        Self {
            name,
            free,
            mark,
            is_equal,
            to_string,
        }
    }
}

pub fn obj2str(sc: *mut s7_scheme, obj: *mut s7_cell) -> String {
    unsafe {
        let expr = s7_object_to_c_string(sc, obj);
        let cstr = CStr::from_ptr(expr);
        let result = match cstr.to_str() {
            Ok(expr) => expr.to_owned(),
            Err(_) => format!("(error 'encoding-error \"Failed to encode string\")"),
        };
        free(expr as *mut libc::c_void);
        result
    }
}

pub struct Evaluator {
    pub sc: *mut s7_scheme,
    primitives: Vec<Primitive>,
}

impl Evaluator {
    pub fn new(types: HashMap<i64, Type>, primitives: Vec<Primitive>) -> Self {
        let mut primitives_ = vec![
            primitive_hex_string_to_byte_vector(),
            primitive_byte_vector_to_hex_string(),
            primitive_expression_to_byte_vector(),
            primitive_byte_vector_to_expression(),
            primitive_random_byte_vector(),
            primitive_time_unix(),
        ];

        primitives_.extend(primitives);

        unsafe {
            let sc: *mut s7_scheme = s7_init();

            // remove insecure primitives
            for primitive in REMOVE {
                s7_define(
                    sc,
                    s7_rootlet(sc),
                    s7_make_symbol(sc, primitive.as_ptr()),
                    s7_make_symbol(sc, c"*removed*".as_ptr()),
                );
            }

            // add new types
            for (&tag_, type_) in types.iter() {
                let tag = s7_make_c_type(sc, type_.name.as_ptr());
                assert!(tag == tag_, "Type tag was not properly set");
                s7_c_type_set_gc_free(sc, tag, Some(type_.free));
                s7_c_type_set_gc_mark(sc, tag, Some(type_.mark));
                s7_c_type_set_is_equal(sc, tag, Some(type_.is_equal));
                s7_c_type_set_to_string(sc, tag, Some(type_.to_string));
            }

            // add new primitives
            for primitive in primitives_.iter() {
                s7_define_function(
                    sc,
                    primitive.name.as_ptr(),
                    Some(primitive.code),
                    primitive
                        .args_required
                        .try_into()
                        .expect("args_required conversion failed"),
                    primitive
                        .args_optional
                        .try_into()
                        .expect("args_optional conversion failed"),
                    primitive.args_rest,
                    primitive.description.as_ptr(),
                );
            }

            Self {
                sc,
                primitives: primitives_,
            }
        }
    }

    pub fn evaluate(&self, code: &str) -> String {
        unsafe {
            // execute query and return
            let wrapped = CString::new(format!(
                "(catch #t (lambda () (eval (read (open-input-string \"{}\")))) (lambda x {}))",
                code.replace("\\", "\\\\").replace("\"", "\\\""),
                "`(error ',(car x) ,(apply format (cons #f (cadr x))))",
            ))
            .expect("failed to create CString for evaluation");
            let s7_obj = s7_eval_c_string(self.sc, wrapped.as_ptr());
            obj2str(self.sc, s7_obj)
        }
    }
}

impl Drop for Evaluator {
    fn drop(&mut self) {
        unsafe {
            s7_free(self.sc);
        }
    }
}

fn primitive_expression_to_byte_vector() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7_scheme, args: s7_pointer) -> s7_pointer {
        let arg = s7_car(args);

        let s7_c_str = s7_object_to_c_string(sc, arg);
        let c_string = CStr::from_ptr(s7_c_str);

        let bv = s7_make_byte_vector(
            sc,
            c_string.to_bytes().len() as i64,
            1 as i64,
            std::ptr::null_mut(),
        );
        for (i, b) in c_string.to_bytes().iter().enumerate() {
            s7_byte_vector_set(bv, i as i64, *b);
        }
        free(s7_c_str as *mut libc::c_void);
        bv
    }

    Primitive::new(
        code,
        c"expression->byte-vector",
        c"(expression->byte-vector expr) convert a expression string to a byte vector",
        1,
        0,
        false,
    )
}

fn primitive_byte_vector_to_expression() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7_scheme, args: s7_pointer) -> s7_pointer {
        let arg = s7_car(args);

        if !s7_is_byte_vector(arg) {
            return s7_wrong_type_arg_error(
                sc,
                c"byte-vector->expression".as_ptr(),
                1,
                arg,
                c"a byte-vector".as_ptr(),
            );
        }

        let mut bytes = vec![39]; // quote so that it evaluates correctly
        for i in 0..s7_vector_length(arg) {
            bytes.push(s7_byte_vector_ref(arg, i))
        }
        bytes.push(0);

        match CString::from_vec_with_nul(bytes) {
            Ok(c_string) => s7_eval_c_string(sc, c_string.as_ptr()),
            Err(_) => s7_error(
                sc,
                s7_make_symbol(sc, c"encoding-error".as_ptr()),
                s7_list(
                    sc,
                    1,
                    s7_make_string(sc, c"Byte vector string is malformed".as_ptr()),
                ),
            ),
        }
    }

    Primitive::new(
        code,
        c"byte-vector->expression",
        c"(byte-vector->expression bv) convert a byte vector to an expression",
        1,
        0,
        false,
    )
}

fn primitive_hex_string_to_byte_vector() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7_scheme, args: s7_pointer) -> s7_pointer {
        let arg = s7_car(args);

        if !s7_is_string(arg) {
            return s7_wrong_type_arg_error(
                sc,
                c"hex-string->byte-vector".as_ptr(),
                1,
                arg,
                c"a hex string".as_ptr(),
            );
        }

        let s7_c_str = s7_object_to_c_string(sc, arg);
        let hex_string = CStr::from_ptr(s7_c_str)
            .to_str()
            .expect("Failed to convert C string to hex string");

        let result: Result<Vec<u8>, ParseIntError> = (1..hex_string.len() - 1)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16))
            .collect();

        free(s7_c_str as *mut libc::c_void);

        match result {
            Ok(result) => {
                let bv =
                    s7_make_byte_vector(sc, result.len() as i64, 1 as i64, std::ptr::null_mut());
                for i in 0..result.len() {
                    s7_byte_vector_set(bv, i as i64, result[i]);
                }
                bv
            }
            _ => s7_wrong_type_arg_error(
                sc,
                c"hex-string->byte-vector".as_ptr(),
                1,
                arg,
                c"a hex string".as_ptr(),
            ),
        }
    }

    Primitive::new(
        code,
        c"hex-string->byte-vector",
        c"(hex-string->byte-vector str) convert a hex string to a byte vector",
        1,
        0,
        false,
    )
}

fn primitive_byte_vector_to_hex_string() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7_scheme, args: s7_pointer) -> s7_pointer {
        let arg = s7_car(args);

        if !s7_is_byte_vector(arg) {
            return s7_wrong_type_arg_error(
                sc,
                c"byte-vector->hex-string".as_ptr(),
                1,
                arg,
                c"a byte-vector".as_ptr(),
            );
        }

        let mut bytes = vec![0 as u8; s7_vector_length(arg) as usize];
        for i in 0..bytes.len() as usize {
            bytes[i] = s7_byte_vector_ref(arg, i as i64);
        }

        let mut string = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(&mut string, "{:02x}", b).expect("Failed to write byte to hex string");
        }

        // todo: this might cause a pointer issue
        let c_string = CString::new(string).expect("Failed to create C string from hex string");
        s7_object_to_string(sc, s7_make_string(sc, c_string.as_ptr()), false)
    }

    Primitive::new(
        code,
        c"byte-vector->hex-string",
        c"(byte-vector->hex-string bv) convert a byte vector to a hex string",
        1,
        0,
        false,
    )
}

fn primitive_random_byte_vector() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7_scheme, args: s7_pointer) -> s7_pointer {
        let arg = s7_car(args);

        if !s7_is_integer(arg) || s7_integer(arg) < 0 {
            return s7_wrong_type_arg_error(
                sc,
                c"random-byte-vector".as_ptr(),
                1,
                arg,
                c"a non-negative integer".as_ptr(),
            );
        }

        let length = s7_integer(arg);
        let mut rng = OsRng;
        let mut bytes = vec![
            0u8;
            length
                .try_into()
                .expect("Length exceeds system memory limits")
        ];
        rng.fill_bytes(&mut bytes);

        let bv = s7_make_byte_vector(sc, length as i64, 1, std::ptr::null_mut());
        for i in 0..length as usize {
            s7_byte_vector_set(bv, i as i64, bytes[i]);
        }
        bv
    }

    Primitive::new(
        code,
        c"random-byte-vector",
        c"(random-byte-vector length) generate a securely random byte vector of the provided length",
        1, 0, false,
    )
}

fn primitive_time_unix() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7_scheme, _args: s7_pointer) -> s7_pointer {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => s7_make_real(sc, duration.as_secs_f64()),
            Err(_) => s7_error(
                sc,
                s7_make_symbol(sc, c"time-error".as_ptr()),
                s7_list(
                    sc,
                    1,
                    s7_make_string(sc, c"Failed to get system time".as_ptr()),
                ),
            ),
        }
    }

    Primitive::new(
        code,
        c"time-unix",
        c"(time-unix) returns current Unix time in seconds",
        0,
        0,
        false,
    )
}

static REMOVE: [&'static CStr; 84] = [
    c"*autoload*",
    c"*autoload-hook*",
    c"*cload-directory*",
    c"*features*",
    c"*function*",
    c"*libraries*",
    c"*load-hook*",
    c"*load-path*",
    c"*stderr*",
    c"*stdin*",
    c"*stdout*",
    c"abort",
    c"autoload",
    c"c-object-type",
    c"c-object?",
    c"c-pointer",
    c"c-pointer->list",
    c"c-pointer-info",
    c"c-pointer-type",
    c"c-pointer-weak1",
    c"c-pointer-weak2",
    c"c-pointer?",
    c"call-with-current-continuation",
    c"call-with-exit",
    c"call-with-input-file",
    c"call-with-input-file",
    c"call-with-input-string",
    c"call-with-output-file",
    c"call-with-output-string",
    c"call/cc",
    c"close-input-port",
    c"close-output-port",
    c"continuation?",
    c"current-error-port",
    c"current-input-port",
    c"current-output-port",
    c"dilambda",
    c"dilambda?",
    c"dynamic-unwind",
    c"dynamic-wind",
    c"emergency-exit",
    c"exit",
    c"flush-output-port",
    c"gc",
    c"get-output-string",
    c"goto?",
    c"hook-functions",
    c"input-port?",
    c"load",
    c"make-hook",
    c"open-input-file",
    c"open-input-function",
    c"open-output-file",
    c"open-output-function",
    c"open-output-string",
    c"output-port?",
    c"owlet",
    c"pair-filename",
    c"pair-line-number",
    c"peek-char",
    c"port-closed?",
    c"port-file",
    c"port-filename",
    c"port-line-number",
    c"port-position",
    c"profile-in",
    c"random",
    c"read-char",
    c"read-string",
    c"read-byte",
    c"read-line",
    c"require",
    c"s7-optimize",
    c"set-current-error-port",
    c"stacktrace",
    c"unlet",
    c"with-baffle",
    c"with-input-from-file",
    c"with-output-to-file",
    c"with-output-to-string",
    c"write",
    c"write-byte",
    c"write-char",
    c"write-string",
];
