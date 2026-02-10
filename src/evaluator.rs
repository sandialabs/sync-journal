#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(warnings)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use libc::free;
use log::info;
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Map, Value};
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
        let expr = s7_string(s7_object_to_string(sc, obj, false));
        let cstr = CStr::from_ptr(expr);
        let result = match cstr.to_str() {
            Ok(rust_str) => match s7_is_string(obj) {
                true => format!("\"{}\"", rust_str),
                false => format!("{}", rust_str.to_owned()),
            },
            Err(_) => format!("(error 'encoding-error \"Failed to encode string\")"),
        };
        result
    }
}

pub fn scheme2json(expression: &str) -> Result<Value, String> {
    // <TYPE>: <JSON>
    // ------------------------------------------------------
    // symbol: "string"
    // number: 5.5
    // boolean: true/false
    // list: []
    // symbol assoc lists: { }
    // special types
    // - @pair: {"*type/pair*": ["first", "second"]}
    // - @string: { "*type/string*": "this is my string" }
    // - @rational: { "*type/rational*": "5/5" }
    // - @complex: { "*type/complex*": "5/5" }
    // - @vector: {"*type/vector*: ["blah", "blah"]}
    // - @byte-vector: {"*type/byte-vector*: "deadbeef0000" }
    // - @float-vector: {"*type/float-vector*": [3.2, 8.6, 0.1]}
    // - @hash-table: {"*type/hash-table*": [["a", 6], [53, 199]]}

    unsafe {
        let sc: *mut s7_scheme = s7_init();

        // Parse the expression without evaluating it
        let c_expr = CString::new(expression).unwrap_or_else(|_| CString::new("()").unwrap());
        let input_port = s7_open_input_string(sc, c_expr.as_ptr());
        let s7_obj = s7_read(sc, input_port);
        s7_close_input_port(sc, input_port);

        let result = s7_obj_to_json(sc, s7_obj);
        s7_free(sc);
        result
    }
}

pub fn json2scheme(expression: Value) -> Result<String, String> {
    unsafe {
        let sc: *mut s7_scheme = s7_init();
        match json_to_s7_obj(sc, &expression) {
            Ok(s7_obj) => {
                let result = obj2str(sc, s7_obj);
                s7_free(sc);
                Ok(result)
            }
            Err(err) => {
                s7_free(sc);
                Err(err)
            }
        }
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
            primitive_print(),
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

        // let s7_c_str = s7_string(s7_object_to_string(sc, arg, false));
        // let c_string = CStr::from_ptr(s7_c_str);
        let bytes = obj2str(sc, arg).into_bytes();

        let bv = s7_make_byte_vector(sc, bytes.len() as i64, 1 as i64, std::ptr::null_mut());
        for (i, b) in bytes.iter().enumerate() {
            s7_byte_vector_set(bv, i as i64, *b);
        }
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

        let s7_c_str = s7_string(s7_object_to_string(sc, arg, false));
        let hex_string = CStr::from_ptr(s7_c_str)
            .to_str()
            .expect("Failed to convert C string to hex string");

        let result: Result<Vec<u8>, ParseIntError> = (0..hex_string.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16))
            .collect();

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

fn primitive_print() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7_scheme, args: s7_pointer) -> s7_pointer {
        let mut result = String::new();
        let mut current_arg = args;

        while !s7_is_null(sc, current_arg) {
            let arg = s7_car(current_arg);
            let str_rep = obj2str(sc, arg);

            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(&str_rep);
            current_arg = s7_cdr(current_arg);
        }

        println!("{}", result);

        if s7_is_null(sc, args) {
            s7_unspecified(sc)
        } else {
            let mut last_arg = args;
            while !s7_is_null(sc, s7_cdr(last_arg)) {
                last_arg = s7_cdr(last_arg);
            }
            s7_car(last_arg)
        }
    }

    Primitive::new(
        code,
        c"print",
        c"(print obj ...) print objects to the console and returns the last object",
        0,
        0,
        true,
    )
}

unsafe fn s7_obj_to_json(sc: *mut s7_scheme, obj: s7_pointer) -> Result<Value, String> {
    unsafe {
        if s7_is_null(sc, obj) {
            Ok(Value::Null)
        } else if s7_is_boolean(obj) {
            Ok(Value::Bool(s7_boolean(sc, obj)))
        } else if s7_is_integer(obj) {
            Ok(Value::Number(serde_json::Number::from(s7_integer(obj))))
        } else if s7_is_real(obj) {
            if let Some(num) = serde_json::Number::from_f64(s7_real(obj)) {
                Ok(Value::Number(num))
            } else {
                Err("Invalid floating point number - cannot convert to JSON".to_string())
            }
        } else if s7_is_string(obj) {
            // let c_str = s7_string(obj);
            // let rust_str = CStr::from_ptr(c_str).to_string_lossy();
            let rust_str = obj2str(sc, obj);

            // Check if it's a special type marker
            let mut special_type = Map::new();
            special_type.insert(
                "*type/string*".to_string(),
                Value::String(String::from(&rust_str[1..(rust_str.len() - 1)])),
            );
            Ok(Value::Object(special_type))
        } else if s7_is_symbol(obj) {
            let c_str = s7_symbol_name(obj);
            let rust_str = CStr::from_ptr(c_str).to_string_lossy();
            Ok(Value::String(rust_str.to_string()))
        } else if s7_is_pair(obj) {
            // Check if it's a quote form first
            let car = s7_car(obj);
            if s7_is_symbol(car) {
                let symbol_name_ptr = s7_symbol_name(car);
                if !symbol_name_ptr.is_null() {
                    let symbol_name = CStr::from_ptr(symbol_name_ptr).to_string_lossy();

                    if symbol_name == "quote" {
                        // Handle quote form: convert (quote expr) to ["quote", expr]
                        let cdr = s7_cdr(obj);
                        if s7_is_pair(cdr) && s7_is_null(sc, s7_cdr(cdr)) {
                            // It's a proper quote form: (quote expr)
                            let quoted_expr = s7_car(cdr);
                            let mut array = Vec::new();
                            array.push(Value::String("quote".to_string()));
                            array.push(s7_obj_to_json(sc, quoted_expr)?);
                            return Ok(Value::Array(array));
                        }
                    }
                }
            }

            // Check if it's an association list with proper list format (for JSON objects)
            if is_proper_assoc_list(sc, obj) {
                let mut map = Map::new();
                let mut current = obj;

                while !s7_is_null(sc, current) {
                    let pair = s7_car(current);
                    if s7_is_pair(pair) {
                        let key_obj = s7_car(pair);
                        let cdr_pair = s7_cdr(pair);

                        // Only handle list format (key value)
                        if s7_is_pair(cdr_pair) && s7_is_null(sc, s7_cdr(cdr_pair)) {
                            let value_obj = s7_car(cdr_pair);

                            if s7_is_symbol(key_obj) {
                                let key_c_str = s7_symbol_name(key_obj);
                                let key = CStr::from_ptr(key_c_str).to_string_lossy().to_string();
                                let value = s7_obj_to_json(sc, value_obj)?;
                                map.insert(key, value);
                            }
                        }
                    }
                    current = s7_cdr(current);
                }
                Ok(Value::Object(map))
            } else if s7_is_pair(obj) && !s7_is_pair(s7_cdr(obj)) {
                // Handle pairs as special type
                let mut special_type = Map::new();
                let mut pair_array = Vec::new();
                pair_array.push(s7_obj_to_json(sc, s7_car(obj))?);
                pair_array.push(s7_obj_to_json(sc, s7_cdr(obj))?);
                special_type.insert("*type/pair*".to_string(), Value::Array(pair_array));
                Ok(Value::Object(special_type))
            } else {
                // Regular list - convert to JSON array
                let mut array = Vec::new();
                let mut current = obj;

                while !s7_is_null(sc, current) {
                    array.push(s7_obj_to_json(sc, s7_car(current))?);
                    current = s7_cdr(current);
                }
                Ok(Value::Array(array))
            }
        } else if s7_is_byte_vector(obj) {
            let mut hex_string = String::new();
            let len = s7_vector_length(obj);

            for i in 0..len {
                let byte = s7_byte_vector_ref(obj, i);
                write!(&mut hex_string, "{:02x}", byte).unwrap();
            }

            let mut special_type = Map::new();
            special_type.insert("*type/byte-vector*".to_string(), Value::String(hex_string));
            Ok(Value::Object(special_type))
        } else if s7_is_vector(obj) {
            let mut special_type = Map::new();
            let mut array = Vec::new();
            let len = s7_vector_length(obj);

            for i in 0..len {
                array.push(s7_obj_to_json(sc, s7_vector_ref(sc, obj, i))?);
            }

            special_type.insert("*type/vector*".to_string(), Value::Array(array));
            Ok(Value::Object(special_type))
        } else if s7_is_rational(obj) {
            // Handle rational numbers as special type
            let rational_str = obj2str(sc, obj);
            let mut special_type = Map::new();
            special_type.insert("*type/rational*".to_string(), Value::String(rational_str));
            Ok(Value::Object(special_type))
        } else if s7_is_complex(obj) {
            // Handle complex numbers as special type
            let complex_str = obj2str(sc, obj);
            let mut special_type = Map::new();
            special_type.insert("*type/complex*".to_string(), Value::String(complex_str));
            Ok(Value::Object(special_type))
        } else if s7_is_hash_table(obj) {
            // Handle hash tables as special type
            let mut special_type = Map::new();
            let mut pairs = Vec::new();

            // Convert hash table to array of [key, value] pairs
            // This is a simplified approach - we'd need to iterate through the hash table
            special_type.insert("*type/hash-table*".to_string(), Value::Array(pairs));
            Ok(Value::Object(special_type))
        } else {
            // For debugging: let's see what type this actually is
            let type_info = if s7_is_procedure(obj) {
                "procedure"
            } else if s7_is_macro(sc, obj) {
                "macro"
            } else {
                "unknown"
            };

            Err(format!(
                "Unknown Scheme type '{}' - cannot convert to JSON",
                type_info
            ))
        }
    }
}

unsafe fn json_to_s7_obj(sc: *mut s7_scheme, json: &Value) -> Result<s7_pointer, String> {
    unsafe {
        match json {
            Value::Null => Ok(s7_nil(sc)),
            Value::Bool(b) => Ok(s7_make_boolean(sc, *b)),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(s7_make_integer(sc, i))
                } else if let Some(f) = n.as_f64() {
                    Ok(s7_make_real(sc, f))
                } else {
                    Err("Invalid number format in JSON".to_string())
                }
            }
            Value::String(s) => match CString::new(s.as_str()) {
                Ok(c_str) => Ok(s7_make_symbol(sc, c_str.as_ptr())),
                Err(_) => Err("Invalid string format in JSON - contains null bytes".to_string()),
            },
            Value::Array(arr) => {
                if arr.is_empty() {
                    Ok(s7_nil(sc))
                } else {
                    // Create (list ...) expression
                    let mut result = s7_nil(sc);

                    // Build arguments in reverse order
                    for item in arr.iter().rev() {
                        let s7_item = json_to_s7_obj(sc, item)?;
                        result = s7_cons(sc, s7_item, result);
                    }
                    Ok(result)
                }
            }
            Value::Object(obj) => {
                // Check for special type markers
                if obj.len() == 1 {
                    if let Some(Value::String(s)) = obj.get("*type/string*") {
                        match CString::new(s.as_str()) {
                            Ok(c_str) => return Ok(s7_make_string(sc, c_str.as_ptr())),
                            Err(_) => {
                                return Err(
                                    "Invalid string in *type/string* - contains null bytes"
                                        .to_string(),
                                );
                            }
                        }
                    }
                    if let Some(Value::Array(arr)) = obj.get("*type/vector*") {
                        let len = arr.len() as i64;
                        let vector = s7_make_vector(sc, len);
                        for (i, item) in arr.iter().enumerate() {
                            let s7_item = json_to_s7_obj(sc, item)?;
                            s7_vector_set(sc, vector, i as i64, s7_item);
                        }
                        return Ok(vector);
                    }
                    if let Some(Value::String(hex)) = obj.get("*type/byte-vector*") {
                        let bytes: Result<Vec<u8>, ParseIntError> = (0..hex.len())
                            .step_by(2)
                            .map(|i| {
                                if i + 2 <= hex.len() {
                                    u8::from_str_radix(&hex[i..i + 2], 16)
                                } else if i + 1 <= hex.len() {
                                    // Handle odd-length hex string
                                    u8::from_str_radix(&hex[i..i + 1], 16)
                                } else {
                                    Ok(0)
                                }
                            })
                            .collect();

                        match bytes {
                            Ok(bytes) => {
                                let len = bytes.len() as i64;
                                let bv = s7_make_byte_vector(sc, len, 1, std::ptr::null_mut());

                                for (i, &byte) in bytes.iter().enumerate() {
                                    s7_byte_vector_set(bv, i as i64, byte);
                                }

                                return Ok(bv);
                            }
                            Err(_) => {
                                return Err("Invalid hex string in *type/byte-vector*".to_string());
                            }
                        }
                    }
                    if let Some(Value::Array(arr)) = obj.get("*type/pair*") {
                        if arr.len() == 2 {
                            let car = json_to_s7_obj(sc, &arr[0])?;
                            let cdr = json_to_s7_obj(sc, &arr[1])?;
                            return Ok(s7_cons(sc, car, cdr));
                        } else {
                            return Err("*type/pair* must contain exactly 2 elements".to_string());
                        }
                    }
                }

                if obj.is_empty() {
                    Ok(s7_nil(sc))
                } else {
                    // Regular object - convert to association list
                    let mut result = s7_nil(sc);

                    for (key, value) in obj.iter().rev() {
                        let key_symbol = match CString::new(key.as_str()) {
                            Ok(c_key) => s7_make_symbol(sc, c_key.as_ptr()),
                            Err(_) => {
                                return Err(format!("Invalid key '{}' - contains null bytes", key));
                            }
                        };
                        let value_obj = json_to_s7_obj(sc, value)?;
                        // Create a list (key value) instead of a pair (key . value)
                        let value_list = s7_cons(sc, value_obj, s7_nil(sc));
                        let pair = s7_cons(sc, key_symbol, value_list);
                        result = s7_cons(sc, pair, result);
                    }
                    Ok(result)
                }
            }
        }
    }
}

unsafe fn is_proper_assoc_list(sc: *mut s7_scheme, obj: s7_pointer) -> bool {
    unsafe {
        if s7_is_null(sc, obj) {
            return true;
        }

        let mut current = obj;
        while !s7_is_null(sc, current) {
            if !s7_is_pair(current) {
                return false;
            }

            let car = s7_car(current);
            if !s7_is_pair(car) {
                return false;
            }

            let key = s7_car(car);
            if !s7_is_symbol(key) {
                return false;
            }

            let cdr_part = s7_cdr(car);
            // Only accept proper list format (key value)
            if !s7_is_pair(cdr_part) || !s7_is_null(sc, s7_cdr(cdr_part)) {
                return false;
            }

            current = s7_cdr(current);
        }
        true
    }
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
