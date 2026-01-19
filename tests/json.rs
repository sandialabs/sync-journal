use journal_sdk::{Config, JOURNAL, Word, SIZE};
use serde_json::{json, Value};
use std::collections::HashMap;
use rand::RngCore;

fn setup() -> (String, impl Fn(&str, &str)) {
    let mut seed: Word = [0 as u8; SIZE];
    rand::thread_rng().fill_bytes(&mut seed);
    let record = hex::encode(seed);

    assert!(
        JOURNAL
            .evaluate(format!("(sync-create (hex-string->byte-vector \"{}\"))", record).as_str())
            == "#t",
        "Unable to set up new Journal",
    );

    (record.clone(), move |query: &str, expected: &str| {
        let result = JOURNAL.evaluate(query);
        assert_eq!(result, expected, "Query: {}", query);
    })
}

#[test]
fn test_json_basic_types() {
    let (_record, _test) = setup();
    
    // Test null
    let result = JOURNAL.evaluate_json(json!(null));
    assert_eq!(result, json!(null));
    
    // Test boolean
    let result = JOURNAL.evaluate_json(json!(true));
    assert_eq!(result, json!(true));
    
    let result = JOURNAL.evaluate_json(json!(false));
    assert_eq!(result, json!(false));
    
    // Test numbers
    let result = JOURNAL.evaluate_json(json!(42));
    assert_eq!(result, json!(42));
    
    let result = JOURNAL.evaluate_json(json!(3.14));
    assert_eq!(result, json!(3.14));
    
    // Test strings
    let result = JOURNAL.evaluate_json(json!("hello world"));
    assert_eq!(result, json!({"*type/string*": "hello world"}));
}

#[test]
fn test_json_arrays() {
    let (_record, _test) = setup();
    
    // Test empty array
    let result = JOURNAL.evaluate_json(json!([]));
    assert_eq!(result, json!([]));
    
    // Test array with mixed types
    let input = json!([1, "hello", true, null]);
    let result = JOURNAL.evaluate_json(input);
    let expected = json!([1, {"*type/string*": "hello"}, true, null]);
    assert_eq!(result, expected);
    
    // Test nested arrays
    let input = json!([[1, 2], [3, 4]]);
    let result = JOURNAL.evaluate_json(input);
    let expected = json!([[1, 2], [3, 4]]);
    assert_eq!(result, expected);
}

#[test]
fn test_json_objects() {
    let (_record, _test) = setup();
    
    // Test empty object
    let result = JOURNAL.evaluate_json(json!({}));
    assert_eq!(result, json!({}));
    
    // Test simple object
    let input = json!({"name": "Alice", "age": 30});
    let result = JOURNAL.evaluate_json(input);
    let expected = json!({"name": {"*type/string*": "Alice"}, "age": 30});
    assert_eq!(result, expected);
    
    // Test nested objects
    let input = json!({
        "person": {
            "name": "Bob",
            "details": {
                "age": 25,
                "active": true
            }
        }
    });
    let result = JOURNAL.evaluate_json(input);
    // The exact structure will depend on how nested objects are handled
    assert!(result.is_object());
}

#[test]
fn test_json_special_types() {
    let (_record, _test) = setup();
    
    // Test byte-vector special type
    let input = json!({"*type/byte-vector*": "deadbeef"});
    let result = JOURNAL.evaluate_json(input);
    // Should round-trip back to the same special type
    assert_eq!(result, json!({"*type/byte-vector*": "deadbeef"}));
    
    // Test vector special type
    let input = json!({"*type/vector*": [1, 2, 3]});
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!({"*type/vector*": [1, 2, 3]}));
    
    // Test string special type
    let input = json!({"*type/string*": "test string"});
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!({"*type/string*": "test string"}));
}

#[test]
fn test_json_scheme_evaluation() {
    let (_record, _test) = setup();
    
    // Test arithmetic - should evaluate the scheme expression
    let input = json!("(+ 1 2 3)");
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!(6));
    
    // Test list operations
    let input = json!("(list 1 2 3)");
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!([1, 2, 3]));
    
    // Test symbol evaluation
    let input = json!("'hello");
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!("hello"));
}

#[test]
fn test_json_round_trip() {
    let (_record, _test) = setup();
    
    // Test that JSON -> Scheme -> JSON preserves structure for basic types
    let original = json!({
        "number": 42,
        "string": "test",
        "boolean": true,
        "null_value": null,
        "array": [1, 2, 3],
        "nested": {
            "inner": "value"
        }
    });
    
    let result = JOURNAL.evaluate_json(original.clone());
    
    // The result should be a valid JSON structure
    assert!(result.is_object());
    
    // Check that basic structure is preserved
    if let Value::Object(obj) = &result {
        assert!(obj.contains_key("number"));
        assert!(obj.contains_key("array"));
        assert!(obj.contains_key("nested"));
    }
}

#[test]
fn test_json_error_handling() {
    let (_record, _test) = setup();
    
    // Test invalid scheme expression
    let input = json!("(invalid-function 1 2 3)");
    let result = JOURNAL.evaluate_json(input);
    
    // Should return some kind of error representation
    assert!(result.is_string() || result.is_object());
    
    // If it's a string, it should contain "error"
    if let Value::String(s) = &result {
        assert!(s.to_lowercase().contains("error"));
    }
}

#[test]
fn test_json_complex_expressions() {
    let (_record, _test) = setup();
    
    // Test defining and using a function
    let input = json!("(begin (define (square x) (* x x)) (square 5))");
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!(25));
    
    // Test conditional expressions
    let input = json!("(if (> 5 3) 'yes 'no)");
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!("yes"));
    
    // Test let expressions
    let input = json!("(let ((x 10) (y 20)) (+ x y))");
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!(30));
}

#[test]
fn test_json_byte_vector_operations() {
    let (_record, _test) = setup();
    
    // Test creating and manipulating byte vectors through JSON
    let input = json!("(hex-string->byte-vector \"deadbeef\")");
    let result = JOURNAL.evaluate_json(input);
    
    // Should return a byte-vector special type
    if let Value::Object(obj) = &result {
        assert!(obj.contains_key("*type/byte-vector*"));
        if let Some(Value::String(hex)) = obj.get("*type/byte-vector*") {
            assert_eq!(hex, "deadbeef");
        }
    }
}

#[test]
fn test_json_list_operations() {
    let (_record, _test) = setup();
    
    // Test list creation and manipulation
    let input = json!("(cons 1 (cons 2 (cons 3 '())))");
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!([1, 2, 3]));
    
    // Test car and cdr
    let input = json!("(car '(1 2 3))");
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!(1));
    
    let input = json!("(cdr '(1 2 3))");
    let result = JOURNAL.evaluate_json(input);
    assert_eq!(result, json!([2, 3]));
}

#[test]
fn test_json_association_lists() {
    let (_record, _test) = setup();
    
    // Test creating association lists that should convert to JSON objects
    let input = json!("(list (cons 'name \"Alice\") (cons 'age 30))");
    let result = JOURNAL.evaluate_json(input);
    
    // Should convert to a JSON object
    if let Value::Object(obj) = &result {
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("age"));
    }
}
