use journal_sdk::evaluator::{json2scheme, scheme2json};
use serde_json::{json, Value};

#[test]
fn test_json_to_scheme_basic_types() {
    // Test null
    let scheme = json2scheme(json!(null)).unwrap();
    assert_eq!(scheme, "()");

    // Test boolean
    let scheme = json2scheme(json!(true)).unwrap();
    assert_eq!(scheme, "#t");

    let scheme = json2scheme(json!(false)).unwrap();
    assert_eq!(scheme, "#f");

    // Test numbers
    let scheme = json2scheme(json!(42)).unwrap();
    assert_eq!(scheme, "42");

    let scheme = json2scheme(json!(3.14)).unwrap();
    assert_eq!(scheme, "3.14");

    // Test strings (should become symbols)
    let scheme = json2scheme(json!("hello")).unwrap();
    assert_eq!(scheme, "hello");
}

#[test]
fn test_json_to_scheme_arrays() {
    // Test empty array
    let scheme = json2scheme(json!([])).unwrap();
    assert_eq!(scheme, "()");

    // Test array with mixed types
    let scheme = json2scheme(json!([1, "hello", true, null])).unwrap();
    assert_eq!(scheme, "(1 hello #t ())");

    // Test nested arrays
    let scheme = json2scheme(json!([[1, 2], [3, 4]])).unwrap();
    assert_eq!(scheme, "((1 2) (3 4))");
}

#[test]
fn test_json_to_scheme_objects() {
    // Test empty object
    let scheme = json2scheme(json!({})).unwrap();
    assert_eq!(scheme, "()");

    // Test simple object - should convert to association list
    let scheme = json2scheme(json!({"name": "Alice", "age": 30})).unwrap();
    // The exact order may vary, but should contain both key-value pairs
    assert!(scheme.contains("name"));
    assert!(scheme.contains("Alice"));
    assert!(scheme.contains("age"));
    assert!(scheme.contains("30"));
}

#[test]
fn test_json_to_scheme_special_types() {
    // Test byte-vector special type
    let scheme = json2scheme(json!({"*type/byte-vector*": "deadbeef"})).unwrap();
    assert!(scheme.contains("#u(222 173 190 239)"));

    // Test vector special type
    let scheme = json2scheme(json!({"*type/vector*": [1, 2, 3]})).unwrap();
    // Should convert to a vector creation expression
    assert!(scheme.contains("1"));
    assert!(scheme.contains("2"));
    assert!(scheme.contains("3"));

    // Test string special type
    let scheme = json2scheme(json!({"*type/string*": "test string"})).unwrap();
    assert!(scheme.contains("test string"));
}

#[test]
fn test_scheme_to_json_basic_types() {
    // Test null
    let json_val = scheme2json("()").unwrap();
    assert_eq!(json_val, json!(null));

    // Test boolean
    let json_val = scheme2json("#t").unwrap();
    assert_eq!(json_val, json!(true));

    let json_val = scheme2json("#f").unwrap();
    assert_eq!(json_val, json!(false));

    // Test numbers
    let json_val = scheme2json("42").unwrap();
    assert_eq!(json_val, json!(42));

    let json_val = scheme2json("3.14").unwrap();
    assert_eq!(json_val, json!(3.14));

    // Test symbols (should become strings)
    let json_val = scheme2json("hello").unwrap();
    assert_eq!(json_val, json!("hello"));
}

#[test]
fn test_scheme_to_json_lists() {
    // Test empty list
    let json_val = scheme2json("()").unwrap();
    assert_eq!(json_val, json!(null));

    // Test simple quoted list
    let json_val = scheme2json("(1 2 3)").unwrap();
    assert_eq!(json_val, json!([1, 2, 3]));

    // Test nested quoted lists
    let json_val = scheme2json("((1 2) (3 4))").unwrap();
    assert_eq!(json_val, json!([[1, 2], [3, 4]]));
}

#[test]
fn test_round_trip_conversion() {
    // Test that JSON -> Scheme -> JSON preserves basic types
    let original = json!(42);
    let scheme = json2scheme(original.clone()).unwrap();
    let back_to_json = scheme2json(&scheme).unwrap();
    assert_eq!(original, back_to_json);

    // Test boolean round trip
    let original = json!(true);
    let scheme = json2scheme(original.clone()).unwrap();
    let back_to_json = scheme2json(&scheme).unwrap();
    assert_eq!(original, back_to_json);

    // Test string round trip (JSON string -> symbol -> JSON string)
    let original = json!("hello");
    let scheme = json2scheme(original.clone()).unwrap();
    let back_to_json = scheme2json(&scheme).unwrap();
    assert_eq!(original, back_to_json);

    // Test null round trip
    let original = json!(null);
    let scheme = json2scheme(original.clone()).unwrap();
    let back_to_json = scheme2json(&scheme).unwrap();
    assert_eq!(original, back_to_json);
}

#[test]
fn test_scheme_strings_and_special_types() {
    // Test string conversion (should use special type marker)
    let json_val = scheme2json("\"hello world\"").unwrap();
    assert_eq!(json_val, json!({"*type/string*": "hello world"}));

    // Test byte vector conversion
    let json_val = scheme2json("#u8(222 173 190 239)").unwrap();
    if let Value::Object(obj) = &json_val {
        assert!(obj.contains_key("*type/byte-vector*"));
    }
}

#[test]
fn test_array_conversion() {
    // Test simple array
    let original = json!([1, 2, 3]);
    let scheme = json2scheme(original.clone()).unwrap();
    assert!(scheme.contains("1"));
    assert!(scheme.contains("2"));
    assert!(scheme.contains("3"));

    // Test mixed type array
    let original = json!([1, "hello", true]);
    let scheme = json2scheme(original).unwrap();
    assert!(scheme.contains("1"));
    assert!(scheme.contains("hello"));
    assert!(scheme.contains("#t"));
}

#[test]
fn test_special_type_round_trip() {
    // Test byte-vector special type round trip
    let original = json!({"*type/byte-vector*": "deadbeef"});
    let scheme = json2scheme(original.clone()).unwrap();
    let back_to_json = scheme2json(&scheme).unwrap();
    assert_eq!(original, back_to_json);

    // Test vector special type round trip
    let original = json!({"*type/vector*": [1, 2, 3]});
    let scheme = json2scheme(original.clone()).unwrap();
    let back_to_json = scheme2json(&scheme).unwrap();
    assert_eq!(original, back_to_json);

    // Test string special type round trip
    let original = json!({"*type/string*": "test string"});
    let scheme = json2scheme(original.clone()).unwrap();
    let back_to_json = scheme2json(&scheme).unwrap();
    assert_eq!(original, back_to_json);
}

#[test]
fn test_association_list_conversion() {
    // Test that proper association lists (with list format) convert to JSON objects
    let json_val = scheme2json("((name \"Alice\") (age 30))").unwrap();

    if let Value::Object(obj) = &json_val {
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("age"));
        assert_eq!(obj.get("name").unwrap(), &json!("Alice"));
        assert_eq!(obj.get("age").unwrap(), &json!(30));
    } else {
        panic!("Expected JSON object for proper association list");
    }
}

#[test]
fn test_pair_type_conversion() {
    // Test that pairs (with dot notation) convert to special type format
    let json_val = scheme2json("(name . \"Alice\")").unwrap();
    
    if let Value::Object(obj) = &json_val {
        assert!(obj.contains_key("*type/pair*"));
        if let Some(Value::Array(arr)) = obj.get("*type/pair*") {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], json!("name"));
            assert_eq!(arr[1], json!({"*type/string*": "Alice"}));
        } else {
            panic!("Expected array for *type/pair* value");
        }
    } else {
        panic!("Expected JSON object for pair type");
    }

    // Test simple pair with symbols
    let json_val = scheme2json("(a . b)").unwrap();
    
    if let Value::Object(obj) = &json_val {
        assert!(obj.contains_key("*type/pair*"));
        if let Some(Value::Array(arr)) = obj.get("*type/pair*") {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], json!("a"));
            assert_eq!(arr[1], json!("b"));
        }
    }
}

#[test]
fn test_pair_type_round_trip() {
    // Test that pair special type converts back to scheme pair
    let original = json!({"*type/pair*": ["key", "value"]});
    let scheme = json2scheme(original.clone()).unwrap();
    let back_to_json = scheme2json(&scheme).unwrap();
    assert_eq!(original, back_to_json);

    // Test with mixed types
    let original = json!({"*type/pair*": [42, true]});
    let scheme = json2scheme(original.clone()).unwrap();
    let back_to_json = scheme2json(&scheme).unwrap();
    assert_eq!(original, back_to_json);
}

#[test]
fn test_mixed_association_structures() {
    // Test that lists of pairs are treated as arrays of pair objects
    let json_val = scheme2json("((a . 1) (b . 2))").unwrap();
    
    if let Value::Array(arr) = &json_val {
        assert_eq!(arr.len(), 2);
        
        // Each element should be a pair object
        for item in arr {
            if let Value::Object(obj) = item {
                assert!(obj.contains_key("*type/pair*"));
            } else {
                panic!("Expected pair objects in array");
            }
        }
    } else {
        panic!("Expected array for list of pairs");
    }
}

#[test]
fn test_quote_handling() {
    // Test that quoted expressions are parsed as quote forms, not evaluated
    let json_val = scheme2json("'(a b c)").unwrap();
    
    // Should be an array with "quote" as first element and the list as second
    assert_eq!(json_val, json!(["quote", ["a", "b", "c"]]));

    // Test simple quoted symbol
    let json_val = scheme2json("'hello").unwrap();
    assert_eq!(json_val, json!(["quote", "hello"]));

    // Test quoted number
    let json_val = scheme2json("'42").unwrap();
    assert_eq!(json_val, json!(["quote", 42]));
}
