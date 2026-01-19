use journal_sdk::evaluator::{json2scheme, scheme2json};
use serde_json::{json, Value};

#[test]
fn test_json_to_scheme_basic_types() {
    // Test null
    let scheme = json2scheme(json!(null));
    assert_eq!(scheme, "()");

    // Test boolean
    let scheme = json2scheme(json!(true));
    assert_eq!(scheme, "#t");

    let scheme = json2scheme(json!(false));
    assert_eq!(scheme, "#f");

    // Test numbers
    let scheme = json2scheme(json!(42));
    assert_eq!(scheme, "42");

    let scheme = json2scheme(json!(3.14));
    assert_eq!(scheme, "3.14");

    // Test strings
    let scheme = json2scheme(json!("hello world"));
    assert_eq!(scheme, "\"hello world\"");
}

#[test]
fn test_json_to_scheme_arrays() {
    // Test empty array
    let scheme = json2scheme(json!([]));
    assert_eq!(scheme, "()");

    // Test array with mixed types
    let scheme = json2scheme(json!([1, "hello", true, null]));
    assert_eq!(scheme, "(list 1 \"hello\" #t ())");

    // Test nested arrays
    let scheme = json2scheme(json!([[1, 2], [3, 4]]));
    assert_eq!(scheme, "(list (list 1 2) (list 3 4))");
}

#[test]
fn test_json_to_scheme_objects() {
    // Test empty object
    let scheme = json2scheme(json!({}));
    assert_eq!(scheme, "()");

    // Test simple object - should convert to association list
    let scheme = json2scheme(json!({"name": "Alice", "age": 30}));
    // The exact order may vary, but should contain both key-value pairs
    assert!(scheme.contains("name"));
    assert!(scheme.contains("Alice"));
    assert!(scheme.contains("age"));
    assert!(scheme.contains("30"));
}

#[test]
fn test_json_to_scheme_special_types() {
    // Test byte-vector special type
    let scheme = json2scheme(json!({"*type/byte-vector*": "deadbeef"}));
    // Should convert to a byte vector creation expression
    assert!(scheme.contains("deadbeef"));

    // Test vector special type
    let scheme = json2scheme(json!({"*type/vector*": [1, 2, 3]}));
    // Should convert to a vector creation expression
    assert!(scheme.contains("1"));
    assert!(scheme.contains("2"));
    assert!(scheme.contains("3"));

    // Test string special type
    let scheme = json2scheme(json!({"*type/string*": "test string"}));
    assert!(scheme.contains("test string"));
}

#[test]
fn test_scheme_to_json_basic_types() {
    // Test null
    let json_val = scheme2json("()");
    assert_eq!(json_val, json!(null));

    // Test boolean
    let json_val = scheme2json("#t");
    assert_eq!(json_val, json!(true));

    let json_val = scheme2json("#f");
    assert_eq!(json_val, json!(false));

    // Test numbers
    let json_val = scheme2json("42");
    assert_eq!(json_val, json!(42));

    let json_val = scheme2json("3.14");
    assert_eq!(json_val, json!(3.14));

    // Test symbols (should become strings)
    let json_val = scheme2json("hello");
    assert_eq!(json_val, json!("hello"));
}

#[test]
fn test_scheme_to_json_lists() {
    // Test empty list
    let json_val = scheme2json("()");
    assert_eq!(json_val, json!(null));

    // Test simple list
    let json_val = scheme2json("(1 2 3)");
    assert_eq!(json_val, json!([1, 2, 3]));

    // Test nested lists
    let json_val = scheme2json("((1 2) (3 4))");
    assert_eq!(json_val, json!([[1, 2], [3, 4]]));
}

#[test]
fn test_round_trip_conversion() {
    // Test that JSON -> Scheme -> JSON preserves basic types
    let original = json!(42);
    let scheme = json2scheme(original.clone());
    let back_to_json = scheme2json(&scheme);
    assert_eq!(original, back_to_json);

    // Test boolean round trip
    let original = json!(true);
    let scheme = json2scheme(original.clone());
    let back_to_json = scheme2json(&scheme);
    assert_eq!(original, back_to_json);

    // Test string round trip
    let original = json!("hello");
    let scheme = json2scheme(original.clone());
    let back_to_json = scheme2json(&scheme);
    assert_eq!(original, back_to_json);

    // Test null round trip
    let original = json!(null);
    let scheme = json2scheme(original.clone());
    let back_to_json = scheme2json(&scheme);
    assert_eq!(original, back_to_json);
}

#[test]
fn test_scheme_strings_and_special_types() {
    // Test string conversion (should use special type marker)
    let json_val = scheme2json("\"hello world\"");
    assert_eq!(json_val, json!({"*type/string*": "hello world"}));

    // Test byte vector conversion
    let json_val = scheme2json("#u8(222 173 190 239)");
    if let Value::Object(obj) = &json_val {
        assert!(obj.contains_key("*type/byte-vector*"));
    }
}

#[test]
fn test_array_conversion() {
    // Test simple array
    let original = json!([1, 2, 3]);
    let scheme = json2scheme(original.clone());
    assert!(scheme.contains("list"));
    assert!(scheme.contains("1"));
    assert!(scheme.contains("2"));
    assert!(scheme.contains("3"));

    // Test mixed type array
    let original = json!([1, "hello", true]);
    let scheme = json2scheme(original);
    assert!(scheme.contains("list"));
    assert!(scheme.contains("1"));
    assert!(scheme.contains("hello"));
    assert!(scheme.contains("#t"));
}

#[test]
fn test_special_type_round_trip() {
    // Test byte-vector special type round trip
    let original = json!({"*type/byte-vector*": "deadbeef"});
    let scheme = json2scheme(original.clone());
    let back_to_json = scheme2json(&scheme);
    assert_eq!(original, back_to_json);

    // Test vector special type round trip
    let original = json!({"*type/vector*": [1, 2, 3]});
    let scheme = json2scheme(original.clone());
    let back_to_json = scheme2json(&scheme);
    assert_eq!(original, back_to_json);

    // Test string special type round trip
    let original = json!({"*type/string*": "test string"});
    let scheme = json2scheme(original.clone());
    let back_to_json = scheme2json(&scheme);
    assert_eq!(original, back_to_json);
}

#[test]
fn test_association_list_conversion() {
    // Test that association lists convert to JSON objects
    let json_val = scheme2json("((name . \"Alice\") (age . 30))");

    if let Value::Object(obj) = &json_val {
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("age"));
    } else {
        // If not an object, should at least be a valid JSON structure
        assert!(json_val.is_array() || json_val.is_object());
    }
}
