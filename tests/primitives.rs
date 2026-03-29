use hex;
use journal_sdk::{JOURNAL, SIZE, Word};
use rand::RngCore;

fn fresh_record_hex() -> String {
    let mut seed: Word = [0; SIZE];
    rand::thread_rng().fill_bytes(&mut seed);
    hex::encode(seed)
}

fn setup_record() -> (String, impl Fn(&str, &str)) {
    let record = fresh_record_hex();

    assert_eq!(
        JOURNAL.evaluate(
            format!("(sync-create (hex-string->byte-vector \"{}\"))", record).as_str(),
        ),
        "#t",
        "Unable to set up new Journal record",
    );

    (record.clone(), move |expression, expected| {
        let result = JOURNAL.evaluate(
            format!(
                "(sync-call '{} #t (hex-string->byte-vector \"{}\"))",
                expression, record,
            )
            .as_str(),
        );
        assert_eq!(result, expected, "Assertion failed: {}", expression);
    })
}

#[test]
fn test_sync_hash_and_digest_on_byte_vectors() {
    assert_eq!(
        JOURNAL.evaluate("(equal? (sync-digest #u(1 2 3)) (sync-hash #u(1 2 3)))"),
        "#t",
    );
}

#[test]
fn test_sync_predicates_on_byte_vectors() {
    assert_eq!(JOURNAL.evaluate("(sync-node? #u(1 2 3))"), "#f");
    assert_eq!(JOURNAL.evaluate("(sync-null? #u(1 2 3))"), "#f");
    assert_eq!(JOURNAL.evaluate("(sync-pair? #u(1 2 3))"), "#f");
    assert_eq!(JOURNAL.evaluate("(sync-stub? #u(1 2 3))"), "#f");
}

#[test]
fn test_sync_node_structure_primitives() {
    assert_eq!(JOURNAL.evaluate("(sync-null? (sync-null))"), "#t");
    assert_eq!(JOURNAL.evaluate("(sync-pair? (sync-cons (sync-null) (sync-null)))"), "#t");
    assert_eq!(
        JOURNAL.evaluate("(sync-null? (sync-car (sync-cons (sync-null) #u(1 2 3))))"),
        "#t",
    );
    assert_eq!(
        JOURNAL.evaluate("(equal? (sync-cdr (sync-cons (sync-null) #u(1 2 3))) #u(1 2 3))"),
        "#t",
    );
    assert_eq!(
        JOURNAL.evaluate("(sync-stub? (sync-cut (sync-cons (sync-null) #u(1 2 3))))"),
        "#t",
    );
    assert_eq!(
        JOURNAL.evaluate("(sync-stub? (sync-stub (sync-hash #u(1 2 3))))"),
        "#t",
    );
}

#[test]
fn test_sync_state_and_sync_eval() {
    let (_record, assert) = setup_record();
    assert("(sync-node? (sync-state))", "#t");
    assert(
        "(let* ((code '(lambda (state) (define* (self (arg #f)) (if arg arg state))))\
                (node (sync-cons (expression->byte-vector code) (sync-null))))\
           ((sync-eval node #f) 'hello))",
        "hello",
    );
    assert(
        "(let* ((code '(lambda (node) #u(7 8 9)))\
                (node (sync-cons (expression->byte-vector code) (sync-null))))\
           (equal? (sync-eval node #t) #u(7 8 9)))",
        "#t",
    );
}

#[test]
fn test_sync_create_all_and_delete() {
    let record = fresh_record_hex();

    assert_eq!(
        JOURNAL.evaluate(
            format!("(sync-create (hex-string->byte-vector \"{}\"))", record).as_str(),
        ),
        "#t",
    );

    assert_eq!(
        JOURNAL.evaluate(
            format!(
                "(not (not (member (hex-string->byte-vector \"{}\") (sync-all))))",
                record
            )
            .as_str(),
        ),
        "#t",
    );

    assert_eq!(
        JOURNAL.evaluate(
            format!("(sync-delete (hex-string->byte-vector \"{}\"))", record).as_str(),
        ),
        "#t",
    );

    assert_eq!(
        JOURNAL.evaluate(
            format!(
                "(not (not (member (hex-string->byte-vector \"{}\") (sync-all))))",
                record
            )
            .as_str(),
        ),
        "#f",
    );
}

#[test]
fn test_sync_call() {
    let (_record, assert) = setup_record();
    assert("(sync-call '(+ 2 2) #t)", "4");
}
