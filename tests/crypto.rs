use hex;
use journal_sdk::{Word, JOURNAL};
use rand::RngCore;

pub fn setup() -> (String, impl Fn(&str, &str)) {
    let mut seed: Word = [0 as u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let record = hex::encode(seed);

    assert!(
        JOURNAL
            .evaluate(format!("(sync-create (hex-string->byte-vector \"{}\"))", record,).as_str())
            == "#t",
        "Unable to set up new Journal",
    );

    (record.clone(), move |expression, expected| {
        let result = JOURNAL.evaluate(
            format!(
                "(sync-call '{} #t (hex-string->byte-vector \"{}\"))",
                expression, record,
            )
            .as_str(),
        );
        assert!(
            result == String::from(expected),
            "Assertion failed: {} --> {} not {}",
            expression,
            result,
            expected,
        );
    })
}

#[test]
fn test_success() {
    let (_record, assert1) = setup();
    assert1(
        "(let ((keys (crypto-generate #u(0)))) (crypto-verify (car keys) (crypto-sign (cdr keys) #u(1)) #u(1)))",
        "#t",
    );
}

#[test]
fn test_failure() {
    let (_record, assert1) = setup();
    assert1(
        "(let ((keys (crypto-generate #u(0)))) (crypto-verify (car keys) (crypto-sign (cdr keys) #u(1)) #u(2)))",
        "#f",
    );
    assert1(
        "(let ((keys (crypto-generate #u(0)))) (crypto-verify (car (crypto-generate #u(1))) (crypto-sign (cdr keys) #u(1)) #u(1)))",
        "#f",
    );
    assert1(
        "(let ((keys (crypto-generate #u(0)))) (crypto-verify (cdr (crypto-generate #u(1))) (crypto-sign (car keys) #u(1)) #u(1)))",
        "(error 'crypto-error \"cryptographic library encountered unexpected error\")",
    );
}
