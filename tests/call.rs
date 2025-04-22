use hex;
use mockito;
use rand::RngCore;
use journal_sdk::{JOURNAL, Word};

pub fn setup() -> (String, impl Fn(&str, &str)) {
    let mut seed: Word = [0 as u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let record = hex::encode(seed);

    assert!(
        JOURNAL.evaluate(format!(
            "(sync-create (hex-string->byte-vector \"{}\"))",
            record,
        ).as_str())== "#t",
        "Unable to set up new Journal",
    );

	(
        record.clone(),
	    move | expression, expected | {
	        let result = JOURNAL.evaluate(format!(
                "(sync-call '{} #t (hex-string->byte-vector \"{}\")))",
                expression,
                record,
            ).as_str());
	        assert!(
		        result == String::from(expected),
		        "Assertion failed: {} --> {} not {}",
		        expression, result, expected,
	        );
	    },
    )
}

#[test]
fn test_self() {
    let (_record, assert1) = setup();
    assert1("(sync-call '(+ 2 2) #t)", "4");
}

#[test]
fn test_record() {
    let (_record1, assert1) = setup();
    let (record2, _assert2) = setup();

    assert1(
	    format!("(sync-call '(+ 2 2) #t (hex-string->byte-vector \"{}\"))", record2).as_str(),
	    "4",
    );
    assert1(
	    format!("(sync-call ''(+ 2 2) #t (hex-string->byte-vector \"{}\"))", record2).as_str(),
	    "(+ 2 2)",
    );
    assert1(
	    format!(
	        "(sync-call '{} #t (hex-string->byte-vector \"{}\"))",
	        "(begin (define *sync-state* (sync-cons (sync-car *sync-state*) #u(2))) #t)",
	        record2,
	    ).as_str(),
	    "#t",
    );
}

#[test]
fn test_http() {
    let (_record, assert) = setup();

    let mut server = mockito::Server::new();
    let url = server.url();

    server.mock("GET", "/hello")
	    .with_status(200)
	    .with_header("content-type", "text/plain")
	    .with_body("hello, world!")
	    .create();

    server.mock("POST", "/hello")
	    .match_body(mockito::Matcher::Exact("world".to_string()))
	    .with_status(200)
	    .with_header("content-type", "text/plain")
	    .with_body("greeted")
	    .create();

    assert(
	    format!(
	        "(byte-vector->string (sync-http 'get \"{}/hello\"))",
	        url,
	    ).as_str(),
	    "\"hello, world!\"",
    );

    assert(
	    format!(
	        "(byte-vector->string (sync-http 'post \"{}/hello\" \"world\"))",
	        url,
	    ).as_str(),
	    "\"greeted\"",
    );
}
