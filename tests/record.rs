use std::fs;
use rand::RngCore;
use journal_sdk::{JOURNAL, Word, SIZE};

pub fn setup() -> impl Fn(&str, &str) {
    let mut seed: Word = [0 as u8; SIZE];
    rand::thread_rng().fill_bytes(&mut seed);
    let record = hex::encode(seed);

    assert!(
        JOURNAL.evaluate(format!(
            "(sync-create (hex-string->byte-vector \"{}\"))",
            record,
        ).as_str())== "#t",
        "Unable to set up new Journal",
    );

    move | expression, expected | {
	    let result = JOURNAL.evaluate(format!(
            "(sync-call '{} #t (hex-string->byte-vector \"{}\"))",
            expression,
            record,
        ).as_str());

	    assert!(
	        result == String::from(expected),
	        "Assertion failed: {} --> {} not {}",
	        expression, result, expected,
	    );
    }
}

#[test]
fn test_standard() {
    let assert = setup();
    assert("4", "4");
    assert("(+ 2 2)", "4");
    assert("(/ 1 0)", "(error 'division-by-zero \"/: division by zero, (/ 1 0)\")");
    assert("\"x", "(error 'string-read-error \"end of input encountered while in a string\")");
}

#[test]
fn test_scratch() {
    let assert = setup();
    let code = fs::read_to_string("lisp/scratch.scm").unwrap();
    assert(&code, "\"Installed scratch interface\"");
    assert("(read)", "\"\"");
    assert("(write \"hello, world!\")", "success");
    assert("(read)", "\"hello, world!\"");
    assert("(write \"goodbye\")", "success");
    assert("(read)", "\"goodbye\"");
}

#[test]
fn test_blockchain() {
    let assert = setup();
    let code = format!(
        "({} \"test-password\")",
        fs::read_to_string("lisp/blockchain.scm").unwrap(),
    );
    assert(&code, "\"Installed blockchain interface\"");
    assert("(size)", "1");
    assert("(write)", "success");
    assert("(write (a 1) (b 2))", "success");
    assert("(size)", "3");
    assert("(read 2 a)", "1");
    assert("(uninstall \"test-password\")", "\"Uninstalled blockchain interface\"");
    assert("(+ 2 2)", "4");
}

#[test]
fn test_evaluator() {
    let assert = setup();
    let code = fs::read_to_string("lisp/evaluator.scm").unwrap();
    assert(&code, "\"Installed metacircular interface\"");
    assert("4", "4");
    assert("(+ 2 2)", "4");
    assert("(define a 8)", "8");
    assert("a", "8");
    assert("(if #f 0 1)", "1");
    assert("'(1 2 3 4)", "(1 2 3 4)");
    assert("(eval '(+ 2 2))", "4");
    assert("(apply + '(1 2 3 4))", "10");
    assert("(undefine a)", "()");
    assert("(byte-vector->hex-string #u(0 255))", "\"00ff\"");
    assert("(hex-string->byte-vector \"00ff\")", "#u(0 255)");
    assert("(expression->byte-vector '(+ 2 2))", "#u(40 43 32 50 32 50 41)");
    assert("(byte-vector->expression #u(40 43 32 50 32 50 41))", "(+ 2 2)");
}

#[test]
fn test_utilities() {
    let assert = setup();
    let code = fs::read_to_string("lisp/evaluator.scm").unwrap();
    assert(&code, "\"Installed metacircular interface\"");
    let code = fs::read_to_string("lisp/utils.scm").unwrap();
    assert(&code, "\"Installed metacircular utilities\"");
    assert("(filter positive? '(1 -1 0))", "(1)");
    assert("(reduce (lambda (x y) (+ x y)) 0 '(1 2 3 4))", "10");
}

#[test]
fn test_rdf() {
    let assert = setup();
    let code = fs::read_to_string("lisp/rdf.scm").unwrap();
    assert(&code, "\"Installed RDF interface\"");
    assert("(insert a b c)", "(a b c)");
    assert("(insert a b d)", "(a b d)");
    assert("(select a b ())", "((a b c) (a b d))");
    assert("(remove a b c)", "(a b c)");
    assert("(select a b ())", "((a b d))");
}

#[test]
fn test_state() {
    let assert = setup();
    let code = fs::read_to_string("lisp/state.scm").unwrap();
    assert(&code, "\"Installed state machine interface\"");
    assert("(define x 2)", "2");
    assert("x", "2");
    assert("(define x 4)", "4");
    assert("x", "4");
    assert("(state-index)", "3");
    assert("((state-get 1) 'x)", "2");

    assert("(define x '(1 2 3 4))", "(1 2 3 4)");
    assert("x", "(1 2 3 4)");
    assert("(define x (hash-table 'a 1))", "(hash-table 'a 1)");
    assert("x", "(hash-table 'a 1)");
    assert("(define x #2d((1 2) (3 4)))", "#2d((1 2) (3 4))");
    assert("x", "#2d((1 2) (3 4))");
    assert("(define (add2 x) (+ x 2))", "add2");
    assert("(add2 2)", "4");
    assert("(define-macro (swap x y) `(list ,y ,x))", "swap");
    assert("(swap 1 2)", "(2 1)");
    assert("(define x (inlet 'a 1 'b 2))", "(inlet 'a 1 'b 2)");
    assert("x", "(inlet 'a 1 'b 2)");

    assert("(begin (define add2 (state-dump (lambda (x) (+ x 2)))) #t)", "#t");
    assert("((state-load add2) 2)", "4");
}
