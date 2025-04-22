Welcome to the Synchronic Web Journal Software Development Kit!
This repository contains technical documentation and code that operates the core of the synchronic web infrastructure.
For an older higher-level overview, please see public [whitepaper](https://arxiv.org/ftp/arxiv/papers/2301/2301.10733.pdf).

# Install

Please see the following two pages to install the build dependencies:

* [Instructions](https://doc.rust-lang.org/cargo/getting-started/installation.html) to install Rust and Cargo
* [Instructions](https://rust-lang.github.io/rust-bindgen/requirements.html) to install CLang for generating C/Rust bindings

Currently, this code has only been confirmed to work on Linux, specifically, Windows Subsystem for Linux.
However, there is no current reason to believe it won't compile elsewhere.

# Run

The recommended usage strategy for most users is the web server.
Although the code can be run in any way that Rust/Cargo allows, there are useful ways for most developers:

* As a low-optimization single step for development:
  * `$ cargo run`
* As a high-optimization two-step procedure for release:
  * `$ cargo build --release`
  * `$ ./target/release/journal-sdk`
  
By default, the journal will run with an in-memory database only.
To persist to disk, pass in the `--database <database name>` argument.

If successful, there will be a Journal server running at the configured URL (default: http://localhost:4096)
To interact with the Journal through the web browser:

1. Navigate to `http://localhost:4096`
2. Click on `Interface`
3. Type in `(+ 2 2)` into the input box and press `evaluate`

If the interface correctly outputs the value `4`, then the Journal is functional.

## Commandline

In addition to using the rudimentary browser interface, the HTTP endpoint can also be invoked using any standard commandline client, for instance:

`$ curl -X POST http://localhost:4096/interface -d "(+ 2 2)"`

## Other Actions

Here are other auxiliary actions that may be useful in the course of development:

* Enumerate and display configuration options
  * `$ cargo run -- --help`
* Run all unit and doc comment tests:
  * `$ cargo test`
* Generate Rust documentation
  * `$ cargo doc --no-deps --open`
  
# Use

The `interface` endpoint exposes an evaluator for executing arbitrary code in a Lisp dialect.
Once the service deploys, all interaction with the Journal SDK should take place through this interface.
The evaluator itself is stateless; all variables and computations are cleared between each invocation of the endpoint.
However, the SDK provides a controlled ability to read and write persistent data to the backend database.
By leveraging the functionality and workflow specified below, it is possible to create arbitrarily complex stateful interfaces that benefit from the same core cryptographic verifiability afforded by the Journal.

## Lisp Evaluation

The Lisp dialect used for Synchronic Web code is a lightly modified version of s7 Scheme.
All source code and documentation is available in the [./external/s7](./external/s7) folder.
Other basic modifcations include:

- Build flags found in [./build.rs](./build.rs)
- Blacklisted functions found in [./evaluator.rs](./evaluator.rs)
- Additional convenience functions found in [./evaluator.rs](./evaluator.rs)

The following commands will be helpful in getting started:

- List all functions in the root environment: `(map car (rootlet))`
- Display the docstring for a given function: `(help my-function-name)`

## Synchronic Web State

Synchronic Web Journals store all stateful information, which we call records, in the form of cryptographic binary trees.
The SDK implements a set of functions in the [./lib.rs](./lib.rs) file for working with records.
These custom functions (and descriptions) are available in the root environment of the evaluator and are identifiable by their `sync-` prefix.
Functionality includes:

- Management of records (binary hash trees)
- Usage of Lisp-inspired constructs (cons, car, cdr, etc.) to build and traverse binary hash trees
- Invocation of other records and generic endpoints

There is only one structural constraint on the form of the record: for a record to be correctly handled by the SDK, the top-most left child must be a unicode bytes string encoding an s7 expression of the following form:

`(lambda (*sync-state* query) (cons ... *sync-state*))`

The `*sync-state*` parameter is the root node of the record while the `query` parameter is the expression provided through the `/interface` endpoint.
The function returns a Lisp pair where the first item is the response to the `/inferface` call and the second item is the new root node.
For example, the default function is the following:

`(lambda (*sync-state* query) (cons (eval query) *sync-state*))`

This function simply evaluates any user query.
From this highly generic and permissive functionality, it is possible to construct arbitrarily specific and controlled interfaces.
The [./lisp](./lisp) folder provides some examples.
  
# Disclaimer

In general, this software still undergoing development.
Functionality and interfaces may change at any time.
