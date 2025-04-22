#![allow(warnings, unused)]

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-search=/path/to/lib");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    cc::Build::new()
	.file("external/s7/s7.c")
	.flag(format!("-DDEFAULT_PRINT_LENGTH={}", isize::MAX).as_str())
	.flag("-DWITH_PURE_S7=1")
	.flag("-DWITH_SYSTEM_EXTRAS=0")
	.flag("-DWITH_C_LOADER=0")
	.warnings(false)
	.compile("evaluator");
    let bindings = bindgen::Builder::default()
	.header("wrapper.h")
	.parse_callbacks(Box::new(bindgen::CargoCallbacks))
	.generate()
	.expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
	.write_to_file(out_path.join("bindings.rs"))
	.expect("Couldn't write bindings!");
}
