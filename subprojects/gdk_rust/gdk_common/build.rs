// build.rs

use std::env;

fn main() {
    if let Ok(wally_dir) = env::var("WALLY_DIR") {
        println!("cargo:rustc-link-lib=static=wallycore");
        println!("cargo:rustc-link-lib=static=secp256k1");
        println!("cargo:rustc-link-search=native={}", wally_dir);
    }
}
