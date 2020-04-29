// build.rs

use std::path::Path;
use std::process::Command;

fn main() {
    let dir = "./target/libwally-core";
    let dir_path = Path::new(dir);
    if !dir_path.exists() {
        let status = Command::new("git")
            .arg("clone")
            .arg("https://github.com/ElementsProject/libwally-core")
            .arg(dir)
            .status()
            .unwrap();
        assert!(status.success());

        let status = Command::new("./tools/autogen.sh").current_dir(dir).status().unwrap();
        assert!(status.success());
    }

    let dst = autotools::Config::new("libwally-core")
        .enable("elements", None)
        .enable("debug", None)
        .enable_static()
        .disable_shared()
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=wallycore");
    println!("cargo:rustc-link-lib=static=secp256k1");
}
