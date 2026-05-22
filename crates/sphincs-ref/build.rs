//! Builds PQClean `sphincs-sha2-128s-simple` (clean) + `common/sha2.c`.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(pqclean_linked)");
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../..");
    let pqclean = repo_root.join("third_party/PQClean");
    let scheme_clean = pqclean.join("crypto_sign/sphincs-sha2-128s-simple/clean");
    let common = pqclean.join("common");

    if !scheme_clean.join("sign.c").exists() {
        println!(
            "cargo:warning=PQClean not found at {}; run scripts/vendor-pqclean.sh",
            pqclean.display()
        );
        return;
    }

    println!("cargo:rerun-if-changed={}", scheme_clean.display());
    println!("cargo:rerun-if-changed={}", common.join("sha2.c").display());

    let mut build = cc::Build::new();
    build
        .std("c11")
        .flag("-Wno-unused-parameter")
        .include(&scheme_clean)
        .include(&common);

    for name in [
        "address",
        "context_sha2",
        "fors",
        "hash_sha2",
        "merkle",
        "sign",
        "thash_sha2_simple",
        "utils",
        "utilsx1",
        "wots",
        "wotsx1",
    ] {
        build.file(scheme_clean.join(format!("{name}.c")));
    }
    build.file(common.join("sha2.c"));
    build.compile("pqclean_sphincs_sha2_128s_simple");

    println!("cargo:rustc-cfg=pqclean_linked");
}
