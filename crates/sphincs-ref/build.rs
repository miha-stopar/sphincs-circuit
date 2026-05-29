//! Builds PQClean `sphincs-sha2-128s-simple` (clean) + instrumented `common/sha2.c`.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(pqclean_linked)");
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../..");
    let pqclean = repo_root.join("third_party/PQClean");
    let scheme_clean = pqclean.join("crypto_sign/sphincs-sha2-128s-simple/clean");
    let common = pqclean.join("common");
    let trace_include = manifest_dir.join("c/include");

    if !scheme_clean.join("sign.c").exists() {
        println!(
            "cargo:warning=PQClean not found at {}; run scripts/vendor-pqclean.sh",
            pqclean.display()
        );
        return;
    }

    println!("cargo:rerun-if-changed={}", scheme_clean.display());
    println!("cargo:rerun-if-changed={}", common.join("sha2.c").display());
    println!("cargo:rerun-if-changed={}", manifest_dir.join("c/spx_sha256_trace.c").display());
    println!("cargo:rerun-if-changed={}", manifest_dir.join("c/spx_thash_oracle.c").display());
    println!("cargo:rerun-if-changed={}", manifest_dir.join("c/spx_compute_root_oracle.c").display());

    let mut build = cc::Build::new();
    build
        .std("c11")
        .flag("-Wno-unused-parameter")
        .define("SPX_SHA256_TRACE", None)
        .include(&scheme_clean)
        .include(&common)
        .include(&trace_include);

    build.file(manifest_dir.join("c/spx_sha256_trace.c"));
    build.file(manifest_dir.join("c/spx_thash_oracle.c"));
    build.file(manifest_dir.join("c/spx_compute_root_oracle.c"));

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
    // Deterministic stub instead of OS RNG (this crate is for circuits / tests).
    build.file(manifest_dir.join("c/randombytes_stub.c"));
    build.compile("pqclean_sphincs_sha2_128s_simple");

    println!("cargo:rustc-cfg=pqclean_linked");
}
