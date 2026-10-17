use std::path::PathBuf;

fn main() {
    let vendor = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vendor");
    let secp = vendor.join("secp256k1");
    let wabi = vendor.join("libwabisabi");

    // libwabisabi first: its objects reference secp256k1 symbols and the linker
    // consumes static archives in the order they are given.
    let mut w = cc::Build::new();
    for f in [
        "sha256", "strobe", "field", "wabisabi_types", "generators", "mac", "transcript", "proof",
        "credential", "issuer", "client", "ownership_proof", "ownership_ffi", "ffi",
    ] {
        w.file(wabi.join("src").join(format!("{f}.c")));
    }
    w.include(wabi.join("include"))
        .include(wabi.join("src"))
        .include(secp.join("include"))
        .flag_if_supported("-std=c11")
        .warnings(false)
        .compile("wabisabi");

    // Same configuration as secp256k1's CMake defaults (table sizes only affect speed).
    cc::Build::new()
        .file(secp.join("src/secp256k1.c"))
        .file(secp.join("src/precomputed_ecmult.c"))
        .file(secp.join("src/precomputed_ecmult_gen.c"))
        .include(secp.join("include"))
        .include(secp.join("src"))
        .define("ECMULT_WINDOW_SIZE", "15")
        .define("ECMULT_GEN_KB", "86")
        .define("ENABLE_MODULE_EXTRAKEYS", "1")
        .define("ENABLE_MODULE_SCHNORRSIG", "1")
        .warnings(false)
        .compile("secp256k1");

    println!("cargo:rerun-if-changed={}", vendor.display());
}
