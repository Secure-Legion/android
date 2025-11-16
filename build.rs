fn main() {
    // Configure for Android builds
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "android" {
        println!("cargo:rustc-link-lib=dylib=c++_shared");
    }

    // Print build information
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
}
