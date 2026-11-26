//! Compiles the C engine (design doc §13.1: the engine is C17 + aarch64 assembly).

fn main() {
    let sources = [
        "src/c/atomic.c",
        "src/c/cpu.c",
        "src/c/dbt.c",
        "src/c/dbt_cache.c",
        "src/c/dbt_group.c",
        "src/c/dbt_loop.c",
        "src/c/dbt_routines.c",
        "src/c/dbt_translate.c",
        "src/c/features.c",
        "src/c/guard.c",
        "src/c/interp.c",
        "src/c/mmu.c",
        "src/c/native.c",
        "src/c/simd.c",
    ];
    for path in sources.iter().chain(&[
        "src/c/dbt_internal.h",
        "src/c/emit.h",
        "src/c/internal.h",
        "include/appine/engine.h",
    ]) {
        println!("cargo::rerun-if-changed={path}");
    }

    cc::Build::new()
        .files(sources)
        .include("include")
        .std("c17")
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .compile("appine_engine");

    // Lets dependents' C code include the headers: the environment variable
    // DEP_APPINE_ENGINE_INCLUDE
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let include = std::path::Path::new(&manifest_dir).join("include");
    println!("cargo::metadata=include={}", include.display());
}
