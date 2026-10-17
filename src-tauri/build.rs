use std::{env, fs, path::Path};

fn main() {
    // Linux/macOS: the window carries the guard program inside itself. CI builds it into guard-bin/ first;
    // without it (plain `cargo check`) an empty stand-in is used and the window says so when asked to lock.
    let real = Path::new("guard-bin/maatram-guard");
    println!("cargo:rerun-if-changed=guard-bin/maatram-guard");
    let guard = if real.exists() {
        fs::canonicalize(real).expect("guard path")
    } else {
        let p = Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).join("guard-empty");
        fs::write(&p, b"").expect("stand-in");
        p
    };
    println!("cargo:rustc-env=MAATRAM_GUARD_BIN={}", guard.display());

    // Custom manifest = always runs as administrator on Windows (needed to edit hosts and end processes).
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest"))),
    )
    .expect("tauri build script failed");
}
