fn main() {
    // Custom manifest = always runs as administrator (needed to edit hosts and end processes).
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest"))),
    )
    .expect("tauri build script failed");
}
