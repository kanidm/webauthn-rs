fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if !cfg!(disable_windows_manifest) && target_os == "windows" {
        embed_resource::compile("windows/fido-key-manager.rc", embed_resource::NONE);
    }
}
