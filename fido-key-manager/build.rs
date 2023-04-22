fn main() {
    #[cfg(windows)]
    {
        winres::WindowsResource::new()
            .set_manifest_file("manifest.xml")
            .compile()
            .unwrap();
    }
}
