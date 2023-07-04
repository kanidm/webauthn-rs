use std::{env, path::PathBuf};

const LINUX_WRAPPER_H: &str = "src/linux/wrapper.h";

fn linux_headers() {
    println!("cargo:rerun-if-changed={LINUX_WRAPPER_H}");
    let bindings = bindgen::builder()
        .header(LINUX_WRAPPER_H)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .derive_debug(false)
        .derive_default(true)
        .allowlist_type("hidraw_report_descriptor")
        .allowlist_type("hidraw_devinfo")
        .allowlist_var("HID_MAX_DESCRIPTOR_SIZE")
        .allowlist_var("BUS_(USB|BLUETOOTH|VIRTUAL)")
        .generate()
        .expect("unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("linux_wrapper.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "linux" {
        linux_headers();
    }
}
