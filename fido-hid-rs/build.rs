#[cfg(target_os = "linux")]
mod linux {
    use std::{env, path::PathBuf};

    const WRAPPER_H: &'static str = "src/linux/wrapper.h";

    pub fn headers() {
        println!("cargo:rerun-if-changed={WRAPPER_H}");
        let bindings = bindgen::builder()
            .header(WRAPPER_H)
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
            .write_to_file(out_path.join("usb_linux_wrapper.rs"))
            .expect("Couldn't write bindings!");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux::headers();
}
