use std::time::SystemTime;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn now() -> SystemTime {
    SystemTime::now()
}

// SystemTime::now() panics on wasm32-unknown-unknown, so read JavaScript's clock.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64)
}
