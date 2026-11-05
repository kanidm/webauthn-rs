use std::time::SystemTime;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn now() -> SystemTime {
    SystemTime::now()
}

// SystemTime::now() panics on wasm32-unknown-unknown.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) fn now() -> SystemTime {
    let elapsed = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default();
    std::time::UNIX_EPOCH + elapsed
}
