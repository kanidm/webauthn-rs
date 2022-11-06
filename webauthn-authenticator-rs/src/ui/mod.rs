use std::fmt::Debug;
use std::io::{stderr, Write};

pub trait UiCallback: Sync + Send + Debug {
    /// Prompts the user to enter their PIN
    fn request_pin(&self) -> Option<String>;

    /// Prompts the user to interact with their authenticator, normally by
    /// pressing or touching its button.
    fn request_touch(&self);
}

/// Basic CLI [UiCallback] implementation.
///
/// This gets input from `stdin` and sends messages to `stderr`.
///
/// This is only intended for testing, and doesn't implement much functionality (like localization).
#[derive(Debug)]
pub struct Cli {}

impl UiCallback for Cli {
    fn request_pin(&self) -> Option<String> {
        rpassword::prompt_password_stderr("Enter PIN: ").ok()
    }

    fn request_touch(&self) {
        let mut stderr = stderr();
        writeln!(stderr, "Touch the authenticator").ok();
    }
}
