use std::fmt::Debug;
use std::io::{stderr, Write};

use crate::ctap2::EnrollSampleStatus;

pub trait UiCallback: Sync + Send + Debug {
    /// Prompts the user to enter their PIN.
    fn request_pin(&self) -> Option<String>;

    /// Prompts the user to interact with their authenticator, normally by
    /// pressing or touching its button.
    ///
    /// This method will be called synchronously, and must not block.
    fn request_touch(&self);

    /// Provide the user feedback when they are enrolling fingerprints.
    ///
    /// This method will be called synchronously, and must not block.
    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    );
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

    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    ) {
        let mut stderr = stderr();
        writeln!(stderr, "Need {} more sample(s)", remaining_samples).ok();
        if let Some(feedback) = feedback {
            writeln!(stderr, "Last impression was {:?}", feedback).ok();
        }
    }
}
