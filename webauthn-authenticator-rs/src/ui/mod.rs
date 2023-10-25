use crate::types::{CableRequestType, CableState, EnrollSampleStatus};
use std::fmt::Debug;

#[cfg(any(all(doc, not(doctest)), feature = "ui-cli"))]
mod cli;

#[cfg(any(all(doc, not(doctest)), feature = "ui-cli"))]
#[doc(inline)]
pub use self::cli::Cli;

pub trait UiCallback: Sync + Send + Debug {
    /// Prompts the user to enter their PIN.
    fn request_pin(&self) -> Option<String>;

    /// Prompts the user to interact with their authenticator, normally by
    /// pressing or touching its button.
    ///
    /// This method will be called synchronously, and must not block.
    fn request_touch(&self);

    /// Tell the user that the key is currently processing a request.
    fn processing(&self);

    /// Provide the user feedback when they are enrolling fingerprints.
    ///
    /// This method will be called synchronously, and must not block.
    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    );

    /// Prompt the user to scan a QR code with their mobile device to start the
    /// caBLE linking process.
    ///
    /// This method will be called synchronously, and must not block.
    fn cable_qr_code(&self, request_type: CableRequestType, url: String);

    /// Dismiss a displayed QR code from the screen.
    ///
    /// This method will be called synchronously, and must not block.
    fn dismiss_qr_code(&self);

    fn cable_status_update(&self, state: CableState);
}
