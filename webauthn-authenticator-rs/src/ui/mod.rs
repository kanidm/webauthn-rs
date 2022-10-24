pub trait UiCallback: Sync {
    /// Prompts the user to enter their PIN
    fn request_pin(&self) -> Option<String>;

    /// Prompts the user to interact with their authenticator, normally by
    /// pressing its button.
    fn request_touch(&self);
}


pub struct Cli {}

impl UiCallback for Cli {
    fn request_pin(&self) -> Option<String> {
        // TODO
        Some("1234".to_string())
    }

    fn request_touch(&self) {
        println!("Touch the authenticator");
    }
}
