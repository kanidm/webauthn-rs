mod home;
mod login;
mod not_found;
mod register;

pub use self::{home::HomePage, login::LoginPage, not_found::NotFoundPage, register::RegisterPage};
use rand::{seq::IteratorRandom, Rng};

fn is_username_valid(username: &str) -> bool {
    let len = username.len();
    len >= 3 && len <= 16 && username.chars().all(|c| c.is_ascii_alphanumeric())
}

const ANIMALS: [&str; 27] = [
    "bilby",
    "bowerbird",
    "brolga",
    "brushturkey",
    "cassowary",
    "cockatiel",
    "dingo",
    "dunnart",
    "echidna",
    "emu",
    "frogmouth",
    "goanna",
    "honeyeater",
    "kangaroo",
    "koala",
    "kookaburra",
    "lorikeet",
    "magpie",
    "platypus",
    "pogona",
    "possum",
    "quokka",
    "quoll",
    "rozella",
    "thylacine",
    "wallaby",
    "wobbegong",
];

/// Generate a random username of the form `{animal}{number}`.
fn random_username() -> String {
    let mut rng = rand::rng();
    let animal = ANIMALS.iter().choose(&mut rng).unwrap();
    let number = rng.random_range(0..100);
    format!("{animal}{number:02}")
}
