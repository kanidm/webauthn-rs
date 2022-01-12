use wasm_bindgen::JsCast;
use wasm_bindgen::UnwrapThrowExt;
use web_sys::Event;
use web_sys::HtmlInputElement;
use web_sys::InputEvent;
use web_sys::Window;
use web_sys::Document;

pub fn get_value_from_element_id(id: &str) -> Option<String> {
    // Once rendered if an element with id autofocus exists, focus it.
    document()
        .get_element_by_id(id)
        .and_then(|element| element.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|element| element.value())
}

pub fn document() -> Document {
    window().document().expect("Unable to retrieve document")
}


pub fn window() -> Window {
    web_sys::window().expect("Unable to retrieve window")
}
