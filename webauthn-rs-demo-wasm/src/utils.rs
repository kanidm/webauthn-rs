use gloo::console;
use wasm_bindgen::JsCast;
use wasm_bindgen::UnwrapThrowExt;
use web_sys::Document;
use web_sys::Event;
use web_sys::HtmlInputElement;
use web_sys::HtmlSelectElement;
use web_sys::InputEvent;
use web_sys::Window;

pub fn get_checked_from_element_id(id: &str) -> Option<bool> {
    document()
        .get_element_by_id(id)
        .and_then(|element| element.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|element| element.checked())
}

pub fn get_select_value_from_element_id(id: &str) -> Option<String> {
    document()
        .get_element_by_id(id)
        .and_then(|element| {
            console::log!("Into Dyn Options Collection.");
            element.dyn_into::<web_sys::HtmlSelectElement>().ok()
        })
        .map(|element|
            element.value()
        )
}

pub fn get_value_from_element_id(id: &str) -> Option<String> {
    document()
        .get_element_by_id(id)
        .and_then(|element| element.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|element| element.value())
}

pub fn autofocus(id: &str) {
    // Once rendered if an element with id autofocus exists, focus it.
    let doc = document();
    if let Some(element) = doc.get_element_by_id(id) {
        if let Ok(htmlelement) = element.dyn_into::<web_sys::HtmlElement>() {
            if htmlelement.focus().is_err() {
                console::log!("unable to autofocus.");
            }
        }
    }
}

pub fn document() -> Document {
    window().document().expect("Unable to retrieve document")
}

pub fn window() -> Window {
    web_sys::window().expect("Unable to retrieve window")
}
