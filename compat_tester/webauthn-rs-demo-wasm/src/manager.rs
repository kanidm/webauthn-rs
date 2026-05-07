use gloo::console;
use yew::functional::*;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::compat::CompatTest;
use crate::demo::Demo;
// use crate::uv::UvInconsistent;

// router to decide on state.
#[derive(Routable, PartialEq, Clone, Debug)]
pub enum Route {
    #[at("/")]
    Demo,

    #[at("/compat_test")]
    CompatTest,

    #[not_found]
    #[at("/404")]
    NotFound,
}

#[function_component]
fn Nav() -> Html {
    // let location = use_location().expect("unable to access location");
    let cur_route: Option<Route> = use_route();

    html! {
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
          <div class="container">
            <p class="navbar-brand">{ "webauthn-rs" }</p>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse"
                data-bs-target="#navbarcontent" aria-controls="navbarcontent"
                aria-expanded="false" aria-label="Toggle navigation">
              <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse justify-content-md-center" id="navbarcontent">
              <ul class="navbar-nav">
                <li class="nav-item">
                  <Link<Route> classes={
                    if matches!(cur_route, Some(Route::Demo)) {
                        classes!("nav-link", "active")
                    } else {
                        classes!("nav-link")
                    }
                  } to={ Route::Demo }>{ "Demonstration" }</Link<Route>>
                </li>
                <li class="nav-item">
                  <Link<Route> classes={
                    if matches!(cur_route, Some(Route::CompatTest)) {
                        classes!("nav-link", "active")
                    } else {
                        classes!("nav-link")
                    }
                  } to={ Route::CompatTest }>{ "Compatibility Test" }</Link<Route>>
                </li>
              </ul>
            </div>
          </div>
        </nav>
    }
}

fn switch(route: Route) -> Html {
    console::log!("manager::switch");
    match route {
        Route::Demo => html! { <Demo /> },
        Route::CompatTest => html! { <CompatTest /> },
        Route::NotFound => {
            html! {
                <>
                    <h1>{ "404" }</h1>
                    <Link<Route> to={ Route::Demo }>
                    { "Back to Demo" }
                    </Link<Route>>
                </>
            }
        }
    }
}

#[function_component]
pub fn ManagerApp() -> Html {
    html! {
        <BrowserRouter>
            <Nav />
            <div class="container mt-1">
                <Switch<Route> render={switch} />
            </div>
        </BrowserRouter>
    }
}
