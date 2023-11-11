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

#[function_component(Nav)]
fn nav() -> Html {
    let location = use_location().expect("unable to access location");
    let cur_route = location.route();

    html! {
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
          <div class="container">
            <p class="navbar-brand">{ "Webauthn RS" }</p>
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

fn switch(routes: &Route) -> Html {
    console::log!("manager::switch");
    match routes {
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

pub struct ManagerApp {}

impl Component for ManagerApp {
    type Message = bool;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!("manager::create");
        ManagerApp {}
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("manager::change");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        console::log!("manager::update");
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::log!("manager::rendered");
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
          <div class="w-100 h-100">
            <BrowserRouter>
                <Nav />
                <Switch<Route> render={ Switch::render(switch) } />
            </BrowserRouter>
          </div>
        }
    }
}
