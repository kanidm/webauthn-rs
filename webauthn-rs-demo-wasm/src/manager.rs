use gloo::console;
use yew::functional::*;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::compat::CompatTest;
use crate::demo::Demo;
use crate::uv::UvInconsistent;

// router to decide on state.
#[derive(Routable, PartialEq, Clone, Debug)]
pub enum Route {
    #[at("/")]
    Demo,

    #[at("/compat_test")]
    CompatTest,

    #[at("/uv_inconsistent")]
    UvInconsistent,

    #[not_found]
    #[at("/404")]
    NotFound,
}

/*

                <li class="nav-item">
                  <Link<Route> classes={ classes!("nav-link", "active") } to={ Route::Demo }>{ "Demo" }</Link<Route>>
                </li>
                <li class="nav-item">
                  <Link<Route> classes={ classes!("nav-link") } to={ Route::CompatTest }>{ "Compatability Test" }</Link<Route>>
                </li>
                <li class="nav-item">
                  <Link<Route> classes={ classes!("nav-link") } to={ Route::UvInconsistent }>{ "Why is UV Discouraged Bad?" }</Link<Route>>
                </li>
*/

#[function_component(Nav)]
fn nav() -> Html {
    html! {
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
          <div class="container-fluid">
            <div class="collapse navbar-collapse justify-content-md-center">
              <ul class="navbar-nav">
                <li class="nav-item">
                  <p class="navbar-brand">{ "Webauthn RS" }</p>
                </li>
                <li class="nav-item">
                  <a class="nav-link active" aria-current="page" href="/">{ "Demo" }</a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="/compat_test">{ "Compatability Test" }</a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="/uv_inconsistent">{ "Why is UV Discouraged Bad?" }</a>
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
        Route::UvInconsistent => html! { <UvInconsistent /> },
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

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("manager::update");
        true
    }

    fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
        console::log!("manager::rendered");
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
          <div class="w-100 h-100">
            <Nav />
            <BrowserRouter>
                <Switch<Route> render={ Switch::render(switch) } />
            </BrowserRouter>
          </div>
        }
    }
}
