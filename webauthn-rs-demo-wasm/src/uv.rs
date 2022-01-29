use gloo::console;
use yew::prelude::*;

#[derive(Debug)]
pub enum UvInconsistent {
    Init,
}

#[derive(Debug)]
pub enum AppMsg {
    Begin,
}

impl Component for UvInconsistent {
    type Message = AppMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!(format!("create").as_str());
        UvInconsistent::Init
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        true
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
          <div class="row h-100">
            <div class="col-6 col-lg-4 col explain">
              <p>{ "what's going on?" }</p>
            </div>
            <div class="col-sm-6 col-lg-8 col">
              <main class="text-center form-signin h-100">
                <div class="vert-center">
                  <div>
                    <h3 class="h3 mb-3 fw-normal">{ "Register a Webauthn Credential" }</h3>
                    <div class="form-floating">
                      <input class="form-control" id="floatingInput" placeholder="username" />
                      <label for="floatingInput">{ "Username" }</label>
                    </div>
                    <button class="btn btn-lg btn-primary" type="submit">{ "Begin Demonstration" }</button>
                  </div>
                </div>
              </main>
            </div>
          </div>
        }
    }
}
