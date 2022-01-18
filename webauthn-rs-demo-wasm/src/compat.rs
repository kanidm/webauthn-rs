use gloo::console;
use yew::functional::*;
use yew::prelude::*;
use yew_router::prelude::*;

/*
 * We want to test:
 * Indirect Attest: Discouraged
 * Direct Attest: Discouraged
 * None Attest: Discouraged
 * None Attest - remove the previous enc algo
 * Auth - use the discouraged as above, see if we get UV=true?
 * None Attest - preferred,
 * Auth - use the discouraged as above, see if we get UV=true?
 * None Attest - required
 * If reg -> is req during auth
 *
 */

#[derive(Debug)]
pub enum CompatTest {
    Init,
}

#[derive(Debug)]
pub enum AppMsg {
    Begin,
}

impl Component for CompatTest {
    type Message = AppMsg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        console::log!(format!("create").as_str());
        CompatTest::Init
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="form-description">
              <main class="h-100">
                <div class="vert-center">
                  <div>
                    <p>
                    {" This will conduct a compatability test of your authenticator (security token) to determine if it is compatible with Webauthn RS." }
                    </p>
                    <p>
                    { "During this test your authenticator will prompt your to authenticate and interact with it a number of times." }
                    </p>
                    <p>
                    { "You may also be requested to configure a PIN or Biometrics on your authenticator. If you do NOT wish for this to happen, do NOT run this test." }
                    </p>
                    <p>
                    { "Please know that and PIN or Biometrics you configure never leave your security token, and are not accessible to the Webauthn RS site." }
                    </p>
                    <p>
                    { "If you have multiple authenticators available, you MUST ensure that you only use a single one of them during the test until completed." }
                    </p>
                    <div class="text-center">
                      <button class="btn btn-lg btn-primary">{ "Begin Compatability Test" }</button>
                    </div>
                  </div>
                </div>
              </main>

            </div>
        }
    }
}
