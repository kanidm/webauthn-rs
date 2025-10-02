use actix_web::HttpResponse;

pub const WASM_JS_FILE: &str = "wasm_tutorial.js";
pub const WASM_BG_FILE: &str = "wasm_tutorial_bg.wasm";

pub(crate) async fn index() -> HttpResponse {
    HttpResponse::Ok().body(format!(
        r#"
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WebAuthn-rs Tutorial</title>

    <script type="module">
        import init, {{ run_app }} from './pkg/{WASM_JS_FILE}';
        async function main() {{
           await init('./pkg/{WASM_BG_FILE}');
           run_app();
        }}
        main()
    </script>
  </head>
  <body>
  <p>Welcome to the WebAuthn Server!</p>
  </body>
</html>"#,
    ))
}
