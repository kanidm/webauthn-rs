use actix_web::HttpResponse;

pub(crate) async fn index() -> HttpResponse {
    HttpResponse::Ok().body(
        r#"
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WebAuthn-rs Tutorial</title>

    <script type="module">
        import init, { run_app } from './pkg/wasm.js';
        async function main() {
           await init('./pkg/wasm_bg.wasm');
           run_app();
        }
        main()
    </script>
  </head>
  <body>
  <p>Welcome to the WebAuthn Server!</p>
  </body>
</html>"#,
    )
}
