Tide with Webauthn
===================

This is an example of using tide as the web server with a webauthn
integration.

How to run it:
--------------

```
cargo run --example tide
```

Then navigate to "http://localhost:8080/auth" as the server prints out.

What if that fails?
-------------------

If your system can't find localhost, this could be a failure in name resolution.
You should check your system's etc/hosts file for this. If you navigate to
"http://127.0.0.1:8080/auth" this example WILL FAIL as the origin is set to
localhost, not 127.0.0.1.

TODO:

* Improve the Javascript to use the username field correcly.
* Make it prettier and sparkly.
* Add cookie handling example.

Building Yew:
-------------

```
cargo install wasm-pack
npm install --global rollup
cd tide_yew
./build_wasm.sh
```



