Actix with Webauthn
===================

This is an example of using Actix-web as the web server with a webauthn
integration.

How to run it:
--------------

```
cargo run --example actix
```

Then navigate to "http://localhost:8080/auth" as the server prints out.

What if that fails?
-------------------

If your system can't find localhost, this could be a failure in name resolution.
You should check you systems etc/hosts file for this. If you navigate to
"http://127.0.0.1:8080/auth" this example WILL FAIL as the origin is set to
localhost, not 127.0.0.1.

TODO:

* Improve the Javascript to use the username field correcly.
* Upgrade to actix 1.0 (see main.rs about this topic).
* Make it prettier and sparkly.
* Add cookie handling example.

