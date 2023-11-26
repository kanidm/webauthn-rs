# Webauthn-rs Tutorial

This is a tutorial / example of how to use the webauthn-rs library in a minimal capacity.

There are two halves to this tutorial - a backend server (`site`) and the front end
that contains a single-page html/wasm application (`wasm`).

## Running These

Try `make` for options, typically `make <tide|axum|actix>` will work.

## Troubleshooting

If you can't get registration to work or other errors are thrown, try clearing the cookies first.
