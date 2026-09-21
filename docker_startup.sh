#!/bin/sh
set -e

if [ -z "${SECRET_KEY}" ]
    echo "WARNING: SECRET_KEY was not specified, randomly generating a key."
    echo "WARNING: All cookies will be invalidated on container restart!"
    export SECRET_KEY="$(openssl rand -hex 32)"
fi

/app/release/migration
/app/release/webauthn-rs-demo
