#!/bin/sh
set -e

/app/migration
LEPTOS_SITE_ROOT="/app/site" /app/webauthn-rs-demo
