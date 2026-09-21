#!/bin/sh
set -e

/app/migration
LEPTOS_SITE_PKG_DIR="/app/site" /app/webauthn-rs-demo
