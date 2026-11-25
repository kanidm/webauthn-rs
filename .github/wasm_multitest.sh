#!/bin/sh
# Run `wasm-pack test` for multiple crates.

set -e
readonly BROWSER="$1"

if [ -z "$BROWSER" ]
then
    echo "Missing browser option, eg: --chrome, --firefox, --node, --safari"
    exit 1
fi

while shift
do
    TARGET="$1"
    if [ -z "$1" ]
    then
        continue
    fi

    echo "** Running WASM $BROWSER test for: $TARGET"
    wasm-pack test --headless "$BROWSER" "$1"
    echo ""
done
