#!/bin/bash
# Checks that documentation artefacts are present.
#
# This ensures that the library's documentation was buildable and included all
# features, regardless of which features were actually enabled.

set -e
readonly MANIFEST="$(dirname $0)/doc_manifest"
readonly TARGET_DIR="$(dirname $0)/../target/doc/"
c=0
m=0

if [[ ! -d "${TARGET_DIR}" ]]
then
    echo "Target directory ${TARGET_DIR} does not exist!"
    exit 1
fi

echo "Checking for missing files:"
while read -r f
do
    # Ignore empty lines and comments
    if [[ -z "$f" || "${f:0:1}" == "#" ]]
    then
        continue
    fi

    c=$((c+1))
    # File must exist and be > 0 bytes
    if [[ ! -s "${TARGET_DIR}/${f}" ]]
    then
        # Missing file
        echo "$f"
        m=$((m+1))
    fi
done < "${MANIFEST}"

if [[ "$c" == "0" ]]
then
    echo "No files listed in ${MANIFEST} to check!"
    exit 1
fi

if [[ "$m" == "0" ]]
then
    echo "All ${c} files present."
else
    echo "${m} of ${c} files missing!"
    exit 1
fi
