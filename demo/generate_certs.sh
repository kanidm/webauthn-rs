#!/bin/sh
set -e
umask 077

readonly TLS_PRIVATE_KEY="key.pem"
readonly TLS_PUBLIC_KEY="cert.pem"

if [ -e "${TLS_PRIVATE_KEY}" ]
then
    echo "Using existing private key: ${TLS_PRIVATE_KEY}"
else
    echo "Generating private key: ${TLS_PRIVATE_KEY}"
    openssl genrsa -out "${TLS_PRIVATE_KEY}"
fi

# If the public key already exists and is not newer than the private key, check
# if it will expire soon.
if [[ -e "${TLS_PUBLIC_KEY}" && ( ! "${TLS_PRIVATE_KEY}" -nt "${TLS_PUBLIC_KEY}" ) ]]
then
    echo "Checking existing certificate: ${TLS_PUBLIC_KEY}"
    # Delete the public key file if it will expire in the next day, so we will
    # rebuild that in the next step.
    if ! openssl x509 -checkend 86400 -noout -in "${TLS_PUBLIC_KEY}"
    then
        rm "${TLS_PUBLIC_KEY}"
    fi
fi

if [ "${TLS_PRIVATE_KEY}" -nt "${TLS_PUBLIC_KEY}" ]
then
    echo "Generating new certificate: ${TLS_PUBLIC_KEY}"
    openssl req -new -x509 \
        -key "${TLS_PRIVATE_KEY}" \
        -out "${TLS_PUBLIC_KEY}" \
        -days 5 \
        -subj "/CN=localhost/" \
        -addext "subjectAltName = IP:127.0.0.1, DNS:localhost" \
        -addext "extendedKeyUsage = serverAuth"
fi
