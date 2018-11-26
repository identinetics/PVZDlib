#!/bin/bash
# Setup Test-CA

mkdir -p ca/db ca/root-ca/private ca/root-ca/db crl certs etc

if [[ ! -e  "etc/openssl.cnf" ]]; then
    echo "missing openssl.cnf"
    exit 1
fi
chmod 700 ca/root-ca/private
cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr
echo 01 > ca/serial
touch ca/index.txt
openssl req -new \
    -config etc/openssl.cnf -batch \
    -subj /CN=PVZD-Alien-Test-CA2 \
    -out ca/root-ca.csr \
    -keyout ca/root-key.pem \
    -passout pass:changeit

openssl ca -selfsign \
    -config etc/openssl.cnf -batch \
    -in ca/root-ca.csr \
    -out ca/root-cert.pem \
    -keyfile ca/root-key.pem \
    -key changeit
    #-extensions root_ca_ext

