#!/bin/bash

create_cert() {
    fqdn=$1
    openssl req -new \
        -subj /CN=${fqdn} \
        -config etc/openssl.cnf -batch -days 7500 \
        -out certs/${fqdn}_csr.pem  -text \
        -keyout certs/${fqdn}_key.pem -nodes -newkey rsa:2048 \
        -passout pass:changeit

    openssl ca \
        -config etc/openssl.cnf -batch -days 3650 \
        -in certs/${fqdn}_csr.pem \
        -out certs/${fqdn}_crt.pem \
        -keyfile ca/root-key.pem \
        -key changeit
}

# extranet.unido.org
fqdn=idp2.example.com

