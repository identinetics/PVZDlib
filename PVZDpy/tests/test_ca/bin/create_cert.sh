#!/bin/bash

# self
openssl req -new \
    -subj /CN=idp.identinetics.com \
    -config etc/openssl.cnf -batch -days 7500 \
    -out certs/cert.csr  -text \
    -keyout certs/key.pem -nodes -newkey rsa:2048 \
    -passout pass:changeit

openssl ca \
    -config etc/openssl.cnf -batch -days 3650 \
    -in certs/cert.csr \
    -keyfile ca/root-key.pem \
    -key changeit


# idp.example.com
openssl req -new \
    -subj /CN=idp.example.com \
    -config etc/openssl.cnf -batch -days 7500 \
    -out certs/idp.example.com.csr  -text \
    -keyout certs/idp.example.com_key.pem -nodes -newkey rsa:2048 \
    -passout pass:changeit

openssl ca \
    -config etc/openssl.cnf -batch -days 3650 \
    -in certs/idp.example.com.csr \
    -keyfile ca/root-key.pem \
    -key changeit


# gondor.wien.gv.at
openssl req -new \
    -subj /CN=gondor.wien.gv.at \
    -config etc/openssl.cnf -batch -days 7500 \
    -out certs/gondor.wien.gv.at_csr.pem  -text \
    -keyout certs/gondor.wien.gv.at_key.pem -nodes -newkey rsa:2048 \
    -passout pass:changeit

openssl ca \
    -config etc/openssl.cnf -batch -days 3650 \
    -in certs/gondor.wien.gv.at_csr.pem \
    -out certs/gondor.wien.gv.at_crt.pem \
    -keyfile ca/root-key.pem \
    -key changeit


# extranet.unido.org
fqdn=extranet.unido.org

create_cert() {
    fqdn=$1
    openssl req -new \
        -subj /CN=${fqdn} \
        -config etc/openssl.cnf -batch -days 7500 \
        -out certs/${fqdn}_csr.pem  -text \
        -keyout certs/${fqdn}_key.pem -nodes -newkey rsa:2048 \
        -passout pass:changeit

    openssl ca \
        -config etc/openssl.cnf -batch -days 7500 \
        -in certs/${fqdn}_csr.pem \
        -out certs/${fqdn}_crt.pem \
        -keyfile ca/root-key.pem \
        -key changeit
}


# idp.example.com
openssl req -new \
    -subj /CN=idp.example.com \
    -config etc/openssl.cnf -batch -days 7500 \
    -out certs/idp.example.com.csr  -text \
    -keyout certs/idp.example.com_key.pem -nodes -newkey rsa:2048 \
    -passout pass:changeit

openssl ca \
    -config etc/openssl.cnf -batch -days 3650 \
    -in certs/idp.example.com.csr \
    -keyfile ca/root-key.pem \
    -key changeit


