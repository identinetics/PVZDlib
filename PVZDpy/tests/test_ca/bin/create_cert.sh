#!/bin/bash

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

openssl req -new \
    -subj /CN=idp.example.com \
    -config etc/openssl.cnf -batch -days 7500 \
    -out certs/cert.csr  -text \
    -keyout certs/key.pem -nodes -newkey rsa:2048 \
    -passout pass:changeit


openssl ca \
    -config etc/openssl.cnf -batch -days 3650 \
    -in certs/cert.csr \
    -keyfile ca/root-key.pem \
    -key changeit
