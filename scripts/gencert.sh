#!/bin/sh

openssl genrsa 2048 > localhost.key
openssl req -x509 -sha256 -new -subj "/CN=localhost" -key localhost.key -out localhost.crt
