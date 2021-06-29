#!/bin/bash

SCRIPT_ROOT=$(cd $(dirname $0); pwd)

OUTPUT_DIR=$SCRIPT_ROOT/data

mkdir $OUTPUT_DIR -p

rm -f $OUTPUT_DIR/*.pem
rm -f $OUTPUT_DIR/*.dat

# Random File

dd if=/dev/random of=$OUTPUT_DIR/bigfile.dat bs=1M count=20

# RSA

openssl genrsa 2048 > $OUTPUT_DIR/rsa-priv.pem
openssl rsa -in $OUTPUT_DIR/rsa-priv.pem -pubout > $OUTPUT_DIR/rsa-pub.pem

openssl genrsa 2048 > $OUTPUT_DIR/rsa-wrong-priv.pem
openssl rsa -in $OUTPUT_DIR/rsa-wrong-priv.pem -pubout > $OUTPUT_DIR/rsa-wrong-pub.pem

openssl genrsa 2048 -passout pass:test_pass > $OUTPUT_DIR/rsa-passphrase-priv.pem
openssl rsa -in $OUTPUT_DIR/rsa-passphrase-priv.pem -pubout -passin pass:test_pass > $OUTPUT_DIR/rsa-passphrase-pub.pem

# ECDSA

openssl ecparam -out $OUTPUT_DIR/ec128-priv.pem -name secp128r1 -genkey
openssl ec -in $OUTPUT_DIR/ec128-priv.pem -pubout > $OUTPUT_DIR/ec128-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec128-wrong-priv.pem -name secp128r2 -genkey
openssl ec -in $OUTPUT_DIR/ec128-wrong-priv.pem -pubout > $OUTPUT_DIR/ec128-wrong-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec160-priv.pem -name brainpoolP160r1 -genkey
openssl ec -in $OUTPUT_DIR/ec160-priv.pem -pubout > $OUTPUT_DIR/ec160-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec160-wrong-priv.pem -name brainpoolP160t1 -genkey
openssl ec -in $OUTPUT_DIR/ec160-wrong-priv.pem -pubout > $OUTPUT_DIR/ec160-wrong-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec224-priv.pem -name secp224r1 -genkey
openssl ec -in $OUTPUT_DIR/ec224-priv.pem -pubout > $OUTPUT_DIR/ec224-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec224-wrong-priv.pem -name secp224k1 -genkey
openssl ec -in $OUTPUT_DIR/ec224-wrong-priv.pem -pubout > $OUTPUT_DIR/ec224-wrong-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec256-priv.pem -name prime256v1 -genkey
openssl ec -in $OUTPUT_DIR/ec256-priv.pem -pubout > $OUTPUT_DIR/ec256-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec256-wrong-priv.pem -name secp256k1 -genkey
openssl ec -in $OUTPUT_DIR/ec256-wrong-priv.pem -pubout > $OUTPUT_DIR/ec256-wrong-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec384-priv.pem -name secp384r1 -genkey
openssl ec -in $OUTPUT_DIR/ec384-priv.pem -pubout > $OUTPUT_DIR/ec384-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec384-wrong-priv.pem -name secp384r1 -genkey
openssl ec -in $OUTPUT_DIR/ec384-wrong-priv.pem -pubout > $OUTPUT_DIR/ec384-wrong-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec512-priv.pem -name brainpoolP512r1 -genkey
openssl ec -in $OUTPUT_DIR/ec512-priv.pem -pubout > $OUTPUT_DIR/ec512-pub.pem

openssl ecparam -out $OUTPUT_DIR/ec512-wrong-priv.pem -name brainpoolP512t1 -genkey
openssl ec -in $OUTPUT_DIR/ec512-wrong-priv.pem -pubout > $OUTPUT_DIR/ec512-wrong-pub.pem

rm $OUTPUT_DIR/*-wrong-priv.pem
