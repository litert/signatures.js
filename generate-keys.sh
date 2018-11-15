mkdir test -p
rm -f test/*.pem

# RSA

openssl genrsa 2048 > test/rsa-priv.pem
openssl rsa -in test/rsa-priv.pem -pubout > test/rsa-pub.pem

openssl genrsa 2048 > test/rsa-wrong-priv.pem
openssl rsa -in test/rsa-wrong-priv.pem -pubout > test/rsa-wrong-pub.pem

openssl genrsa 2048 -passout pass:test_pass > test/rsa-passphrase-priv.pem
openssl rsa -in test/rsa-passphrase-priv.pem -pubout -passin pass:test_pass > test/rsa-passphrase-pub.pem

# ECDSA

openssl ecparam -out test/ec128-priv.pem -name secp128r1 -genkey
openssl ec -in test/ec128-priv.pem -pubout > test/ec128-pub.pem

openssl ecparam -out test/ec128-wrong-priv.pem -name secp128r2 -genkey
openssl ec -in test/ec128-wrong-priv.pem -pubout > test/ec128-wrong-pub.pem

openssl ecparam -out test/ec160-priv.pem -name brainpoolP160r1 -genkey
openssl ec -in test/ec160-priv.pem -pubout > test/ec160-pub.pem

openssl ecparam -out test/ec160-wrong-priv.pem -name brainpoolP160t1 -genkey
openssl ec -in test/ec160-wrong-priv.pem -pubout > test/ec160-wrong-pub.pem

openssl ecparam -out test/ec224-priv.pem -name secp224r1 -genkey
openssl ec -in test/ec224-priv.pem -pubout > test/ec224-pub.pem

openssl ecparam -out test/ec224-wrong-priv.pem -name secp224k1 -genkey
openssl ec -in test/ec224-wrong-priv.pem -pubout > test/ec224-wrong-pub.pem

openssl ecparam -out test/ec256-priv.pem -name prime256v1 -genkey
openssl ec -in test/ec256-priv.pem -pubout > test/ec256-pub.pem

openssl ecparam -out test/ec256-wrong-priv.pem -name secp256k1 -genkey
openssl ec -in test/ec256-wrong-priv.pem -pubout > test/ec256-wrong-pub.pem

openssl ecparam -out test/ec384-priv.pem -name secp384r1 -genkey
openssl ec -in test/ec384-priv.pem -pubout > test/ec384-pub.pem

openssl ecparam -out test/ec384-wrong-priv.pem -name secp384r1 -genkey
openssl ec -in test/ec384-wrong-priv.pem -pubout > test/ec384-wrong-pub.pem

openssl ecparam -out test/ec512-priv.pem -name brainpoolP512r1 -genkey
openssl ec -in test/ec512-priv.pem -pubout > test/ec512-pub.pem

openssl ecparam -out test/ec512-wrong-priv.pem -name brainpoolP512t1 -genkey
openssl ec -in test/ec512-wrong-priv.pem -pubout > test/ec512-wrong-pub.pem

rm test/*-wrong-priv.pem
