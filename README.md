# LiteRT/Signatures

[![Strict TypeScript Checked](https://badgen.net/badge/TS/Strict "Strict TypeScript Checked")](https://www.typescriptlang.org)
[![npm version](https://img.shields.io/npm/v/@litert/signatures.svg?colorB=brightgreen)](https://www.npmjs.com/package/@litert/signatures "Stable Version")
[![License](https://img.shields.io/npm/l/@litert/signatures.svg?maxAge=2592000?style=plastic)](https://github.com/litert/signatures/blob/master/LICENSE)
[![node](https://img.shields.io/node/v/@litert/signatures.svg?colorB=brightgreen)](https://nodejs.org/dist/latest-v8.x/)
[![GitHub issues](https://img.shields.io/github/issues/litert/signatures.js.svg)](https://github.com/litert/signatures.js/issues)
[![GitHub Releases](https://img.shields.io/github/release/litert/signatures.js.svg)](https://github.com/litert/signatures.js/releases "Stable Release")

A signatures library based on Node.js crypto module.

## Requirement

- TypeScript v3.1.x (or newer)
- Node.js v8.0.0 (or newer)

## Installation

```sh
npm i @litert/signatures --save
```

## Usage

```ts
import * as Signs from '@litert/signatures';

// Sign by RSA-SHA-256 with PKCS1-v1.5 padding
const rsaSign = Signs.RSA.sign('sha256', privKeyRSA, content);

// Verify by RSA-SHA-256 with PKCS1-v1.5 padding
if (Signs.RSA.verify('sha256', pubKeyRSA, content, rsaSign)) {

    console.log('RSA ok');
}

// Sign by RSA-SHA-256 with PSS-MGF1 padding
const rsapssSign = Signs.RSA.sign('sha256', privKeyRSA, content, {
    padding: 'pss-mgf1'
});

// Verify by RSA-SHA-256 with PSS-MGF1 padding
if (Signs.RSA.verify('sha256', pubKeyRSA, content, rsapssSign, {
    padding: 'pss-mgf1'
})) {

    console.log('RSA ok');
}

// Sign by ECDSA-SHA-256
const ecdsaSign = Signs.ECDSA.sign('sha256', privKeyECDSA, content);

// The output is of DER format.
console.log(`ECDSA DER:   ${ecdsaSign.toString('hex')}`);

// You can convert it into P1363 format
// And transform it back to DER by method derToP1363
console.log(`ECDSA p1363: ${Signs.ECDSA.p1363ToDER(ecdsaSign).toString('hex')}`);

// or use format option:
console.log(`ECDSA p1363: ${Signs.ECDSA.sign('sha256', privKeyECDSA, content, {format: 'ieee-p1363'}).toString('hex')}`);


// Verify by ECDSA-SHA-256
if (Signs.ECDSA.verify('sha256', pubKeyECDSA, content, ecdsaSign)) {

    console.log('ECDSA ok');
}

// Sign by HMAC-SHA-256
const hmacSign = Signs.HMAC.sign('sha256', hmacKey, content);

// Verify by HMAC-SHA-256
if (Signs.HMAC.verify('sha256', hmacKey, content, hmacSign)) {

    console.log('HMAC ok');
}
```

> See more [examples](./src/examples).

## Document

Preparing yet.

## License

This library is published under [Apache-2.0](./LICENSE) license.
