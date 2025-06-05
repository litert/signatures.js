# LiteRT/Signatures

[![Strict TypeScript Checked](https://badgen.net/badge/TS/Strict "Strict TypeScript Checked")](https://www.typescriptlang.org)
[![npm version](https://img.shields.io/npm/v/@litert/signatures.svg?colorB=brightgreen)](https://www.npmjs.com/package/@litert/signatures "Stable Version")
[![License](https://img.shields.io/npm/l/@litert/signatures.svg?maxAge=2592000?style=plastic)](https://github.com/litert/signatures/blob/master/LICENSE)
[![node](https://img.shields.io/node/v/@litert/signatures.svg?colorB=brightgreen)](https://nodejs.org/dist/latest-v8.x/)
[![GitHub issues](https://img.shields.io/github/issues/litert/signatures.js.svg)](https://github.com/litert/signatures.js/issues)
[![GitHub Releases](https://img.shields.io/github/release/litert/signatures.js.svg)](https://github.com/litert/signatures.js/releases "Stable Release")

A signatures library based on Node.js crypto module.

## Requirement

- TypeScript v5.0.x (or newer)
- Node.js v18.0.0 (or newer)

## Installation

```sh
npm i @litert/signatures --save
```

## Usage

- [Hash/Digest](./src/examples/00-hash.ts)

    The utilities API for calculating hash/digest of data.

- [HMAC](./src/examples/01-hmac.ts)

    The API for signing/verifying data using HMAC.

- [RSA](./src/examples/02-rsa.ts)

    The API for signing/verifying data using RSA.

- [RSA-PSS](./src/examples/03-rsa-pss.ts)

    The API for signing/verifying data using RSA-PSS.

- [EcDSA](./src/examples/04-ecdsa.ts)

    The API for signing/verifying data using EcDSA.

- [EdDSA](./src/examples/05-eddsa.ts)

    The API for signing/verifying data using EdDSA.

## Document

- [API Docs (en-US)](https://litert.org/projects/signatures.js/api-docs)

## License

This library is published under [Apache-2.0](./LICENSE) license.
