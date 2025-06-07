[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [ECDSA/ModuleApi](../README.md) / sign

# Function: sign()

> **sign**(`algo`, `privateKey`, `message`, `opts?`): `Buffer`

Defined in: [src/lib/ECDSA/ModuleApi.ts:61](https://github.com/litert/signatures.js/blob/master/src/lib/ECDSA/ModuleApi.ts#L61)

Sign simple short data.

## Parameters

### algo

The digest/hash algorithm to be used.

`"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"`

### privateKey

The private key to sign the data.

`string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### message

The payload to be signed.

`string` | `Buffer`\<`ArrayBufferLike`\>

### opts?

[`IEcdsaOptions`](../../Decl/interfaces/IEcdsaOptions.md)

The options for signing.

## Returns

`Buffer`

Return a `Buffer` that contains the signature of the payload.
