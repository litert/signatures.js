[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [ECDSA/ModuleApi](../README.md) / verify

# Function: verify()

> **verify**(`algo`, `publicKey`, `message`, `signature`, `opts?`): `boolean`

Defined in: [src/lib/ECDSA/ModuleApi.ts:95](https://github.com/litert/signatures.js/blob/master/src/lib/ECDSA/ModuleApi.ts#L95)

Verify the signature of simple short data.

## Parameters

### algo

The digest/hash algorithm to be used.

`"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"`

### publicKey

The public key to verify the signature.

`string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### message

The payload to be verified.

`string` | `Buffer`\<`ArrayBufferLike`\>

### signature

`Buffer`

The signature of the payload to be verified.

### opts?

[`IEcdsaOptions`](../../Decl/interfaces/IEcdsaOptions.md)

The options for verification.

## Returns

`boolean`

Return true if the signature is valid, otherwise false.
