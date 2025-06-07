[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [ECDSA/ModuleApi](../README.md) / signStream

# Function: signStream()

> **signStream**(`algo`, `privateKey`, `message`, `opts?`): `Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

Defined in: [src/lib/ECDSA/ModuleApi.ts:128](https://github.com/litert/signatures.js/blob/master/src/lib/ECDSA/ModuleApi.ts#L128)

Sign the input stream.

## Parameters

### algo

The digest/hash algorithm to be used.

`"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"`

### privateKey

The private key to sign the data.

`string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### message

`Readable`

The input stream to be signed.

### opts?

[`IEcdsaOptions`](../../Decl/interfaces/IEcdsaOptions.md)

The options for signing.

## Returns

`Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

Return a promise that resolves to a `Buffer` that contains the signature of the input stream.
