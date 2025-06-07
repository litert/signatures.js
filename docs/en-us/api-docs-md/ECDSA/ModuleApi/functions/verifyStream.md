[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [ECDSA/ModuleApi](../README.md) / verifyStream

# Function: verifyStream()

> **verifyStream**(`algo`, `publicKey`, `message`, `signature`, `opts?`): `Promise`\<`boolean`\>

Defined in: [src/lib/ECDSA/ModuleApi.ts:166](https://github.com/litert/signatures.js/blob/master/src/lib/ECDSA/ModuleApi.ts#L166)

Verify the signature of the input stream.

## Parameters

### algo

The digest/hash algorithm to be used.

`"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"`

### publicKey

The public key to verify the signature.

`string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### message

`Readable`

The input stream to be verified.

### signature

`Buffer`

The signature of the input stream.

### opts?

[`IEcdsaOptions`](../../Decl/interfaces/IEcdsaOptions.md)

The options for verification.

## Returns

`Promise`\<`boolean`\>

Return a promise that resolves to true if the signature is valid, otherwise false.
