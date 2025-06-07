[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [RSA/ModuleApi](../README.md) / signStream

# Function: signStream()

> **signStream**(`algo`, `privateKey`, `message`, `opts?`): `Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

Defined in: [src/lib/RSA/ModuleApi.ts:191](https://github.com/litert/signatures.js/blob/master/src/lib/RSA/ModuleApi.ts#L191)

Sign a message inside a stream with the specified hash/digest algorithm.

## Parameters

### algo

The hash/digest algorithm to use.

`"md5"` | `"ripemd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"`

### privateKey

The private key to sign the message with.

`string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### message

`Readable`

The payload to be signed, which is a readable stream.

### opts?

[`IRsaOptions`](../interfaces/IRsaOptions.md)

The options for signing, including the passphrase of the private key and the padding algorithm.

## Returns

`Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

Return a `Promise` that resolves to a `Buffer` containing the signature of the payload.

## Throws

`E_INVALID_PRIVATE_KEY` If the private key is not a valid RSA private key.

## Throws

`E_SIGN_FAILED` If the signing fails.
