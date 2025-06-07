[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [HMAC](../README.md) / signStream

# Function: signStream()

> **signStream**(`algo`, `key`, `message`): `Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

Defined in: [src/lib/HMAC.ts:107](https://github.com/litert/signatures.js/blob/master/src/lib/HMAC.ts#L107)

Sign a message inside a stream with HMAC.

## Parameters

### algo

The digest/hash algorithm to use.

`"blake2b512"` | `"blake2s256"` | `"md5"` | `"md5-sha1"` | `"ripemd"` | `"ripemd160"` | `"rmd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"` | `"sha512-224"` | `"sha512-256"` | `"sm3"`

### key

The key to sign the message with.

`string` | `Buffer`\<`ArrayBufferLike`\>

### message

`Readable`

The payload to be signed, which is a readable stream.

## Returns

`Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

Return a `Promise` that resolves to a `Buffer` containing the signature of the payload.
