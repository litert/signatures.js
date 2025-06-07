[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [HMAC](../README.md) / verifyStream

# Function: verifyStream()

> **verifyStream**(`algo`, `key`, `message`, `signature`): `Promise`\<`boolean`\>

Defined in: [src/lib/HMAC.ts:130](https://github.com/litert/signatures.js/blob/master/src/lib/HMAC.ts#L130)

Verify the signature of a message inside a stream with HMAC.

## Parameters

### algo

The digest/hash algorithm to use.

`"blake2b512"` | `"blake2s256"` | `"md5"` | `"md5-sha1"` | `"ripemd"` | `"ripemd160"` | `"rmd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"` | `"sha512-224"` | `"sha512-256"` | `"sm3"`

### key

The key to verify the signature with.

`string` | `Buffer`\<`ArrayBufferLike`\>

### message

`Readable`

The payload to be verified, which is a readable stream.

### signature

`Buffer`

The signature of payload to be verified, which is a `Buffer`.

## Returns

`Promise`\<`boolean`\>

Return a `Promise` that resolves to `true` if the signature is valid, otherwise `false`.
