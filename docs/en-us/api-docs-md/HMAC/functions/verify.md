[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [HMAC](../README.md) / verify

# Function: verify()

> **verify**(`algo`, `key`, `message`, `signature`): `boolean`

Defined in: [src/lib/HMAC.ts:88](https://github.com/litert/signatures.js/blob/master/src/lib/HMAC.ts#L88)

Verify the signature of a message with HMAC.

## Parameters

### algo

The digest/hash algorithm to use.

`"blake2b512"` | `"blake2s256"` | `"md5"` | `"md5-sha1"` | `"ripemd"` | `"ripemd160"` | `"rmd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"` | `"sha512-224"` | `"sha512-256"` | `"sm3"`

### key

The key to verify the signature with.

`string` | `Buffer`\<`ArrayBufferLike`\>

### message

The payload to be verified.

`string` | `Buffer`\<`ArrayBufferLike`\>

### signature

`Buffer`

The signature of payload to be verified.

## Returns

`boolean`

Return `true` if the signature is valid, otherwise `false`.
