[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [Hash](../README.md) / hashStream

# Function: hashStream()

> **hashStream**(`algo`, `message`): `Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

Defined in: [src/lib/Hash.ts:84](https://github.com/litert/signatures.js/blob/master/src/lib/Hash.ts#L84)

Calculate the hash/digest of a stream using the specified algorithm.

## Parameters

### algo

The hash/digest algorithm to use.

`"blake2b512"` | `"blake2s256"` | `"md5"` | `"md5-sha1"` | `"ripemd"` | `"ripemd160"` | `"rmd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"` | `"sha512-224"` | `"sha512-256"` | `"sm3"`

### message

`Readable`

The stream to hash, must be a `Readable` stream.

## Returns

`Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

A `Promise` that resolves to a `Buffer` containing the hash/digest of the stream.
