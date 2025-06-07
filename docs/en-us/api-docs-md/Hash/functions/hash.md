[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [Hash](../README.md) / hash

# Function: hash()

> **hash**(`algo`, `message`): `Buffer`

Defined in: [src/lib/Hash.ts:71](https://github.com/litert/signatures.js/blob/master/src/lib/Hash.ts#L71)

Calculate the hash/digest of a message using the specified algorithm.

## Parameters

### algo

The hash/digest algorithm to use.

`"blake2b512"` | `"blake2s256"` | `"md5"` | `"md5-sha1"` | `"ripemd"` | `"ripemd160"` | `"rmd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"` | `"sha512-224"` | `"sha512-256"` | `"sm3"`

### message

The message to hash, can be a `Buffer` or a `string`.

`string` | `Buffer`\<`ArrayBufferLike`\>

## Returns

`Buffer`

A `Buffer` containing the hash/digest of the message.
