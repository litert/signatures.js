[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [HMAC](../README.md) / createSigner

# Function: createSigner()

> **createSigner**(`algo`, `key`): [`ISigner`](../../Decl/interfaces/ISigner.md)

Defined in: [src/lib/HMAC.ts:148](https://github.com/litert/signatures.js/blob/master/src/lib/HMAC.ts#L148)

Create a signer object for HMAC, binding a specific digest/hash algorithm and key.

## Parameters

### algo

The digest/hash algorithm to use.

`"blake2b512"` | `"blake2s256"` | `"md5"` | `"md5-sha1"` | `"ripemd"` | `"ripemd160"` | `"rmd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"` | `"sha512-224"` | `"sha512-256"` | `"sm3"`

### key

The key to sign the message with.

`string` | `Buffer`\<`ArrayBufferLike`\>

## Returns

[`ISigner`](../../Decl/interfaces/ISigner.md)

Return a signer object for HMAC.
