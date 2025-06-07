[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [Hash](../README.md) / createHasher

# Function: createHasher()

> **createHasher**(`algo`): [`IHasher`](../../Decl/interfaces/IHasher.md)

Defined in: [src/lib/Hash.ts:100](https://github.com/litert/signatures.js/blob/master/src/lib/Hash.ts#L100)

Create a hasher object for the specified algorithm.

## Parameters

### algo

The hash/digest algorithm to use.

`"blake2b512"` | `"blake2s256"` | `"md5"` | `"md5-sha1"` | `"ripemd"` | `"ripemd160"` | `"rmd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"` | `"sha512-224"` | `"sha512-256"` | `"sm3"`

## Returns

[`IHasher`](../../Decl/interfaces/IHasher.md)

A hasher object that implements the `IHasher` interface.
