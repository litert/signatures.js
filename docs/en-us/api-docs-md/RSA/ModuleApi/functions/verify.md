[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [RSA/ModuleApi](../README.md) / verify

# Function: verify()

> **verify**(`algo`, `publicKey`, `message`, `signature`, `opts?`): `boolean`

Defined in: [src/lib/RSA/ModuleApi.ts:152](https://github.com/litert/signatures.js/blob/master/src/lib/RSA/ModuleApi.ts#L152)

Verify a message with the specified hash/digest algorithm.

## Parameters

### algo

The hash/digest algorithm to use.

`"md5"` | `"ripemd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"`

### publicKey

The public key to verify the message with.

`string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### message

The payload to be verified, can be a `Buffer` or a `string`.

`string` | `Buffer`\<`ArrayBufferLike`\>

### signature

`Buffer`

The signature of the payload to be verified, must be a `Buffer`.

### opts?

[`IRsaOptions`](../interfaces/IRsaOptions.md)

The options for verification, including the padding algorithm.

## Returns

`boolean`

Return true if the signature is valid, otherwise false.

## Throws

`E_INVALID_PUBLIC_KEY` If the public key is not a valid RSA public key.

## Throws

`E_VERIFY_FAILED` If the verification fails.
