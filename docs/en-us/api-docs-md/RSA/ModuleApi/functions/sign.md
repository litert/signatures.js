[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [RSA/ModuleApi](../README.md) / sign

# Function: sign()

> **sign**(`algo`, `privateKey`, `message`, `opts?`): `Buffer`

Defined in: [src/lib/RSA/ModuleApi.ts:112](https://github.com/litert/signatures.js/blob/master/src/lib/RSA/ModuleApi.ts#L112)

Hash a message with the specified hash/digest algorithm.

## Parameters

### algo

The hash/digest algorithm to use.

`"md5"` | `"ripemd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"`

### privateKey

The private key to sign the message with.

`string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### message

The payload to be signed, can be a `Buffer` or a `string`.

`string` | `Buffer`\<`ArrayBufferLike`\>

### opts?

[`IRsaOptions`](../interfaces/IRsaOptions.md)

The options for signing, including the passphrase of the private key and the padding algorithm.

## Returns

`Buffer`

Return a `Buffer` that contains the signature of the payload.

## Throws

`E_INVALID_PRIVATE_KEY` If the private key is not a valid RSA private key.

## Throws

`E_SIGN_FAILED` If the signing fails.
