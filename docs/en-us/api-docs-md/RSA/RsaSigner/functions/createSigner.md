[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [RSA/RsaSigner](../README.md) / createSigner

# Function: createSigner()

> **createSigner**(`hashAlgo`, `publicKey`, `privateKey`, `opts?`): [`ISigner`](../../../Decl/interfaces/ISigner.md)

Defined in: [src/lib/RSA/RsaSigner.ts:255](https://github.com/litert/signatures.js/blob/master/src/lib/RSA/RsaSigner.ts#L255)

Create a new RSA signer instance.

## Parameters

### hashAlgo

The hash/digest algorithm to use.

`"md5"` | `"ripemd160"` | `"sha1"` | `"sha224"` | `"sha256"` | `"sha3-224"` | `"sha3-256"` | `"sha3-384"` | `"sha3-512"` | `"sha384"` | `"sha512"`

### publicKey

The public key to use for verification, or null to create a signer without a public key.

`null` | `string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### privateKey

The private key to use for signing, or null to create a verifier without a private key.

`null` | `string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### opts?

[`IRsaOptions`](../../ModuleApi/interfaces/IRsaOptions.md)

Optional options for the signer, such as key passphrase.

## Returns

[`ISigner`](../../../Decl/interfaces/ISigner.md)

A new RSA signer instance.

## Throws

`E_NO_KEY_PROVIDED` If neither publicKey nor privateKey is provided.

## Throws

`E_INVALID_PUBLIC_KEY` If the provided public key is invalid or not of type 'rsa'.

## Throws

`E_INVALID_PRIVATE_KEY` If the provided private key is invalid or not of type 'rsa'.

## Throws

`E_KEY_TYPE_MISMATCH` If the types of the key pair do not match.
