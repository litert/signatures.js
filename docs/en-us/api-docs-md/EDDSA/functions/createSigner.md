[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [EDDSA](../README.md) / createSigner

# Function: createSigner()

> **createSigner**(`publicKey`, `privateKey`, `keyType`, `opts?`): [`ISigner`](../../Decl/interfaces/ISigner.md)

Defined in: [src/lib/EDDSA.ts:106](https://github.com/litert/signatures.js/blob/master/src/lib/EDDSA.ts#L106)

Create a new EDDSA signer instance.

## Parameters

### publicKey

The public key to use for verification, or null to create a signer without a public key.

`null` | `string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### privateKey

The private key to use for signing, or null to create a verifier without a private key.

`null` | `string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### keyType

The key algorithm to use, or null to use the algorithm of the key.

`null` | `"ed25519"` | `"ed448"`

### opts?

[`IEddsaOptions`](../interfaces/IEddsaOptions.md)

Optional options for the signer, such as key passphrase.

## Returns

[`ISigner`](../../Decl/interfaces/ISigner.md)

A new EDDSA signer instance.

## Throws

`E_NO_KEY_PROVIDED` If neither publicKey nor privateKey is provided.

## Throws

`E_INVALID_PUBLIC_KEY` If the provided public key is invalid or not of type 'ed25519' or 'ed448'.

## Throws

`E_INVALID_PRIVATE_KEY` If the provided private key is invalid or not of type 'ed25519' or 'ed448'.

## Throws

`E_KEY_TYPE_MISMATCH` If the types of the key pair do not match.
