[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [EDDSA](../README.md) / sign

# Function: sign()

> **sign**(`key`, `data`, `opts?`): `Buffer`

Defined in: [src/lib/EDDSA.ts:46](https://github.com/litert/signatures.js/blob/master/src/lib/EDDSA.ts#L46)

Sign the data with the given key.

## Parameters

### key

The key to sign the data with, can be a string, Buffer, or KeyObject.

`string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### data

The data to be signed, can be a string or Buffer.

`string` | `Buffer`\<`ArrayBufferLike`\>

### opts?

[`IEddsaOptions`](../interfaces/IEddsaOptions.md)

Optional options for signing, such as key passphrase.

## Returns

`Buffer`

The signature of the data as a Buffer.
