[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [EDDSA](../README.md) / verify

# Function: verify()

> **verify**(`key`, `data`, `signature`): `boolean`

Defined in: [src/lib/EDDSA.ts:75](https://github.com/litert/signatures.js/blob/master/src/lib/EDDSA.ts#L75)

Verify the signature of the data with the given key.

## Parameters

### key

The key to verify the signature with, can be a string, Buffer, or KeyObject.

`string` | `Buffer`\<`ArrayBufferLike`\> | `KeyObject`

### data

The data to be verified, can be a string or Buffer.

`string` | `Buffer`\<`ArrayBufferLike`\>

### signature

`Buffer`

The signature of the data to be verified, must be a Buffer.

## Returns

`boolean`

`true` if the signature is valid, `false` otherwise.
