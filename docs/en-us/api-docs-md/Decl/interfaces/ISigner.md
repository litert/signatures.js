[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [Decl](../README.md) / ISigner

# Interface: ISigner

Defined in: [src/lib/Decl.ts:22](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L22)

The signer interface.

## Properties

### hashAlgorithm

> `readonly` **hashAlgorithm**: `string`

Defined in: [src/lib/Decl.ts:57](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L57)

The digest hash algorithm of this signer.

***

### signAlgorithm

> `readonly` **signAlgorithm**: `string`

Defined in: [src/lib/Decl.ts:62](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L62)

The signing algorithm of this signer.

## Methods

### sign()

> **sign**(`message`): `Buffer`

Defined in: [src/lib/Decl.ts:29](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L29)

Sign simple short data.

#### Parameters

##### message

The payload to be signed.

`string` | `Buffer`\<`ArrayBufferLike`\>

#### Returns

`Buffer`

***

### signStream()

> **signStream**(`message`): `Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

Defined in: [src/lib/Decl.ts:36](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L36)

Sign data insides stream.

#### Parameters

##### message

`Readable`

The payload to be signed.

#### Returns

`Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

***

### verify()

> **verify**(`message`, `signature`): `boolean`

Defined in: [src/lib/Decl.ts:44](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L44)

Verify the signature of simple short data.

#### Parameters

##### message

The payload to be verified.

`string` | `Buffer`\<`ArrayBufferLike`\>

##### signature

`Buffer`

The signature of payload to be verified.

#### Returns

`boolean`

***

### verifyStream()

> **verifyStream**(`message`, `signature`): `Promise`\<`boolean`\>

Defined in: [src/lib/Decl.ts:52](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L52)

Verify data insides stream.

#### Parameters

##### message

`Readable`

The payload to be verified.

##### signature

`Buffer`

The signature of payload to be verified.

#### Returns

`Promise`\<`boolean`\>
