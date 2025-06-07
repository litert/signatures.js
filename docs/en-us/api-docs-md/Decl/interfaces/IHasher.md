[**Documents for @litert/signatures**](../../README.md)

***

[Documents for @litert/signatures](../../README.md) / [Decl](../README.md) / IHasher

# Interface: IHasher

Defined in: [src/lib/Decl.ts:68](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L68)

The hasher interface.

## Properties

### algorithm

> `readonly` **algorithm**: `string`

Defined in: [src/lib/Decl.ts:87](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L87)

The digest hash algorithm of this hasher.

## Methods

### hash()

> **hash**(`message`): `Buffer`

Defined in: [src/lib/Decl.ts:75](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L75)

Calculate the hash of simple short data.

#### Parameters

##### message

The payload to be processed.

`string` | `Buffer`\<`ArrayBufferLike`\>

#### Returns

`Buffer`

***

### hashStream()

> **hashStream**(`message`): `Promise`\<`Buffer`\<`ArrayBufferLike`\>\>

Defined in: [src/lib/Decl.ts:82](https://github.com/litert/signatures.js/blob/master/src/lib/Decl.ts#L82)

Calculate the hash of data insides stream.

#### Parameters

##### message

`Readable`

The payload to be processed.

#### Returns

`Promise`\<`Buffer`\<`ArrayBufferLike`\>\>
