[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [ECDSA/Decl](../README.md) / IEcdsaOptions

# Interface: IEcdsaOptions

Defined in: [src/lib/ECDSA/Decl.ts:37](https://github.com/litert/signatures.js/blob/master/src/lib/ECDSA/Decl.ts#L37)

The options for ECDSA signing and verification.

## Properties

### format?

> `optional` **format**: `"der"` \| `"ieee-p1363"`

Defined in: [src/lib/ECDSA/Decl.ts:49](https://github.com/litert/signatures.js/blob/master/src/lib/ECDSA/Decl.ts#L49)

The output format of signature.

#### Default

```ts
'ieee-p1363
```

***

### keyPassphrase?

> `optional` **keyPassphrase**: `string` \| `Buffer`\<`ArrayBufferLike`\>

Defined in: [src/lib/ECDSA/Decl.ts:42](https://github.com/litert/signatures.js/blob/master/src/lib/ECDSA/Decl.ts#L42)

The passphrase of private key.
