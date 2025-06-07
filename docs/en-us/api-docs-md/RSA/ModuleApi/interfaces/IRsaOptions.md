[**Documents for @litert/signatures**](../../../README.md)

***

[Documents for @litert/signatures](../../../README.md) / [RSA/ModuleApi](../README.md) / IRsaOptions

# Interface: IRsaOptions

Defined in: [src/lib/RSA/ModuleApi.ts:79](https://github.com/litert/signatures.js/blob/master/src/lib/RSA/ModuleApi.ts#L79)

## Properties

### keyPassphrase?

> `optional` **keyPassphrase**: `string` \| `Buffer`\<`ArrayBufferLike`\>

Defined in: [src/lib/RSA/ModuleApi.ts:84](https://github.com/litert/signatures.js/blob/master/src/lib/RSA/ModuleApi.ts#L84)

The passphrase of the private key.

***

### padding?

> `optional` **padding**: `"default"` \| `"pss-mgf1"`

Defined in: [src/lib/RSA/ModuleApi.ts:91](https://github.com/litert/signatures.js/blob/master/src/lib/RSA/ModuleApi.ts#L91)

The padding algorithm to use.

#### Default

```ts
'default'
```

***

### saltLength?

> `optional` **saltLength**: `number`

Defined in: [src/lib/RSA/ModuleApi.ts:96](https://github.com/litert/signatures.js/blob/master/src/lib/RSA/ModuleApi.ts#L96)

The salt length for PSS padding.
