# Changes Logs

## v4.0.0

- build(project): updated minimum node version to `18.0`, and use ES2022 features.

- add(test): added unit tests for the library.

- add(eddsa): Added EDDSA support.

    > The `require('node:stream/promises').pipeline` API is used in the `sign` and `verify` methods, which is only available since Node.js 15.0 and later.

- deprecate(hmac): removed the following algorithms, which are not recommended to use anymore

    - `md4`
    - `mdc2`
    - `whirlpool`

- deprecate(hash): removed the following algorithms, which are not recommended to use anymore

    - `md4`
    - `mdc2`
    - `whirlpool`

- deprecated(ecdsa): removed the custom API to sign and verify signatures in IEEE-P1363 format.

    > Since Node.js v12.15, the `crypto` module has supported the `ECDSA` signatures in IEEE-P1363 format, so the custom API is no longer needed. Especially now the library requires Node.js v18.0 or later.

## v3.1.0

- Added hash APIs supports.

## v3.0.0

- New simplified APIs.
- Added unit tests.
