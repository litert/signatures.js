/**
 * Copyright 2025 Angus.Fenying <fenying@litert.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as NodeCrypto from 'node:crypto';
import type { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type * as dG from './Decl';

export type IAlgorithms = keyof {
    /* eslint-disable @typescript-eslint/naming-convention */
    'blake2b512': unknown;
    'blake2s256': unknown;
    'md5': unknown;
    'md5-sha1': unknown;
    'ripemd': unknown;
    'ripemd160': unknown;
    'rmd160': unknown;
    'sha1': unknown;
    'sha224': unknown;
    'sha256': unknown;
    'sha3-224': unknown;
    'sha3-256': unknown;
    'sha3-384': unknown;
    'sha3-512': unknown;
    'sha384': unknown;
    'sha512': unknown;
    'sha512-224': unknown;
    'sha512-256': unknown;
    'sm3': unknown;
    /* eslint-enable @typescript-eslint/naming-convention */
};

/**
 * Get the list of supported algorithms.
 */
export function getSupportedAlgorithms(): IAlgorithms[] {

    return [
        'blake2b512', 'blake2s256', 'md5', 'sm3',
        'md5-sha1', 'ripemd', 'ripemd160',
        'rmd160', 'sha1', 'sha224', 'sha256',
        'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
        'sha384', 'sha512', 'sha512-224', 'sha512-256',
    ];
}

/**
 * Sign a message with HMAC.
 *
 * @param algo      The digest/hash algorithm to use.
 * @param key       The key to sign the message with.
 * @param message   The payload to be signed.
 *
 * @returns Return a `Buffer` that contains the signature of the payload.
 */
export function sign(
    algo: IAlgorithms,
    key: Buffer | string,
    message: Buffer | string,
): Buffer {

    return NodeCrypto.createHmac(algo, key).update(message).digest();
}

/**
 * Verify the signature of a message with HMAC.
 *
 * @param algo          The digest/hash algorithm to use.
 * @param key           The key to verify the signature with.
 * @param message       The payload to be verified.
 * @param signature     The signature of payload to be verified.
 *
 * @returns Return `true` if the signature is valid, otherwise `false`.
 */
export function verify(
    algo: IAlgorithms,
    key: Buffer | string,
    message: Buffer | string,
    signature: Buffer,
): boolean {

    return sign(algo, key, message).compare(signature) === 0;
}

/**
 * Sign a message inside a stream with HMAC.
 *
 * @param algo      The digest/hash algorithm to use.
 * @param key       The key to sign the message with.
 * @param message   The payload to be signed, which is a readable stream.
 *
 * @returns Return a `Promise` that resolves to a `Buffer` containing the signature of the payload.
 */
export async function signStream(
    algo: IAlgorithms,
    key: Buffer | string,
    message: Readable,
): Promise<Buffer> {

    const hashStream = NodeCrypto.createHmac(algo, key);

    await pipeline(message, hashStream);

    return hashStream.read() as Buffer;
}

/**
 * Verify the signature of a message inside a stream with HMAC.
 *
 * @param algo          The digest/hash algorithm to use.
 * @param key           The key to verify the signature with.
 * @param message       The payload to be verified, which is a readable stream.
 * @param signature     The signature of payload to be verified, which is a `Buffer`.
 *
 * @returns Return a `Promise` that resolves to `true` if the signature is valid, otherwise `false`.
 */
export async function verifyStream(
    algo: IAlgorithms,
    key: Buffer | string,
    message: Readable,
    signature: Buffer,
): Promise<boolean> {

    return signature.equals(await signStream(algo, key, message));
}

/**
 * Create a signer object for HMAC, binding a specific digest/hash algorithm and key.
 *
 * @param algo  The digest/hash algorithm to use.
 * @param key   The key to sign the message with.
 *
 * @returns Return a signer object for HMAC.
 */
export function createSigner(algo: IAlgorithms, key: Buffer | string): dG.ISigner {

    const ret = {};

    Object.defineProperties(ret, {
        sign: {
            writable: false,
            configurable: false,
            value: (msg: Buffer | string): Buffer => sign(algo, key, msg)
        },
        signStream: {
            writable: false,
            configurable: false,
            value: (msg: Readable): Promise<Buffer> => signStream(algo, key, msg)
        },
        verify: {
            writable: false,
            configurable: false,
            value: (msg: Buffer | string, sign: Buffer): boolean => verify(algo, key, msg, sign)
        },
        verifyStream: {
            writable: false,
            configurable: false,
            value: (msg: Readable, sign: Buffer): Promise<boolean> => verifyStream(
                algo, key, msg, sign
            )
        },
        hashAlgorithm: {
            writable: false,
            configurable: false,
            value: algo
        },
        signAlgorithm: {
            writable: false,
            configurable: false,
            value: 'hmac'
        }
    });

    return ret as unknown as dG.ISigner;
}
