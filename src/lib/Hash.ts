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

/**
 * The supported hash/digest algorithms.
 */
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
        'blake2b512', 'blake2s256', 'sm3', 'md5',
        'md5-sha1', 'ripemd', 'ripemd160',
        'rmd160', 'sha1', 'sha224', 'sha256',
        'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
        'sha384', 'sha512', 'sha512-224', 'sha512-256',
    ];
}

/**
 * Calculate the hash/digest of a message using the specified algorithm.
 *
 * @param algo      The hash/digest algorithm to use.
 * @param message   The message to hash, can be a `Buffer` or a `string`.
 *
 * @returns A `Buffer` containing the hash/digest of the message.
 */
export function hash(algo: IAlgorithms, message: Buffer | string): Buffer {

    return NodeCrypto.createHash(algo).update(message).digest();
}

/**
 * Calculate the hash/digest of a stream using the specified algorithm.
 *
 * @param algo    The hash/digest algorithm to use.
 * @param message The stream to hash, must be a `Readable` stream.
 *
 * @returns A `Promise` that resolves to a `Buffer` containing the hash/digest of the stream.
 */
export async function hashStream(algo: IAlgorithms, message: Readable): Promise<Buffer> {

    const hashStream = NodeCrypto.createHash(algo);

    await pipeline(message, hashStream);

    return hashStream.read() as Buffer;
}

/**
 * Create a hasher object for the specified algorithm.
 *
 * @param algo  The hash/digest algorithm to use.
 *
 * @returns A hasher object that implements the `IHasher` interface.
 */
export function createHasher(algo: IAlgorithms): dG.IHasher {

    const ret = {};

    Object.defineProperties(ret, {
        hash: {
            writable: false,
            configurable: false,
            value: (msg: Buffer | string): Buffer => hash(algo, msg)
        },
        hashStream: {
            writable: false,
            configurable: false,
            value: (msg: Readable): Promise<Buffer> => hashStream(algo, msg)
        },
        algorithm: {
            writable: false,
            configurable: false,
            value: algo
        }
    });

    return ret as unknown as dG.IHasher;
}
