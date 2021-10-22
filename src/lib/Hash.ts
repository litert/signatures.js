/**
 *  Copyright 2021 Angus.Fenying <fenying@litert.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import * as $Crypto from 'crypto';
import * as C from './Common';
import { Readable } from 'stream';

export type IAlgorithms = 'blake2b512' | 'blake2s256' | 'md4' | 'md5' |
'md5-sha1' | 'mdc2' | 'ripemd' | 'ripemd160' |
'rmd160' | 'sha1' | 'sha224' | 'sha256' |
'sha3-224' | 'sha3-256' | 'sha3-384' | 'sha3-512' |
'sha384' | 'sha512' | 'sha512-224' | 'sha512-256' |
'sm3' | 'whirlpool';

export function getSupportedAlgorithms(): IAlgorithms[] {

    return [
        'blake2b512', 'blake2s256', 'md4', 'md5',
        'md5-sha1', 'mdc2', 'ripemd', 'ripemd160',
        'rmd160', 'sha1', 'sha224', 'sha256',
        'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
        'sha384', 'sha512', 'sha512-224', 'sha512-256',
        'sm3', 'whirlpool'
    ];
}

export function hash(
    algo: IAlgorithms,
    message: Buffer | string,
): Buffer {

    return $Crypto.createHash(algo).update(message).digest();
}

export function hashStream(
    algo: IAlgorithms,
    message: Readable,
): Promise<Buffer> {

    return new Promise<Buffer>(function(resolve, reject): void {

        const hashStream = $Crypto.createHash(algo);

        message.pipe(hashStream).on('finish', () => {

            resolve(hashStream.read());

        }).once('error', reject);
    });
}

export function createHasher(algo: IAlgorithms): C.IHasher {

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

    return ret as any;
}
