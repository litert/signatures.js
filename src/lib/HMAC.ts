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

export function sign(
    algo: IAlgorithms,
    key: Buffer | string,
    message: Buffer | string,
): Buffer {

    return $Crypto.createHmac(algo, key).update(message).digest();
}

export function verify(
    algo: IAlgorithms,
    key: Buffer | string,
    message: Buffer | string,
    signature: Buffer,
): boolean {

    return sign(algo, key, message).compare(signature) === 0;
}

export function signStream(
    algo: IAlgorithms,
    key: Buffer | string,
    message: Readable,
): Promise<Buffer> {

    return new Promise<Buffer>(function(resolve, reject): void {

        const hashStream = $Crypto.createHmac(algo, key);

        message.pipe(hashStream).on('finish', () => {

            resolve(hashStream.read());

        }).once('error', reject);
    });
}

export async function verifyStream(
    algo: IAlgorithms,
    key: Buffer | string,
    message: Readable,
    signature: Buffer,
): Promise<boolean> {

    return signature.compare(await signStream(algo, key, message)) === 0;
}

export function createSigner(algo: IAlgorithms, key: Buffer | string): C.ISigner {

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

    return ret as any;
}
