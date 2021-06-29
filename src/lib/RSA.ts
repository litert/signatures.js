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

import * as C from './Common';
import * as $Crypto from 'crypto';
import * as $Constants from 'constants';
import { Readable } from 'stream';

export type IAlgorithms = 'sha1' | 'md5' | 'ripemd160' |
'sha224' | 'sha256' | 'sha384' | 'sha512' |
'sha3-224' | 'sha3-256' | 'sha3-384' | 'sha3-512';

export function getSupportedAlgorithms(): IAlgorithms[] {

    return [
        'sha1', 'md5', 'ripemd160',
        'sha224', 'sha256', 'sha384', 'sha512',
        'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
    ];
}

export interface IRSAOptions {

    keyPassphrase?: string | Buffer;

    padding?: 'pss-mgf1' | 'default';
}

export function sign(
    algo: IAlgorithms,
    privateKey: string | Buffer,
    message: Buffer | string,
    opts?: IRSAOptions,
): Buffer {

    const hasher = $Crypto.createSign(algo);

    return hasher.update(message).sign({
        'key': privateKey,
        'passphrase': opts?.keyPassphrase,
        'padding': opts?.padding === 'pss-mgf1' ?
            $Constants.RSA_PKCS1_PSS_PADDING :
            $Constants.RSA_PKCS1_PADDING
    });
}

export function verify(
    algo: IAlgorithms,
    publicKey: string | Buffer,
    message: Buffer | string,
    signature: Buffer,
    opts?: IRSAOptions,
): boolean {

    const hasher = $Crypto.createVerify(algo);

    return hasher.update(message).verify({
        'key': publicKey,
        'padding': opts?.padding === 'pss-mgf1' ?
            $Constants.RSA_PKCS1_PSS_PADDING :
            $Constants.RSA_PKCS1_PADDING
    }, signature);
}

export function signStream(
    algo: IAlgorithms,
    privateKey: string | Buffer,
    message: Readable,
    opts?: IRSAOptions,
): Promise<Buffer> {

    const hasher = $Crypto.createSign(algo);

    return new Promise<Buffer>(function(resolve, reject): void {

        message.pipe(hasher).on('finish', function() {

            try {

                resolve(hasher.sign({
                    'key': privateKey,
                    'passphrase': opts?.keyPassphrase,
                    'padding': opts?.padding === 'pss-mgf1' ?
                        $Constants.RSA_PKCS1_PSS_PADDING :
                        $Constants.RSA_PKCS1_PADDING
                }));
            }
            catch (e) {

                reject(e);
            }

        }).once('error', reject);
    });
}

export function verifyStream(
    algo: IAlgorithms,
    publicKey: string | Buffer,
    message: Readable,
    signature: Buffer,
    opts?: IRSAOptions,
): Promise<boolean> {

    const hasher = $Crypto.createVerify(algo);

    return new Promise<boolean>(function(resolve, reject): void {

        message.pipe(hasher).on('finish', function() {

            try {

                resolve(hasher.verify({
                    'key': publicKey,
                    'padding': opts?.padding === 'pss-mgf1' ?
                        $Constants.RSA_PKCS1_PSS_PADDING :
                        $Constants.RSA_PKCS1_PADDING
                }, signature));
            }
            catch (e) {

                reject(e);
            }

        }).once('error', reject);
    });
}

export function createSigner(
    algo: IAlgorithms,
    publicKey: Buffer | string,
    privateKey: Buffer | string,
    opts?: IRSAOptions
): C.ISigner {

    const ret = {};

    Object.defineProperties(ret, {
        sign: {
            writable: false,
            configurable: false,
            value: (msg: Buffer | string): Buffer => sign(algo, privateKey, msg, opts)
        },
        signStream: {
            writable: false,
            configurable: false,
            value: (msg: Readable): Promise<Buffer> => signStream(algo, privateKey, msg, opts)
        },
        verify: {
            writable: false,
            configurable: false,
            value: (msg: Buffer | string, sign: Buffer): boolean => verify(
                algo, publicKey, msg, sign, opts
            )
        },
        verifyStream: {
            writable: false,
            configurable: false,
            value: (msg: Readable, sign: Buffer): Promise<boolean> => verifyStream(
                algo, publicKey, msg, sign, opts
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
            value: 'ecdsa'
        }
    });
    return ret as any;
}
