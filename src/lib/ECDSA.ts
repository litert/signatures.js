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
import { Readable } from 'stream';

export type IAlgorithms = 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512' |
'sha3-224' | 'sha3-256' | 'sha3-384' | 'sha3-512';

export function getSupportedAlgorithms(): IAlgorithms[] {

    return [
        'sha1',
        'sha224', 'sha256', 'sha384', 'sha512',
        'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'
    ];
}

export interface IECDSAOptions {

    keyPassphrase?: string | Buffer;

    /**
     * The output format of signature.
     *
     * @default 'ieee-p1363
     */
    format?: 'ieee-p1363' | 'der';
}

/**
 * This method helps recover R/S to the DER form, with padding if necessary.
 *
 * @param {Buffer} input The R/S to be recovered.
 */
function ecdsaRecoverRS(input: Buffer): Buffer {

    let start: number = 0;

    while (input[start] === 0) {
        start++;
    }

    if (input[start] <= 0x7F) {

        return input.slice(start);
    }

    if (start > 0) {

        return input.slice(start - 1);
    }

    const output = Buffer.alloc(input.length + 1);

    input.copy(output, 1);
    output[0] = 0;

    return output;
}

const UINT32_READ_BUFFER = Buffer.alloc(4);

function derReadLength(bf: Buffer, offset: number): [number, number] {

    let length = bf[offset++];

    /**
     * Using long form length if it's larger than 0x7F.
     *
     * @see https://stackoverflow.com/a/47099047
     */
    if (length > 0x7F) {

        const llen = length & 0x7F;
        UINT32_READ_BUFFER.fill(0);
        bf.copy(UINT32_READ_BUFFER, 4 - llen, offset, offset + llen);
        length = UINT32_READ_BUFFER.readUInt32BE(0);
        offset += llen;
    }

    return [length, offset];
}

function removePrependZero(bf: Buffer): Buffer {

    let i = 0;

    for (; i < bf.length && !bf[i]; i++);

    if (i === bf.length) {

        return bf.slice(0, 1);
    }

    return bf.slice(i);
}

/**
 * This method helps transform signature from DER format to IEEE-P1363 format.
 *
 * @param {Buffer} der  The signature in DER format.
 *
 * @returns {Buffer}  Return the signature in IEEE-P1363 format.
 */
export function derToP1363(der: Buffer): Buffer {

    let ctx: [number, number] = [0, 0];

    let [, offset] = derReadLength(der, 1);

    ctx = derReadLength(der, ++offset);
    offset = ctx[1];

    const r = removePrependZero(der.slice(offset, offset + ctx[0]));

    offset += ctx[0];

    ctx = derReadLength(der, ++offset);

    offset = ctx[1];

    const s = removePrependZero(der.slice(offset, offset + ctx[0]));

    if (s.length > r.length) {

        return Buffer.concat([Buffer.alloc(s.length - r.length), r, s]);
    }
    else if (r.length > s.length) {

        return Buffer.concat([r, Buffer.alloc(r.length - s.length), s]);
    }

    return Buffer.concat([r, s]);
}

/**
 * This method helps transform signature from DER format to IEEE-P1363 format.
 *
 * @param {Buffer} p1363   The signature in IEEE-P1363 format.
 *
 * @returns {Buffer}  Return the signature in DER format.
 */
export function p1363ToDER(p1363: Buffer): Buffer {

    let base = 0;

    const hL = p1363.length / 2;

    /**
     * Prepend a 0x00 byte to R or S if it starts with a byte larger than 0x79.
     *
     * Because a integer starts with a byte larger than 0x79 means negative.
     *
     * @see https://bitcointalk.org/index.php?topic=215205.msg2258789#msg2258789
     */
    const r = ecdsaRecoverRS(p1363.slice(0, hL));
    const s = ecdsaRecoverRS(p1363.slice(hL));

    /**
     * Using long form length if it's larger than 0x7F.
     *
     * @see https://stackoverflow.com/a/47099047
     */
    if (4 + s.length + r.length > 0x7f) {

        base++;
    }

    const der = Buffer.alloc(base + 6 + s.length + r.length);

    if (base) {

        der[1] = 0x81;
    }

    der[0] = 0x30;
    der[base + 1] = 4 + s.length + r.length;
    der[base + r.length + 4] = der[base + 2] = 0x02;
    der[base + r.length + 5] = s.length;
    der[base + 3] = r.length;
    r.copy(der, base + 4);
    s.copy(der, base + 6 + r.length);

    return der;
}

let shouldUseNativeP1363 = false;

function signWithNativeP1363(
    algo: IAlgorithms,
    privateKey: string | Buffer,
    message: Buffer | string,
    opts?: IECDSAOptions,
): Buffer {

    if (algo === 'sha224' || algo === 'sha3-224') {

        return signWithCustomP1363(algo, privateKey, message, opts);
    }

    const hasher = $Crypto.createSign(algo);

    return hasher.update(message).sign({
        'key': privateKey,
        'passphrase': opts?.keyPassphrase,
        'dsaEncoding': opts?.format ?? 'ieee-p1363'
    });
}

function signWithCustomP1363(
    algo: IAlgorithms,
    privateKey: string | Buffer,
    message: Buffer | string,
    opts?: IECDSAOptions,
): Buffer {

    const hasher = $Crypto.createSign(algo);

    const ret = hasher.update(message).sign({
        'key': privateKey,
        'passphrase': opts?.keyPassphrase
    });

    if (opts?.format !== 'der') {

        return derToP1363(ret);
    }

    return ret;
}

export let sign = signWithCustomP1363;

function verifyWithCustomP1363(
    algo: IAlgorithms,
    publicKey: string | Buffer,
    message: Buffer | string,
    signature: Buffer,
    opts?: IECDSAOptions,
): boolean {

    const hasher = $Crypto.createVerify(algo);

    if (opts?.format !== 'der') {
        signature = p1363ToDER(signature);
    }

    return hasher.update(message).verify(
        publicKey,
        signature
    );
}

function verifyWithNativeP1363(
    algo: IAlgorithms,
    publicKey: string | Buffer,
    message: Buffer | string,
    signature: Buffer,
    opts?: IECDSAOptions,
): boolean {

    if (algo === 'sha224' || algo === 'sha3-224') {

        return verifyWithCustomP1363(algo, publicKey, message, signature, opts);
    }

    const hasher = $Crypto.createVerify(algo);

    return hasher.update(message).verify({
        key: publicKey,
        dsaEncoding: opts?.format
    }, signature);
}

export let verify = verifyWithCustomP1363;

export let signStream = signStreamWithCustomP1363;

export function signStreamWithNativeP1363(
    algo: IAlgorithms,
    privateKey: string | Buffer,
    message: Readable,
    opts?: IECDSAOptions,
): Promise<Buffer> {

    if (algo === 'sha224' || algo === 'sha3-224') {

        return signStreamWithCustomP1363(algo, privateKey, message, opts);
    }

    const hasher = $Crypto.createSign(algo);

    return new Promise<Buffer>(function(resolve, reject): void {

        message.pipe(hasher).on('finish', function() {

            try {

                resolve(hasher.sign({
                    'key': privateKey,
                    'passphrase': opts?.keyPassphrase,
                    'dsaEncoding': opts?.format
                }));
            }
            catch (e) {

                reject(e);
            }

        }).once('error', reject);
    });
}

export function signStreamWithCustomP1363(
    algo: IAlgorithms,
    privateKey: string | Buffer,
    message: Readable,
    opts?: IECDSAOptions,
): Promise<Buffer> {

    const hasher = $Crypto.createSign(algo);

    return new Promise<Buffer>(function(resolve, reject): void {

        message.pipe(hasher).on('finish', function() {

            try {

                const ret = hasher.sign({
                    'key': privateKey,
                    'passphrase': opts?.keyPassphrase
                });

                if (opts?.format === 'ieee-p1363') {

                    resolve(derToP1363(ret));
                    return;
                }

                resolve(ret);
            }
            catch (e) {

                reject(e);
            }

        }).once('error', reject);
    });
}

export let verifyStream = verifyStreamWithCustomP1363;

export function verifyStreamWithNativeP1363(
    algo: IAlgorithms,
    publicKey: string | Buffer,
    message: Readable,
    signature: Buffer,
    opts?: IECDSAOptions,
): Promise<boolean> {

    if (algo === 'sha224' || algo === 'sha3-224') {

        return verifyStreamWithCustomP1363(algo, publicKey, message, signature, opts);
    }

    const hasher = $Crypto.createVerify(algo);

    return new Promise<boolean>(function(resolve, reject): void {

        message.pipe(hasher).on('finish', function() {

            try {

                resolve(hasher.verify({
                    key: publicKey,
                    dsaEncoding: opts?.format ?? 'ieee-p1363'
                }, signature));
            }
            catch (e) {

                reject(e);
            }

        }).once('error', reject);
    });
}

export function verifyStreamWithCustomP1363(
    algo: IAlgorithms,
    publicKey: string | Buffer,
    message: Readable,
    signature: Buffer,
    opts?: IECDSAOptions,
): Promise<boolean> {

    const hasher = $Crypto.createVerify(algo);

    return new Promise<boolean>(function(resolve, reject): void {

        message.pipe(hasher).on('finish', function() {

            try {

                if (opts?.format !== 'der') {
                    signature = p1363ToDER(signature);
                }

                resolve(hasher.verify(publicKey, signature));
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
    opts?: IECDSAOptions,
): C.ISigner {

    return (function(sign, verify, signStream, verifyStream): C.ISigner {

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

    })(sign, verify, signStream, verifyStream);
}

/**
 * Tell if current version of NodeJS supports native IEEE-P1363 formatter.
 */
export function hasNativeP1363Support(): boolean {

    return parseFloat(process.versions.node.split('.').slice(0, 2).join('.')) > 12.15;
}

/**
 * Switch between NodeJS native IEEE-P1363 formater and custom one.
 *
 * > Use custom one by default.
 *
 * @param enabled Set to true to use native formatter.
 *
 * @returns Return true if native formatter is supported and switched successfully.
 */
export function enableNativeP1363(enabled: boolean = true): boolean {

    if (!hasNativeP1363Support()) {

        return false;
    }

    shouldUseNativeP1363 = enabled;

    if (shouldUseNativeP1363) {

        sign = signWithNativeP1363;
        verify = verifyWithNativeP1363;
        signStream = signStreamWithNativeP1363;
        verifyStream = verifyStreamWithNativeP1363;
    }
    else {

        sign = signWithCustomP1363;
        verify = verifyWithCustomP1363;
        signStream = signStreamWithCustomP1363;
        verifyStream = verifyStreamWithCustomP1363;
    }

    return true;
}

/**
 * Tell if it's using NodeJS native IEEE-P1363 formatter or not.
 */
export function isNativeP1363Enabled(): boolean {

    return shouldUseNativeP1363;
}
