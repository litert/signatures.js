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

import type { Readable } from 'node:stream';
import * as NodeCrypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import type * as dL from './Decl';
import * as eG from '../Errors';

function checkPrivateKey(privateKey: string | Buffer | NodeCrypto.KeyObject): void {

    if (privateKey instanceof NodeCrypto.KeyObject) {

        if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ec') {

            throw new eG.E_INVALID_PRIVATE_KEY({
                'keyAlgo': privateKey.asymmetricKeyType,
                'keyType': privateKey.type,
            });
        }
    }
}

function checkPublicKey(publicKey: string | Buffer | NodeCrypto.KeyObject): void {

    if (publicKey instanceof NodeCrypto.KeyObject) {

        if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ec') {

            throw new eG.E_INVALID_PUBLIC_KEY({
                'keyAlgo': publicKey.asymmetricKeyType,
                'keyType': publicKey.type,
            });
        }
    }
}

/**
 * Sign simple short data.
 *
 * @param algo         The digest/hash algorithm to be used.
 * @param privateKey   The private key to sign the data.
 * @param message      The payload to be signed.
 * @param opts         The options for signing.
 *
 * @returns Return a `Buffer` that contains the signature of the payload.
 */
export function sign(
    algo: dL.IAlgorithms,
    privateKey: string | Buffer | NodeCrypto.KeyObject,
    message: Buffer | string,
    opts?: dL.IEcdsaOptions,
): Buffer {

    checkPrivateKey(privateKey);

    try {

        return NodeCrypto.createSign(algo).update(message).sign({
            'key': privateKey as Buffer,
            'passphrase': opts?.keyPassphrase,
            'dsaEncoding': opts?.format ?? 'ieee-p1363'
        });
    }
    catch (e) {

        throw new eG.E_SIGN_FAILED({}, e);
    }
}

/**
 * Verify the signature of simple short data.
 *
 * @param algo         The digest/hash algorithm to be used.
 * @param publicKey    The public key to verify the signature.
 * @param message      The payload to be verified.
 * @param signature    The signature of the payload to be verified.
 * @param opts         The options for verification.
 *
 * @returns Return true if the signature is valid, otherwise false.
 */
export function verify(
    algo: dL.IAlgorithms,
    publicKey: string | Buffer | NodeCrypto.KeyObject,
    message: Buffer | string,
    signature: Buffer,
    opts?: dL.IEcdsaOptions,
): boolean {

    checkPublicKey(publicKey);

    try {

        return NodeCrypto.createVerify(algo).update(message).verify({
            key: publicKey as Buffer,
            dsaEncoding: opts?.format ?? 'ieee-p1363'
        }, signature);
    }
    catch (e) {

        throw new eG.E_VERIFY_FAILED({}, e);
    }
}

/**
 * Sign the input stream.
 *
 * @param algo         The digest/hash algorithm to be used.
 * @param privateKey   The private key to sign the data.
 * @param message      The input stream to be signed.
 * @param opts         The options for signing.
 *
 * @returns Return a promise that resolves to a `Buffer` that contains the signature of the input stream.
 */
export async function signStream(
    algo: dL.IAlgorithms,
    privateKey: string | Buffer | NodeCrypto.KeyObject,
    message: Readable,
    opts?: dL.IEcdsaOptions,
): Promise<Buffer> {

    checkPrivateKey(privateKey);

    try {

        const signer = NodeCrypto.createSign(algo);

        await pipeline(message, signer);

        return signer.sign({
            'key': privateKey as Buffer,
            'passphrase': opts?.keyPassphrase,
            'dsaEncoding': opts?.format ?? 'ieee-p1363'
        });
    }
    catch (e) {

        throw new eG.E_SIGN_FAILED({}, e);
    }
}

/**
 * Verify the signature of the input stream.
 *
 * @param algo         The digest/hash algorithm to be used.
 * @param publicKey    The public key to verify the signature.
 * @param message      The input stream to be verified.
 * @param signature    The signature of the input stream.
 * @param opts         The options for verification.
 *
 * @returns Return a promise that resolves to true if the signature is valid, otherwise false.
 */
export async function verifyStream(
    algo: dL.IAlgorithms,
    publicKey: string | Buffer | NodeCrypto.KeyObject,
    message: Readable,
    signature: Buffer,
    opts?: dL.IEcdsaOptions,
): Promise<boolean> {

    checkPublicKey(publicKey);

    try {

        const verifier = NodeCrypto.createVerify(algo);

        await pipeline(message, verifier);

        return verifier.verify({
            key: publicKey as Buffer,
            dsaEncoding: opts?.format ?? 'ieee-p1363'
        }, signature);
    }
    catch (e) {

        throw new eG.E_VERIFY_FAILED({}, e);
    }
}

/**
 * Get the list of supported digest/hash algorithms.
 */
export function getSupportedAlgorithms(): dL.IAlgorithms[] {

    return [
        'sha1',
        'sha224', 'sha256', 'sha384', 'sha512',
        'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'
    ];
}
