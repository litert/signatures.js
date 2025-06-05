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
import * as NodeConst from 'node:constants';
import type { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import * as eG from '../Errors';

function checkPrivateKey(privateKey: string | Buffer | NodeCrypto.KeyObject): void {

    if (privateKey instanceof NodeCrypto.KeyObject) {

        if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'rsa') {

            throw new eG.E_INVALID_PRIVATE_KEY({
                'keyAlgo': privateKey.asymmetricKeyType,
                'keyType': privateKey.type,
            });
        }
    }
}

function checkPublicKey(publicKey: string | Buffer | NodeCrypto.KeyObject): void {

    if (publicKey instanceof NodeCrypto.KeyObject) {

        if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'rsa') {

            throw new eG.E_INVALID_PUBLIC_KEY({
                'keyAlgo': publicKey.asymmetricKeyType,
                'keyType': publicKey.type,
            });
        }
    }
}

export type IAlgorithms = keyof {
    /* eslint-disable @typescript-eslint/naming-convention */
    'sha1': unknown;
    'md5': unknown;
    'ripemd160': unknown;
    'sha224': unknown;
    'sha256': unknown;
    'sha384': unknown;
    'sha512': unknown;
    'sha3-224': unknown;
    'sha3-256': unknown;
    'sha3-384': unknown;
    'sha3-512': unknown;
    /* eslint-enable @typescript-eslint/naming-convention */
};

/**
 * Get the list of supported hash/digest algorithms.
 */
export function getSupportedAlgorithms(): IAlgorithms[] {

    return [
        'sha1', 'md5', 'ripemd160',
        'sha224', 'sha256', 'sha384', 'sha512',
        'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
    ];
}

export interface IRsaOptions {

    /**
     * The passphrase of the private key.
     */
    keyPassphrase?: string | Buffer;

    /**
     * The padding algorithm to use.
     *
     * @default 'default'
     */
    padding?: 'pss-mgf1' | 'default';

    /**
     * The salt length for PSS padding.
     */
    saltLength?: number;
}

/**
 * Hash a message with the specified hash/digest algorithm.
 *
 * @param algo          The hash/digest algorithm to use.
 * @param privateKey    The private key to sign the message with.
 * @param message       The payload to be signed, can be a `Buffer` or a `string`.
 * @param opts          The options for signing, including the passphrase of the private key and the padding algorithm.
 *
 * @returns Return a `Buffer` that contains the signature of the payload.
 *
 * @throws `E_INVALID_PRIVATE_KEY` If the private key is not a valid RSA private key.
 * @throws `E_SIGN_FAILED` If the signing fails.
 */
export function sign(
    algo: IAlgorithms,
    privateKey: string | Buffer | NodeCrypto.KeyObject,
    message: Buffer | string,
    opts?: IRsaOptions,
): Buffer {

    checkPrivateKey(privateKey);

    try {

        return (NodeCrypto.createSign(algo)).update(message).sign({
            'key': privateKey as Buffer,
            'passphrase': opts?.keyPassphrase,
            'padding': opts?.padding === 'pss-mgf1' ?
                NodeConst.RSA_PKCS1_PSS_PADDING :
                NodeConst.RSA_PKCS1_PADDING,
            'saltLength': opts?.saltLength,
        });
    }
    catch (e) {

        throw new eG.E_SIGN_FAILED({}, e);
    }
}

/**
 * Verify a message with the specified hash/digest algorithm.
 *
 * @param algo      The hash/digest algorithm to use.
 * @param publicKey The public key to verify the message with.
 * @param message   The payload to be verified, can be a `Buffer` or a `string`.
 * @param signature The signature of the payload to be verified, must be a `Buffer`.
 * @param opts      The options for verification, including the padding algorithm.
 *
 * @returns Return true if the signature is valid, otherwise false.
 *
 * @throws `E_INVALID_PUBLIC_KEY` If the public key is not a valid RSA public key.
 * @throws `E_VERIFY_FAILED` If the verification fails.
 */
export function verify(
    algo: IAlgorithms,
    publicKey: string | Buffer | NodeCrypto.KeyObject,
    message: Buffer | string,
    signature: Buffer,
    opts?: IRsaOptions,
): boolean {

    checkPublicKey(publicKey);

    try {

        return NodeCrypto.createVerify(algo).update(message).verify({
            'key': publicKey as Buffer,
            'padding': opts?.padding === 'pss-mgf1' ?
                NodeConst.RSA_PKCS1_PSS_PADDING :
                NodeConst.RSA_PKCS1_PADDING,
            'saltLength': opts?.saltLength,
        }, signature);
    }
    catch (e) {

        throw new eG.E_VERIFY_FAILED({}, e);
    }
}

/**
 * Sign a message inside a stream with the specified hash/digest algorithm.
 *
 * @param algo       The hash/digest algorithm to use.
 * @param privateKey The private key to sign the message with.
 * @param message    The payload to be signed, which is a readable stream.
 * @param opts       The options for signing, including the passphrase of the private key and the padding algorithm.
 *
 * @returns Return a `Promise` that resolves to a `Buffer` containing the signature of the payload.
 *
 * @throws `E_INVALID_PRIVATE_KEY` If the private key is not a valid RSA private key.
 * @throws `E_SIGN_FAILED` If the signing fails.
 */
export async function signStream(
    algo: IAlgorithms,
    privateKey: string | Buffer | NodeCrypto.KeyObject,
    message: Readable,
    opts?: IRsaOptions,
): Promise<Buffer> {

    checkPrivateKey(privateKey);

    try {

        const signer = NodeCrypto.createSign(algo);

        await pipeline(message, signer);

        return signer.sign({
            'key': privateKey as Buffer,
            'passphrase': opts?.keyPassphrase,
            'padding': opts?.padding === 'pss-mgf1' ?
                NodeConst.RSA_PKCS1_PSS_PADDING :
                NodeConst.RSA_PKCS1_PADDING,
            'saltLength': opts?.saltLength,
        });
    }
    catch (e) {

        throw new eG.E_SIGN_FAILED({}, e);
    }
}

/**
 * Verify the signature of a message inside a stream with the specified hash/digest algorithm.
 *
 * @param algo      The hash/digest algorithm to use.
 * @param publicKey The public key to verify the message with.
 * @param message   The payload to be verified, which is a readable stream.
 * @param signature The signature of the payload to be verified, must be a `Buffer`.
 * @param opts      The options for verification, including the padding algorithm.
 *
 * @returns Return a `Promise` that resolves to true if the signature is valid, otherwise false.
 *
 * @throws `E_INVALID_PUBLIC_KEY` If the public key is not a valid RSA public key.
 * @throws `E_VERIFY_FAILED` If the verification fails.
 */
export async function verifyStream(
    algo: IAlgorithms,
    publicKey: string | Buffer | NodeCrypto.KeyObject,
    message: Readable,
    signature: Buffer,
    opts?: IRsaOptions,
): Promise<boolean> {

    checkPublicKey(publicKey);

    try {

        const verifier = NodeCrypto.createVerify(algo);

        await pipeline(message, verifier);

        return verifier.verify({
            'key': publicKey as Buffer,
            'padding': opts?.padding === 'pss-mgf1' ?
                NodeConst.RSA_PKCS1_PSS_PADDING :
                NodeConst.RSA_PKCS1_PADDING,
            'saltLength': opts?.saltLength,
        }, signature);
    }
    catch (e) {

        throw new eG.E_VERIFY_FAILED({}, e);
    }
}
