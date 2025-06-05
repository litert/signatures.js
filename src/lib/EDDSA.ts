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
import type * as dG from './Decl';
import * as eG from './Errors';

/**
 * The supported EDDSA algorithms.
 */
export type IAlgorithms = keyof {
    'ed25519': unknown;
    'ed448': unknown;
};

export interface IEddsaOptions {

    /**
     * The passphrase of the private key.
     */
    keyPassphrase?: string | Buffer;
}

/**
 * Sign the data with the given key.
 *
 * @param key   The key to sign the data with, can be a string, Buffer, or KeyObject.
 * @param data  The data to be signed, can be a string or Buffer.
 * @param opts  Optional options for signing, such as key passphrase.
 *
 * @returns The signature of the data as a Buffer.
 */
export function sign(key: string | Buffer | NodeCrypto.KeyObject, data: string | Buffer, opts?: IEddsaOptions): Buffer {

    try {

        if (opts?.keyPassphrase) {

            if (typeof key === 'string' || key instanceof Buffer) {

                key = NodeCrypto.createPrivateKey({ key: key, passphrase: opts.keyPassphrase });
            }
        }

        return NodeCrypto.sign(null, typeof data === 'string' ? Buffer.from(data) : data, key);
    }
    catch (e) {

        throw new eG.E_SIGN_FAILED({}, e);
    }
}

/**
 * Verify the signature of the data with the given key.
 *
 * @param key        The key to verify the signature with, can be a string, Buffer, or KeyObject.
 * @param data       The data to be verified, can be a string or Buffer.
 * @param signature  The signature of the data to be verified, must be a Buffer.
 *
 * @returns `true` if the signature is valid, `false` otherwise.
 */
export function verify(
    key: string | Buffer | NodeCrypto.KeyObject,
    data: string | Buffer,
    signature: Buffer,
): boolean {

    try {

        return NodeCrypto.verify(null, typeof data === 'string' ? Buffer.from(data) : data, key, signature);
    }
    catch (e) {

        throw new eG.E_VERIFY_FAILED({}, e);
    }
}

/**
 * Create a new EDDSA signer instance.
 *
 * @param publicKey    The public key to use for verification, or null to create a signer without a public key.
 * @param privateKey   The private key to use for signing, or null to create a verifier without a private key.
 * @param keyType      The key algorithm to use, or null to use the algorithm of the key.
 * @param opts         Optional options for the signer, such as key passphrase.
 *
 * @returns A new EDDSA signer instance.
 *
 * @throws `E_NO_KEY_PROVIDED` If neither publicKey nor privateKey is provided.
 * @throws `E_INVALID_PUBLIC_KEY` If the provided public key is invalid or not of type 'ed25519' or 'ed448'.
 * @throws `E_INVALID_PRIVATE_KEY` If the provided private key is invalid or not of type 'ed25519' or 'ed448'.
 * @throws `E_KEY_TYPE_MISMATCH` If the types of the key pair do not match.
 */
export function createSigner(
    publicKey: string | Buffer | NodeCrypto.KeyObject | null = null,
    privateKey: string | Buffer | NodeCrypto.KeyObject | null = null,
    keyType: IAlgorithms | null = null,
    opts?: IEddsaOptions,
): dG.ISigner {

    return new EddsaSigner(publicKey, privateKey, keyType, opts);
}

class EddsaSigner implements dG.ISigner {

    public readonly hashAlgorithm!: IAlgorithms;

    public readonly signAlgorithm = 'eddsa';

    private readonly _key: NodeCrypto.KeyObject | null = null;

    private readonly _pub: NodeCrypto.KeyObject | null = null;

    public constructor(
        publicKey: string | Buffer | NodeCrypto.KeyObject | null,
        privateKey: string | Buffer | NodeCrypto.KeyObject | null,
        hashAlgo: IAlgorithms | null = null,
        opts?: IEddsaOptions,
    ) {

        if (!publicKey && !privateKey) {

            throw new eG.E_NO_KEY_PROVIDED();
        }

        if (publicKey) {

            if (typeof publicKey === 'string' || publicKey instanceof Buffer) {

                try {
                    this._pub = NodeCrypto.createPublicKey({ key: publicKey });
                }
                catch (e) {

                    throw new eG.E_INVALID_PUBLIC_KEY({}, e);
                }
            }
            else if (publicKey instanceof NodeCrypto.KeyObject && publicKey.type === 'public') {

                this._pub = publicKey;
            }
            else {

                throw new eG.E_INVALID_PUBLIC_KEY();
            }

            switch (this._pub.asymmetricKeyType) {
                case 'ed25519':
                case 'ed448':
                    break;
                default:
                    throw new eG.E_INVALID_PUBLIC_KEY({
                        keyAlgo: this._pub.asymmetricKeyType,
                    });
            }

            this.hashAlgorithm = this._pub.asymmetricKeyType;
        }

        if (privateKey) {

            if (typeof privateKey === 'string' || privateKey instanceof Buffer) {

                try {
                    this._key = NodeCrypto.createPrivateKey({
                        key: privateKey,
                        passphrase: opts?.keyPassphrase,
                    });
                }
                catch (e) {

                    throw new eG.E_INVALID_PRIVATE_KEY({}, e);
                }
            }
            else if (privateKey instanceof NodeCrypto.KeyObject && privateKey.type === 'private') {

                this._key = privateKey;
            }
            else {

                throw new eG.E_INVALID_PRIVATE_KEY();
            }

            switch (this._key.asymmetricKeyType) {
                case 'ed25519':
                case 'ed448':
                    break;
                default:
                    throw new eG.E_INVALID_PRIVATE_KEY({
                        keyAlgo: this._key.asymmetricKeyType,
                    });
            }

            this.hashAlgorithm = this._key.asymmetricKeyType;
        }

        hashAlgo ??= this.hashAlgorithm;

        if ((this._pub?.asymmetricKeyType ?? hashAlgo) !== hashAlgo) {

            throw new eG.E_KEY_PAIR_MISMATCH({
                keyAlgo: this._pub?.asymmetricKeyType,
                expectedAlgo: hashAlgo,
            });
        }

        if ((this._key?.asymmetricKeyType ?? hashAlgo) !== hashAlgo) {

            throw new eG.E_KEY_PAIR_MISMATCH({
                keyAlgo: this._key?.asymmetricKeyType,
                expectedAlgo: hashAlgo,
            });
        }
    }

    public sign(data: string | Buffer): Buffer {

        if (!this._key) {

            throw new eG.E_NO_PRIVATE_KEY();
        }

        try {

            return NodeCrypto.sign(
                null,
                typeof data === 'string' ? Buffer.from(data) : data,
                this._key,
            );
        }
        catch (e) {

            throw new eG.E_SIGN_FAILED({}, e);
        }
    }

    public verify(data: string | Buffer, signature: Buffer): boolean {

        if (!this._pub) {

            throw new eG.E_NO_PUBLIC_KEY();
        }

        try {

            return NodeCrypto.verify(
                null,
                typeof data === 'string' ? Buffer.from(data) : data,
                this._pub,
                signature,
            );
        }
        catch (e) {

            throw new eG.E_VERIFY_FAILED({}, e);
        }
    }

    public signStream(): Promise<Buffer> {

        return Promise.reject(new eG.E_NOT_IMPLEMENTED());
    }

    public verifyStream(): Promise<boolean> {

        return Promise.reject(new eG.E_NOT_IMPLEMENTED());
    }
}
