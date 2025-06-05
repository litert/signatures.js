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
import type * as dG from '../Decl';
import type * as mApi from './ModuleApi';
import * as eG from '../Errors';

interface ISignArgs {

    key: string;

    passphrase?: string | Buffer;

    padding?: number;

    saltLength?: number;
}

class RsaSigner implements dG.ISigner {

    public readonly hashAlgorithm!: mApi.IAlgorithms;

    public readonly signAlgorithm = 'rsa';

    private readonly _signArgs: ISignArgs | null = null;

    private readonly _verifyArgs: ISignArgs | null = null;

    public constructor(
        hashAlgo: mApi.IAlgorithms,
        publicKey: string | Buffer | NodeCrypto.KeyObject | null,
        privateKey: string | Buffer | NodeCrypto.KeyObject | null,
        opts?: mApi.IRsaOptions,
    ) {

        this.hashAlgorithm = hashAlgo;

        if (!publicKey && !privateKey) {

            throw new eG.E_NO_KEY_PROVIDED();
        }

        if (publicKey) {

            if (typeof publicKey === 'string' || publicKey instanceof Buffer) {

                try {

                    publicKey = NodeCrypto.createPublicKey({ key: publicKey });
                }
                catch (e) {

                    throw new eG.E_INVALID_PUBLIC_KEY({}, e);
                }
            }
            else if (publicKey instanceof NodeCrypto.KeyObject) {

                if (publicKey.type !== 'public') {

                    throw new eG.E_INVALID_PUBLIC_KEY({
                        keyAlgo: publicKey.asymmetricKeyType,
                        keyType: publicKey.type,
                    });
                }
            }
            else {

                throw new eG.E_INVALID_PUBLIC_KEY();
            }

            if (publicKey.asymmetricKeyType !== 'rsa') {

                throw new eG.E_INVALID_PUBLIC_KEY({ keyAlgo: publicKey.asymmetricKeyType });
            }

            this._verifyArgs = {
                key: publicKey as unknown as string,
                padding: opts?.padding === 'pss-mgf1' ?
                    NodeConst.RSA_PKCS1_PSS_PADDING :
                    NodeConst.RSA_PKCS1_PADDING,
                saltLength: opts?.saltLength,
            };
        }

        if (privateKey) {

            if (typeof privateKey === 'string' || privateKey instanceof Buffer) {

                try {
                    privateKey = NodeCrypto.createPrivateKey({
                        key: privateKey,
                        passphrase: opts?.keyPassphrase,
                    });
                }
                catch (e) {

                    throw new eG.E_INVALID_PRIVATE_KEY({}, e);
                }
            }
            else if (privateKey instanceof NodeCrypto.KeyObject) {

                if (privateKey.type !== 'private') {

                    throw new eG.E_INVALID_PRIVATE_KEY({
                        keyAlgo: privateKey.asymmetricKeyType,
                        keyType: privateKey.type,
                    });
                }
            }
            else {

                throw new eG.E_INVALID_PRIVATE_KEY();
            }

            if (privateKey.asymmetricKeyType !== 'rsa') {

                throw new eG.E_INVALID_PRIVATE_KEY({ keyAlgo: privateKey.asymmetricKeyType });
            }

            this._signArgs = {
                key: privateKey as unknown as string,
                passphrase: opts?.keyPassphrase,
                padding: opts?.padding === 'pss-mgf1' ?
                    NodeConst.RSA_PKCS1_PSS_PADDING :
                    NodeConst.RSA_PKCS1_PADDING,
                saltLength: opts?.saltLength,
            };
        }

        if (privateKey && publicKey) {

            const kLen = (privateKey as NodeCrypto.KeyObject).asymmetricKeyDetails!.modulusLength;
            const pLen = (publicKey as NodeCrypto.KeyObject).asymmetricKeyDetails!.modulusLength;
            if (kLen !== pLen) {

                throw new eG.E_KEY_PAIR_MISMATCH({
                    privateKeyLength: kLen,
                    publicKeyLength: pLen,
                });
            }
        }
    }

    public sign(data: string | Buffer): Buffer {

        if (!this._signArgs) {

            throw new eG.E_NO_PRIVATE_KEY();
        }

        try {

            return NodeCrypto.createSign(this.hashAlgorithm).update(data).sign(this._signArgs);
        }
        catch (e) {

            throw new eG.E_SIGN_FAILED({}, e);
        }
    }

    public verify(data: string | Buffer, signature: Buffer): boolean {

        if (!this._verifyArgs) {

            throw new eG.E_NO_PUBLIC_KEY();
        }

        try {

            return NodeCrypto.createVerify(this.hashAlgorithm)
                .update(data)
                .verify(this._verifyArgs, signature);
        }
        catch (e) {

            throw new eG.E_VERIFY_FAILED({}, e);
        }
    }

    public async signStream(message: Readable): Promise<Buffer> {

        if (!this._signArgs) {

            throw new eG.E_NO_PRIVATE_KEY();
        }

        try {

            const signer = NodeCrypto.createSign(this.hashAlgorithm);

            await pipeline(message, signer);

            return signer.sign(this._signArgs);
        }
        catch (e) {

            throw new eG.E_SIGN_FAILED({}, e);
        }
    }

    public async verifyStream(message: Readable, sig: Buffer): Promise<boolean> {

        if (!this._verifyArgs) {

            throw new eG.E_NO_PUBLIC_KEY();
        }

        try {

            const verifier = NodeCrypto.createVerify(this.hashAlgorithm);

            await pipeline(message, verifier);

            return verifier.verify(this._verifyArgs, sig);
        }
        catch (e) {

            throw new eG.E_VERIFY_FAILED({}, e);
        }
    }
}

/**
 * Create a new RSA signer instance.
 *
 * @param hashAlgo     The hash/digest algorithm to use.
 * @param publicKey    The public key to use for verification, or null to create a signer without a public key.
 * @param privateKey   The private key to use for signing, or null to create a verifier without a private key.
 * @param opts         Optional options for the signer, such as key passphrase.
 *
 * @returns A new RSA signer instance.
 *
 * @throws `E_NO_KEY_PROVIDED` If neither publicKey nor privateKey is provided.
 * @throws `E_INVALID_PUBLIC_KEY` If the provided public key is invalid or not of type 'rsa'.
 * @throws `E_INVALID_PRIVATE_KEY` If the provided private key is invalid or not of type 'rsa'.
 * @throws `E_KEY_TYPE_MISMATCH` If the types of the key pair do not match.
 */
export function createSigner(
    hashAlgo: mApi.IAlgorithms,
    publicKey: string | Buffer | NodeCrypto.KeyObject | null = null,
    privateKey: string | Buffer | NodeCrypto.KeyObject | null = null,
    opts?: mApi.IRsaOptions,
): dG.ISigner {

    return new RsaSigner(hashAlgo, publicKey, privateKey, opts);
}
