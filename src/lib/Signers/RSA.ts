/**
 *  Copyright 2020 Angus.Fenying <fenying@litert.org>
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

import { Readable } from "stream";
import * as $Crypto from "crypto";
import { IAsymmetricKey, ERSAPadding } from "../Common";
import * as $Constants from "constants";
import * as C from "../Common";
import * as Enc from "@litert/encodings";
import * as I from "./Internal";

export type TAlgorithms = "sha1" | "sha224" | "sha256" |
                            "sha384" | "sha512" | "whirlpool" |
                            "md5" | "md4";

export interface IOptions {

    padding: ERSAPadding;
}

/**
 * Sign a signature by RSA.
 *
 * @param algo          The hash algorithm to be used.
 * @param message       The message to be signed.
 * @param privKey       The private key of RSA.
 * @param opts          The options of RSA.
 */
export const sign: C.ISignerFn<TAlgorithms, IAsymmetricKey, IOptions> = function(
    algo: TAlgorithms,
    message: string | Buffer | Readable,
    privKey: IAsymmetricKey,
    opts?: IOptions
): any {

    const hasher = $Crypto.createSign(algo);

    if (message instanceof Buffer || typeof message === "string") {

        return hasher.update(message).sign({
            "key": privKey.key as any,
            "passphrase": privKey.password,
            "padding": opts && opts.padding === ERSAPadding.PSS_MGF1 ?
                $Constants.RSA_PKCS1_PSS_PADDING :
                $Constants.RSA_PKCS1_PADDING
        });
    }
    else {

        return new Promise<Buffer>(function(resolve, reject): void {
            message.pipe(hasher).on("finish", () => {

                try {

                    resolve(hasher.sign({
                        "key": privKey.key as any,
                        "passphrase": privKey.password,
                        "padding": opts && opts.padding === ERSAPadding.PSS_MGF1 ?
                            $Constants.RSA_PKCS1_PSS_PADDING :
                            $Constants.RSA_PKCS1_PADDING
                    }));
                }
                catch (e) {

                    reject(e);
                }

            }).once("error", reject);
        });
    }
};

/**
 * Verify a signature by RSA.
 *
 * @param algo          The hash algorithm to be used.
 * @param message       The message to be verified.
 * @param signature     The signature of message to be verified.
 * @param pubKey        The public key of RSA.
 * @param opts          The options of RSA.
 */
export const verify: C.IVerifierFn<TAlgorithms, IOptions> = function(
    algo: TAlgorithms,
    message: string | Buffer | Readable,
    signature: Buffer,
    pubKey: Buffer | string,
    opts?: IOptions
): any {

    const hasher = $Crypto.createVerify(algo);

    if (message instanceof Buffer || typeof message === "string") {

        return hasher.update(message).verify({
            "key": pubKey as any,
            "padding": opts && opts.padding === ERSAPadding.PSS_MGF1 ?
                $Constants.RSA_PKCS1_PSS_PADDING :
                $Constants.RSA_PKCS1_PADDING
        }, signature);
    }
    else {

        return new Promise<boolean>(function(resolve, reject): void {
            message.pipe(hasher).on("finish", () => {

                try {
                    resolve(
                        hasher.verify({
                            "key": pubKey as any,
                            "padding": opts && opts.padding === ERSAPadding.PSS_MGF1 ?
                                $Constants.RSA_PKCS1_PSS_PADDING :
                                $Constants.RSA_PKCS1_PADDING
                        }, signature)
                    );
                }
                catch (e) {

                    reject(e);
                }

            }).once("error", reject);
        });
    }
};

/**
 * Get the names of supported hash algorithms for RSA.
 */
export function getSupportedAlgorithms(): TAlgorithms[] {

    return [
        "sha1", "sha224", "sha256", "sha384",
        "sha512", "md5", "md4"
    ];
}

/**
 * Create an RSA signer (also a verifier).
 *
 * @param hashAlgorithm     The HASH algorithm to be used in signing.
 * @param pubKey            The public key for verifying.
 * @param privKey           The private ket for signing.
 * @param padding           The padding mode of RSA. [Default: PKCS1-v1.5]
 * @param output            The encoding for signature output and input. [Default: Buffer]
 */
export function createSigner<T extends C.TSignature = "buffer">(
    hashAlgorithm: TAlgorithms,
    pubKey: string | Buffer,
    privKey: string | Buffer | C.TAsymmetricKey,
    padding: C.ERSAPadding = C.ERSAPadding.PKCS1_V1_5,
    output?: T
): C.ISigner<T> {

    if (!output) {

        output = "buffer" as any;
    }

    let signaturePreprocess: string = "";

    if (output !== "buffer") {

        signaturePreprocess = I._getDecoderName(output as any, "Enc", "signature");
    }

    if (privKey instanceof Buffer || typeof privKey === "string") {

        privKey = {
            key: privKey,
            password: ""
        };
    }

    return (new Function(`Enc`, "_sign", "_verify", "privKey", "pubKey", `

        const ret = {
            sign(data) {

                const result = _sign("${hashAlgorithm}", data, privKey, {"padding": ${padding}});

                if (result instanceof Promise) {

                    return result.then((x) => ${I._getEncoderName(output as string, "Enc", "x")})
                }

                return ${I._getEncoderName(output as string, "Enc", "result")};
            },
            verify(data, signature) {

                ${signaturePreprocess}

                return _verify("${hashAlgorithm}", data, signature, pubKey, {"padding": ${padding}});
            }
        };

        Object.defineProperties(ret, {
            "signAlgorithm": {
                "writtable": false,
                "value": "${padding === C.ERSAPadding.PSS_MGF1 ? "rsa-pss-mgf1" : "rsa-pkcs-v1.5"}",
                "configurable": false
            },
            "hashAlgorithm": {
                "writtable": false,
                "value": "${hashAlgorithm}",
                "configurable": false
            },
            "output": {
                "writtable": false,
                "value": "${output}",
                "configurable": false
            }
        });

        return ret;

    `)(Enc, sign, verify, privKey, pubKey));
}
