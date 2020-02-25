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
import * as C from "../Common";
import * as Enc from "@litert/encodings";
import * as I from "./Internal";

export type TAlgorithms = "blake2b512" | "blake2s256" | "md4" | "md5" |
                        "md5-sha1" | "mdc2" | "ripemd" | "ripemd160" |
                        "rmd160" | "sha1" | "sha224" | "sha256" |
                        "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" |
                        "sha384" | "sha512" | "sha512-224" | "sha512-256" |
                        "sm3" | "whirlpool";

/**
 * Sign a signature by HMAC.
 *
 * @param algo          The hash algorithm to be used.
 * @param message       The message to be signed.
 * @param key           The secret key of HMAC.
 */
export const sign: C.ISignerFn<TAlgorithms, string | Buffer> = function(
    algo: TAlgorithms,
    message: string | Buffer | Readable,
    key: string | Buffer
): any {

    const hasher = $Crypto.createHmac(algo, key);

    if (message instanceof Buffer || typeof message === "string") {

        return hasher.update(message).digest();
    }
    else {

        return new Promise<Buffer>(function(resolve, reject): void {
            message.pipe(hasher).on("finish", () => {

                const ret = hasher.read() as Buffer;
                resolve(ret);

            }).once("error", reject);
        });
    }
};

/**
 * Verify a signature by HMAC.
 *
 * @param algo          The hash algorithm to be used.
 * @param message       The message to be verified.
 * @param signature     The signature of message to be verified.
 * @param key           The secret key of HMAC.
 */
export const verify: C.IVerifierFn<TAlgorithms, string | Buffer> = function(
    algo: TAlgorithms,
    message: string | Buffer | Readable,
    signature: Buffer,
    key: string | Buffer
): any {

    const hasher = $Crypto.createHmac(algo, key);

    if (message instanceof Buffer || typeof message === "string") {

        return !hasher.update(message).digest().compare(signature);
    }
    else {

        return new Promise<boolean>(function(resolve, reject): void {
            message.pipe(hasher).on("finish", () => resolve(
                !(hasher.read() as Buffer).compare(signature)
            )).once("error", reject);
        });
    }
};

/**
 * Get the names of supported hash algorithms for HMAC.
 */
export function getSupportedAlgorithms(): TAlgorithms[] {

    return [
        "blake2b512", "blake2s256", "md4", "md5",
        "md5-sha1", "mdc2", "ripemd", "ripemd160",
        "rmd160", "sha1", "sha224", "sha256",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512",
        "sha384", "sha512", "sha512-224", "sha512-256",
        "sm3", "whirlpool"
    ];
}

export function createSigner<T extends C.TSignature = "buffer">(
    hashAlgorithm: TAlgorithms,
    key: string | Buffer,
    output?: T
): C.ISigner<T> {

    if (!output) {

        output = "buffer" as any;
    }

    let signaturePreprocess: string = "";

    if (output !== "buffer") {

        signaturePreprocess = I._getDecoderName(output as any, "Enc", "signature");
    }

    return (new Function(`Enc`, "_sign", "_verify", "key", `

        const ret = {
            sign(data) {

                const result = _sign("${hashAlgorithm}", data, key);

                if (result instanceof Promise) {

                    return result.then((x) => ${I._getEncoderName(output as string, "Enc", "x")});
                }

                return ${I._getEncoderName(output as string, "Enc", "result")};
            },
            verify(data, signature) {

                ${signaturePreprocess}

                return _verify("${hashAlgorithm}", data, signature, key);
            }
        };

        Object.defineProperties(ret, {
            "signAlgorithm": {
                "writtable": false,
                "value": "hmac",
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

    `)(Enc, sign, verify, key));
}
