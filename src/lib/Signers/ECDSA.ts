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

export type TAlgorithms = "sha1" | "sha224" | "sha256" | "sha384" | "sha512";

/**
 * Sign a signature by ECDSA.
 *
 * @param algo          The hash algorithm to be used.
 * @param message       The message to be signed.
 * @param privKey       The private key of ECDSA.
 */
export const sign: C.ISignerFn<TAlgorithms, C.IAsymmetricKey> = function(
    algo: TAlgorithms,
    message: string | Buffer | Readable,
    privKey: C.IAsymmetricKey
): any {

    const hasher = $Crypto.createSign(algo);

    if (message instanceof Buffer || typeof message === "string") {

        return hasher.update(message).sign({
            "key": privKey.key as any,
            "passphrase": privKey.password
        });
    }
    else {

        return new Promise<Buffer>(function(resolve, reject): void {
            message.pipe(hasher).on("finish", () => {

                try {

                    resolve(hasher.sign({
                        "key": privKey.key as any,
                        "passphrase": privKey.password
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
 * Verify a signature by ECDSA.
 *
 * @param algo          The hash algorithm to be used.
 * @param message       The message to be verified.
 * @param signature     The signature of message to be verified.
 * @param pubKey        The public key of ECDSA.
 */
export const verify: C.IVerifierFn<TAlgorithms> = function(
    algo: TAlgorithms,
    message: string | Buffer | Readable,
    signature: Buffer,
    pubKey: string | Buffer
): any {

    const hasher = $Crypto.createVerify(algo);

    if (message instanceof Buffer || typeof message === "string") {

        return hasher.update(message).verify({"key": pubKey}, signature);
    }
    else {

        return new Promise<boolean>(function(resolve, reject): void {
            message.pipe(hasher).on("finish", () => {

                try {

                    resolve(hasher.verify({"key": pubKey}, signature));
                }
                catch (e) {

                    reject(e);
                }

            }).once("error", reject);
        });
    }
};

/**
 * Get the names of supported hash algorithms for ECDSA.
 */
export function getSupportedAlgorithms(): TAlgorithms[] {

    return [
        "sha1", "sha224", "sha256", "sha384",
        "sha512"
    ];
}

/**
 * This method helps recover R/S to the DER form, with padding if necessary.
 *
 * @param {Buffer} input The R/S to be recovered.
 */
function _ecdsaRecoverRS(input: Buffer): Buffer {

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

    let output = Buffer.alloc(input.length + 1);

    input.copy(output, 1);
    output[0] = 0;

    return output;
}

const UINT32_READ_BUFFER = Buffer.alloc(4);

function _derReadLength(bf: Buffer, offset: number): [number, number] {

    let length = bf[offset++];

    /**
     * Using long form length if it's larger than 0x7F.
     *
     * @see https://stackoverflow.com/a/47099047
     */
    if (length > 0x7F) {

        // tslint:disable: no-bitwise
        let llen = length & 0x7F;
        UINT32_READ_BUFFER.fill(0);
        bf.copy(UINT32_READ_BUFFER, 4 - llen, offset, offset + llen);
        length = UINT32_READ_BUFFER.readUInt32BE(0);
        offset += llen;
    }

    return [length, offset];
}

function _removePrependZero(bf: Buffer): Buffer {

    let i = 0;

    // tslint:disable-next-line: curly
    for (; i < bf.length && !bf[i]; i++);

    if (i === bf.length) {

        return bf.slice(0, 1);
    }

    return bf.slice(i);
}

/**
 * This method helps transform signature from DER format to P1363 format.
 *
 * @param {Buffer} der  The signature in DER format.
 *
 * @returns {Buffer}  Return the signature in P1363 format.
 */
export function derToP1363(der: Buffer): Buffer {

    let [, offset] = _derReadLength(der, 1);

    let rL: number;
    let sL: number;

    [rL, offset] = _derReadLength(der, ++offset);

    let r = _removePrependZero(der.slice(offset, offset + rL));

    offset += rL;

    [sL, offset] = _derReadLength(der, ++offset);

    let s = _removePrependZero(der.slice(offset, offset + sL));

    if (s.length > r.length) {

        return Buffer.concat([Buffer.alloc(s.length - r.length), r, s]);
    }
    else if (r.length > s.length) {

        return Buffer.concat([r, Buffer.alloc(r.length - s.length), s]);
    }

    return Buffer.concat([r, s]);
}

/**
 * This method helps transform signature from DER format to P1363 format.
 *
 * @param {Buffer} p1363   The signature in P1363 format.
 *
 * @returns {Buffer}  Return the signature in DER format.
 */
export function p1363ToDER(p1363: Buffer): Buffer {

    let base = 0;

    let r: Buffer;
    let s: Buffer;

    const hL = p1363.length / 2;

    /**
     * Prepend a 0x00 byte to R or S if it starts with a byte larger than 0x79.
     *
     * Because a integer starts with a byte larger than 0x79 means negative.
     *
     * @see https://bitcointalk.org/index.php?topic=215205.msg2258789#msg2258789
     */
    r = _ecdsaRecoverRS(p1363.slice(0, hL));
    s = _ecdsaRecoverRS(p1363.slice(hL));

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

/**
 * Create an ECDSA signer (also a verifier).
 *
 * @param hashAlgorithm     The HASH algorithm to be used in signing.
 * @param pubKey            The public key for verifying.
 * @param privKey           The private ket for signing.
 * @param format            The format for signature output and input. [Default: DER]
 * @param output            The encoding for signature output and input. [Default: Buffer]
 */
export function createSigner<T extends C.TSignature = "buffer">(
    hashAlgorithm: TAlgorithms,
    pubKey: string | Buffer,
    privKey: string | Buffer | C.TAsymmetricKey,
    format: C.EECDSAFormat = C.EECDSAFormat.DER,
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

    if (format !== C.EECDSAFormat.DER) {

        signaturePreprocess += `signature = p1363ToDER(signature)`;
    }

    return (new Function(`Enc`, "_sign", "_verify", "privKey", "pubKey", `derToP1363`, `p1363ToDER`, `

        const ret = {
            sign(data) {

                const result = _sign("${hashAlgorithm}", data, privKey);

                if (result instanceof Promise) {

                    return result.then((x) => ${
                        format !== C.EECDSAFormat.DER ?
                        I._getEncoderName(output as string, "Enc", "derToP1363(x)") :
                        I._getEncoderName(output as string, "Enc", "x")
                    })
                }

                return ${
                    format !== C.EECDSAFormat.DER ?
                        I._getEncoderName(output as string, "Enc", "derToP1363(result)") :
                        I._getEncoderName(output as string, "Enc", "result")
                };
            },
            verify(data, signature) {

                ${signaturePreprocess}

                return _verify("${hashAlgorithm}", data, signature, pubKey);
            }
        };

        Object.defineProperties(ret, {
            "signAlgorithm": {
                "writtable": false,
                "value": "ecdsa",
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

    `)(Enc, sign, verify, privKey, pubKey, derToP1363, p1363ToDER));
}
