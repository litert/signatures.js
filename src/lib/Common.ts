/**
 *  Copyright 2018 Angus.Fenying <fenying@litert.org>
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

import { Encodings as ValidEncoding } from "@litert/encodings";

export { ValidEncoding };

export type ValidHashAlgoritms = "ripemd160" | "sha1" | "sha224" | "sha256" |
                                 "sha384" | "sha512" | "whirlpool" |
                                 "md5" | "mdc2" | "md4";

export type ValidSignAlgorithms = "hmac" | "rsassa-pkcs1-v1_5" | "ecdsa" | "rsassa-pss";

export const DEFAULT_RESULT_OUTPUT: ValidEncoding = "buffer";

export const HASH_OUTPUT_BITS: Record<ValidHashAlgoritms, number> = {
    "sha1": 160,
    "sha224": 224,
    "sha256": 256,
    "sha384": 384,
    "sha512": 512,
    "whirlpool": 512,
    "md5": 128,
    "mdc2": 128,
    "md4": 128,
    "ripemd160": 160,
};

export interface IOutputType
extends Record<ValidEncoding, string | Buffer> {

    "buffer": Buffer;

    "hex": string;

    "base64": string;

    "base64url": string;

    "utf8": string;
}

export interface ISignerAlgorithm {

    name: string;

    hash: ValidHashAlgoritms;

    sign: ValidSignAlgorithms;
}

export interface ISigner<
    K extends ISignKeyFormat,
    D extends ValidEncoding = "buffer"
> {

    /**
     * The default key of signature.
     */
    readonly key?: K["construct"];

    readonly algorithm: ISignerAlgorithm;

    /**
     * The default encoding of signature input and output.
     */
    readonly encoding: ValidEncoding;

    sign(opts: {

        message: string | Buffer;

        key?: K["sign"];

    }): IOutputType[D];

    sign<E extends keyof IOutputType>(opts: {

        message: string | Buffer;

        key?: K["sign"];

        encoding: E;

    }): IOutputType[E];

    verify(opts: {

        message: string | Buffer;

        signature: IOutputType[D];

        key?: K["verify"];

    }): boolean;

    verify<E extends keyof IOutputType>(opts: {

        message: string | Buffer;

        signature: IOutputType[E];

        key?: K["verify"];

        encoding: E;

    }): boolean;
}

export type ISecretKey = string | Buffer | {

    "key": string | Buffer;

    "passphrase": string;
};

export type IKeyPair = Record<"private" | "public", ISecretKey>;

export interface ISignKeyFormat {

    "construct": string | Buffer | IKeyPair;

    "sign": string | Buffer | ISecretKey;

    "verify": string | Buffer | ISecretKey;
}

export interface IPKeySignKeyFormat
extends ISignKeyFormat {

    "construct": IKeyPair;

    "sign": ISecretKey;

    "verify": ISecretKey;
}

export interface IHMACSignKeyFormat
extends ISignKeyFormat {

    "construct": string | Buffer;

    "sign": string | Buffer;

    "verify": string | Buffer;
}

export interface ISignerOptions<
    K extends ISignKeyFormat,
    D extends ValidEncoding
> {
    "hash": ValidHashAlgoritms;

    "key"?: K["construct"];

    "encoding"?: D;
}

/**
 * The algorithms for signature usage.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.1
 */
export enum ESignAlgorithms {

    /**
     * No digital signature or MAC performed.
     *
     * @optional
     */
    NONE,

    /**
     * HMAC using SHA-256.
     *
     * @required
     */
    HS256,

    /**
     * HMAC using SHA-384.
     *
     * @optional
     */
    HS384,

    /**
     * HMAC using SHA-512.
     *
     * @optional
     */
    HS512,

    /**
     * RSASSA-PKCS1-v1_5 using SHA-256.
     *
     * @recommended
     */
    RS256,

    /**
     * RSASSA-PKCS1-v1_5 using SHA-384.
     *
     * @optional
     */
    RS384,

    /**
     * RSASSA-PKCS1-v1_5 using SHA-512.
     *
     * @optional
     */
    RS512,

    /**
     * ECDSA using P-256 and SHA-256.
     *
     * @recommended
     */
    ES256,

    /**
     * ECDSA using P-256 and SHA-384.
     *
     * @optional
     */
    ES384,

    /**
     * ECDSA using P-256 and SHA-512.
     *
     * @optional
     */
    ES512,

    /**
     * RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
     *
     * @optional
     */
    PS256,

    /**
     * RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
     *
     * @optional
     */
    PS384,

    /**
     * RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
     *
     * @optional
     */
    PS512
}
