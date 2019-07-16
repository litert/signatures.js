/**
 *  Copyright 2019 Angus.Fenying <fenying@litert.org>
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

export interface IAsymmetricKey {

    "key": Buffer | string;

    "password": string;
}

export type TAsymmetricKey = Buffer | string | IAsymmetricKey;

/**
 * The supported padding mode of RSA.
 */
export enum ERSAPadding {

    /**
     * PSS-MGF1 padding mode, used for RSA-PSS.
     */
    PSS_MGF1,

    /**
     * PKCS1-v1.5 padding mode.
     */
    PKCS1_V1_5
}

/**
 * The supported output format of ECDSA.
 */
export enum EECDSAFormat {

    /**
     * IEEE-P1363 format, widely used on the Internet like JWT.
     */
    IEEE_P1363,

    /**
     * DER format generated by OpenSSL.
     */
    DER
}

/**
 * The bit-length of hash algorithms output.
 */
export const HASH_OUTPUT_BITS: Record<string, number> = {
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

/**
 * The names of supported signature output.
 */
export type TSignature = "base64" | "base64url" | "hex" | "buffer";

export interface ISigner<O extends TSignature> {

    /**
     * The name of sign algorithm of this signer.
     */
    readonly signAlgorithm: string;

    /**
     * The name of hash algorithm of this signer.
     */
    readonly hashAlgorithm: string;

    /**
     * The output format of this signer.
     */
    readonly output: O;

    /**
     * Sign the data with specific the bound algorithm and key.
     *
     * @param data The data to be signed.
     */
    sign(data: Buffer | string): O extends "buffer" ? Buffer : string;

    /**
     * Sign a stream with specific the bound algorithm and key.
     *
     * @param data The data to be signed.
     */
    sign(data: Readable): Promise<O extends "buffer" ? Buffer : string>;

    /**
     * Verify the data with specific the bound algorithm and key.
     *
     * @param data The data to be verified.
     */
    verify(data: Buffer | string, signature: O extends "buffer" ? Buffer : string): boolean;

    /**
     * Verify a stream with specific the bound algorithm and key.
     *
     * @param data The data to be verified.
     */
    verify(data: Readable, signature: O extends "buffer" ? Buffer : string): Promise<boolean>;
}

export interface ISignerFn<A extends string, K, O = never> {

    /**
     * Sign a signature.
     *
     * @param algo          The hash algorithm to be used.
     * @param message       The message to be signed.
     * @param privKey       The private key.
     * @param opts          The options.
     */
    (algo: A, message: string | Buffer, key: K, options?: O): Buffer;

    /**
     * Sign a signature.
     *
     * @param algo          The hash algorithm to be used.
     * @param message       The message to be signed.
     * @param privKey       The private key.
     * @param opts          The options.
     */
    (algo: A, message: Readable, key: K, options?: O): Promise<Buffer>;
}

export interface IVerifierFn<A extends string, O = never> {

    /**
     * Verify a signature.
     *
     * @param algo          The hash algorithm to be used.
     * @param message       The message to be verified.
     * @param signature     The signature of message to be verified.
     * @param pubKey        The public key.
     * @param options       The options.
     */
    (algo: A, message: string | Buffer, signature: Buffer, pubKey: Buffer | string, options?: O): boolean;

    /**
     * Verify a signature.
     *
     * @param algo          The hash algorithm to be used.
     * @param message       The message to be verified.
     * @param signature     The signature of message to be verified.
     * @param pubKey        The public key.
     * @param options       The options.
     */
    (algo: A, message: Readable, signature: Buffer, pubKey: Buffer | string, options?: O): Promise<boolean>;
}
