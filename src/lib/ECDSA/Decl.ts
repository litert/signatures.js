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

/**
 * The supported digest algorithms.
 */
export type IAlgorithms = keyof {
    /* eslint-disable @typescript-eslint/naming-convention */
    'sha1': unknown;
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
 * The options for ECDSA signing and verification.
 */
export interface IEcdsaOptions {

    /**
     * The passphrase of private key.
     */
    'keyPassphrase'?: string | Buffer;

    /**
     * The output format of signature.
     *
     * @default 'ieee-p1363
     */
    'format'?: 'ieee-p1363' | 'der';
}
