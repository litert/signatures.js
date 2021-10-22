/**
 *  Copyright 2021 Angus.Fenying <fenying@litert.org>
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

import { Readable } from 'stream';

export interface ISigner {

    /**
     * Sign simple short data.
     *
     * @param message   The payload to be signed.
     */
    sign(message: Buffer | string): Buffer;

    /**
     * Sign data insides stream.
     *
     * @param message   The payload to be signed.
     */
    signStream(message: Readable): Promise<Buffer>;

    /**
     * Verify the signature of simple short data.
     *
     * @param message       The payload to be verified.
     * @param signature     The signature of payload to be verified.
     */
    verify(message: Buffer | string, signature: Buffer): boolean;

    /**
     * Verify data insides stream.
     *
     * @param message       The payload to be verified.
     * @param signature     The signature of payload to be verified.
     */
    verifyStream(message: Readable, signature: Buffer): Promise<boolean>;

    /**
     * The digest hash algorithm of this signer.
     */
    hashAlgorithm: string;

    /**
     * The signing algorithm of this signer.
     */
    signAlgorithm: string;
}

export interface IHasher {

    /**
     * Calculate the hash of simple short data.
     *
     * @param message   The payload to be processed.
     */
    hash(message: Buffer | string): Buffer;

    /**
     * Calculate the hash of data insides stream.
     *
     * @param message   The payload to be processed.
     */
    hashStream(message: Readable): Promise<Buffer>;

    /**
     * The digest hash algorithm of this hasher.
     */
    algorithm: string;
}
