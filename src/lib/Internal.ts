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

import * as C from "./Common";

export interface IRSAKeyOptions {

    key: string | Buffer;

    passphrase: string;

    padding?: number;

    saltLength?: number;
}

export function wrapKey(
    key: C.ISecretKey,
    padding?: number,
    saltLength?: number
): IRSAKeyOptions {

    let ret: IRSAKeyOptions;

    if (typeof key === "string" || key instanceof Buffer) {

        ret = {
            key,
            passphrase: ""
        };
    }
    else {

        ret = {
            key: key.key,
            passphrase: key.passphrase
        };
    }

    if (padding !== undefined) {

        ret.padding = padding;
    }

    if (saltLength) {

        ret.saltLength = saltLength;
    }

    return ret;
}

export const HASH_ALGORITHMS: C.ValidHashAlgoritms[] = [
    "sha1", "sha224", "sha256",
    "sha384", "sha512", "whirlpool",
    "md5", "mdc2", "md4", "ripemd160"
];

export const SIGN_ALGORITHMS: C.ValidSignAlgorithms[] = [
    "hmac", "rsassa-pkcs1-v1_5", "ecdsa", "rsassa-pss"
];
