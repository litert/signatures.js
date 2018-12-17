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

import { AbstractPKeySigner } from "./AbstractPKeySigner";
import * as C from "./Common";
import * as $Constants from "constants";

export type RSAPaddingType = "pkcs1-v1_5" | "pss-mgf1";

class RSASigner<D extends C.ValidEncoding>
 extends AbstractPKeySigner<D> {

    public constructor(
        hashAlgo: C.ValidHashAlgoritms,
        key?: C.IPairKeyFormat["construct"],
        encoding: C.ValidEncoding = "buffer",
        padding: RSAPaddingType = "pkcs1-v1_5"
    ) {

        if (padding === "pss-mgf1") {

            super(
                hashAlgo,
                "rsassa-pss",
                key,
                encoding,
                padding === "pss-mgf1" ?
                    $Constants.RSA_PKCS1_PSS_PADDING :
                    $Constants.RSA_PKCS1_PADDING
            );
        }
        else {

            super(
                hashAlgo,
                "rsassa-pkcs1-v1_5",
                key,
                encoding
            );
        }
    }
}

export interface IRSASignerOptions<D extends C.ValidEncoding = "buffer">
extends C.ISignerOptions<
    C.IPairKeyFormat,
    D
> {
    "padding"?: RSAPaddingType;
}

export function createRSASigner<D extends C.ValidEncoding = "buffer">(
    opts: IRSASignerOptions<D>
): C.ISigner<C.IPairKeyFormat, D> {

    return new RSASigner<D>(
        opts.hash,
        opts.key,
        opts.encoding,
        opts.padding
    );
}
