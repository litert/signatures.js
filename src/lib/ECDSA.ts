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
import * as Enc from "@litert/encodings";
import * as U from "./Utils";

export type ECDSAOutput = "der" | "rs";

class ECDSASignerDER<D extends C.ValidEncoding>
 extends AbstractPKeySigner<D> {

    public constructor(
        algo: C.ValidHashAlgoritms,
        key?: C.IPKeySignKeyFormat["construct"],
        encoding: C.ValidEncoding = "buffer"
    ) {

        super(
            algo,
            "ecdsa",
            key,
            encoding
        );
    }
}

class ECDSASignerRS<D extends C.ValidEncoding>
extends AbstractPKeySigner<D> {

    public constructor(
        algo: C.ValidHashAlgoritms,
        key?: C.IPKeySignKeyFormat["construct"],
        encoding: C.ValidEncoding = "buffer"
    ) {

        super(
            algo,
            "ecdsa",
            key,
            encoding
        );
    }

    public sign<E extends C.ValidEncoding>(opts: {

        message: string | Buffer;

        key?: C.IPKeySignKeyFormat["sign"];

        encoding?: E;

    }): C.IOutputType[E] {

        return Enc.convert(U.ecdsaDER2RS(super.sign({
            message: opts.message,
            key: opts.key,
            encoding: "buffer"
        })), opts.encoding || this.encoding as any);
    }

    public verify<E extends keyof C.IOutputType>(opts: {

        message: string | Buffer;

        signature: C.IOutputType[E];

        key?: C.IPKeySignKeyFormat["verify"];

        encoding?: E;

    }): boolean {

        return super.verify({
            message: opts.message,
            signature: U.ecdsaRS2DER(Enc.convert(
                opts.signature as any,
                "buffer",
                opts.encoding || this.encoding as any
            )),
            encoding: "buffer",
            key: opts.key
        });
    }
}

export interface IECDSASignerOptions<D extends C.ValidEncoding = "buffer">
extends C.ISignerOptions<C.IPKeySignKeyFormat, D> {

    /**
     * The output & input format of signature.
     *
     * @default "rs"
     */
    "output"?: ECDSAOutput;
}

export function createECDSASigner<D extends C.ValidEncoding = "buffer">(
    opts: IECDSASignerOptions<D>
): C.ISigner<C.IPKeySignKeyFormat, D> {

    if (opts.output === "der") {

        return new ECDSASignerDER<D>(
            opts.hash,
            opts.key,
            opts.encoding
        );
    }

    return new ECDSASignerRS<D>(
        opts.hash,
        opts.key,
        opts.encoding
    );
}
