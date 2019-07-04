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

import { AbstractPKeySigner } from "./AbstractPKeySigner";
import * as C from "./Common";
import * as Enc from "./Encodings";
import * as U from "./Utils";
import * as $Stream from "stream";

export type ECDSAOutput = "der" | "p1363";

class ECDSASignerDER<D extends C.ValidEncoding>
 extends AbstractPKeySigner<D> {

    public constructor(
        algo: C.ValidHashAlgoritms,
        key?: C.IPairKeyFormat["construct"],
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
        key?: C.IPairKeyFormat["construct"],
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

        key?: C.IPairKeyFormat["sign"];

        encoding?: E;

    }): C.IOutputType[E] {

        return Enc.convert(
            U.ecdsaDERToP1363(super.sign({
                message: opts.message,
                key: opts.key,
                encoding: "buffer"
            })),
            opts.encoding || this.encoding as any,
            "buffer"
        );
    }

    public async signStream<E extends C.ValidEncoding>(opts: {

        message: $Stream.Readable;

        key?: C.IPairKeyFormat["sign"];

        encoding?: E;

    }): Promise<C.IOutputType[E]> {

        return Enc.convert(U.ecdsaDERToP1363(
            await super.signStream({
                message: opts.message,
                key: opts.key,
                encoding: "buffer"
            })),
            opts.encoding || this.encoding as any,
            "buffer"
        );
    }

    public verify<E extends keyof C.IOutputType>(opts: {

        message: string | Buffer;

        signature: C.IOutputType[E];

        key?: C.IPairKeyFormat["verify"];

        encoding?: E;

    }): boolean {

        return super.verify({
            message: opts.message,
            signature: U.ecdsaP1363ToDER(Enc.convert(
                opts.signature as any,
                "buffer",
                opts.encoding || this.encoding as any
            )),
            encoding: "buffer",
            key: opts.key
        });
    }

    public verifyStream<E extends keyof C.IOutputType>(opts: {

        message: $Stream.Readable;

        signature: C.IOutputType[E];

        key?: C.IPairKeyFormat["verify"];

        encoding?: E;

    }): Promise<boolean> {

        return super.verifyStream({
            message: opts.message,
            signature: U.ecdsaP1363ToDER(Enc.convert(
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
extends C.ISignerOptions<C.IPairKeyFormat, D> {

    /**
     * The output & input format of signature.
     *
     * @default "p1363"
     */
    "output"?: ECDSAOutput;
}

/**
 * Create an ECDSA signer object.
 *
 * @param opts The options of signer.
 */
export function createECDSASigner<D extends C.ValidEncoding = "buffer">(
    opts: IECDSASignerOptions<D>
): C.ISigner<C.IPairKeyFormat, D> {

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
