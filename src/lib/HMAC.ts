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
import * as Enc from "@litert/encodings";
import * as $Crypto from "crypto";

class HMACSigner<D extends C.ValidEncoding>
implements C.ISigner<C.IHMACSignKeyFormat, D> {

    private _key?: C.IHMACSignKeyFormat["construct"];

    private _algo: C.ValidHashAlgoritms;

    private _encoding: C.ValidEncoding;

    public constructor(
        algo: C.ValidHashAlgoritms,
        key?: C.IHMACSignKeyFormat["construct"],
        encoding: C.ValidEncoding = "buffer",
    ) {

        this._algo = algo;
        this._key = key;
        this._encoding = encoding;
    }

    public get key(): C.IHMACSignKeyFormat["construct"] | undefined {

        return this._key;
    }

    public get algorithm(): C.ISignerAlgorithm {

        return {
            name: `hmac-${this._algo}`,
            hash: this._algo,
            sign: "hmac"
        };
    }

    public get encoding(): C.ValidEncoding {

        return this._encoding;
    }

    public sign<E extends C.ValidEncoding>(opts: {

        message: string | Buffer;

        key?: C.IHMACSignKeyFormat["sign"];

        encoding?: E;

    }): C.IOutputType[E] {

        const hasher = $Crypto.createHmac(this._algo, opts.key || this._key as string);

        hasher.update(opts.message);

        return Enc.convert(
            hasher.digest(),
            (opts.encoding || this._encoding) as any
        );
    }

    public verify<E extends keyof C.IOutputType>(opts: {

        message: string | Buffer;

        signature: C.IOutputType[E];

        key?: C.IHMACSignKeyFormat["verify"];

        encoding?: E;

    }): boolean {

        return !Enc.compare(
            this.sign({
                message: opts.message,
                key: opts.key,
                encoding: opts.encoding || this._encoding
            }),
            opts.signature,
            (opts.encoding || this._encoding),
            (opts.encoding || this._encoding)
        );
    }
}

export function createHMACSigner<D extends C.ValidEncoding = "buffer">(
    opts: C.ISignerOptions<C.IHMACSignKeyFormat, D>
): C.ISigner<C.IHMACSignKeyFormat, D> {

    return new HMACSigner<D>(
        opts.hash,
        opts.key,
        opts.encoding
    );
}
