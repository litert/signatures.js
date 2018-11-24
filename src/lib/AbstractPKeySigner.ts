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
import * as I from "./Internal";
import * as Enc from "@litert/encodings";
import * as $Crypto from "crypto";

export abstract class AbstractPKeySigner<D extends C.ValidEncoding>
implements C.ISigner<C.IPKeySignKeyFormat, D> {

    private _key?: C.IPKeySignKeyFormat["construct"];

    private _algo: C.ValidHashAlgoritms;

    private _encoding: C.ValidEncoding;

    private _signAlgo: C.ValidSignAlgorithms;

    private _padding?: number;

    private _saltLength?: number;

    private _privKey!: I.IRSAKeyOptions;

    private _pubKey!: I.IRSAKeyOptions;

    public constructor(
        hashAlgo: C.ValidHashAlgoritms,
        signAlgo: C.ValidSignAlgorithms,
        key?: C.IPKeySignKeyFormat["construct"],
        encoding: C.ValidEncoding = "buffer",
        padding?: number,
        saltLength?: number
    ) {

        this._algo = hashAlgo;
        this._signAlgo = signAlgo;
        this._key = key;
        this._encoding = encoding;
        this._padding = padding;
        this._saltLength = saltLength;

        if (key) {

            this._privKey = I.wrapKey(
                key.private,
                padding,
                saltLength
            );
            this._pubKey = I.wrapKey(
                key.public,
                padding,
                saltLength
            );
        }
    }

    public get key(): C.IPKeySignKeyFormat["construct"] | undefined {

        return this._key;
    }

    public get algorithm(): C.ISignerAlgorithm {

        return {
            name: `${this._signAlgo}-${this._algo}`,
            hash: this._algo,
            sign: this._signAlgo
        };
    }

    public get encoding(): C.ValidEncoding {

        return this._encoding;
    }

    public sign<E extends C.ValidEncoding>(opts: {

        message: string | Buffer;

        key?: C.IPKeySignKeyFormat["sign"];

        encoding?: E;

    }): C.IOutputType[E] {

        const hasher = $Crypto.createSign(this._algo);

        hasher.update(opts.message);
        hasher.end();

        return Enc.convert(
            hasher.sign(
                (opts.key && I.wrapKey(
                    opts.key,
                    this._padding,
                    this._saltLength
                )) || (this._key && this._privKey) as any
            ),
            (opts.encoding || this._encoding) as any,
            "buffer"
        );
    }

    public verify<E extends keyof C.IOutputType>(opts: {

        message: string | Buffer;

        signature: C.IOutputType[E];

        key?: C.IPKeySignKeyFormat["verify"];

        encoding?: E;

    }): boolean {

        const hasher = $Crypto.createVerify(this._algo);

        hasher.update(opts.message);

        hasher.end();

        return hasher.verify(
            (opts.key && I.wrapKey(
                opts.key,
                this._padding,
                this._saltLength
            )) || (this._key && this._pubKey) as any,
            Enc.convert(
                opts.signature as any,
                "buffer",
                opts.encoding || this._encoding as any
            )
        );
    }
}
