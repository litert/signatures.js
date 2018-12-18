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
import * as $Stream from "stream";
import * as Errors from "./Errors";

export abstract class AbstractPKeySigner<D extends C.ValidEncoding>
implements C.ISigner<C.IPairKeyFormat, D> {

    private _key?: C.IPairKeyFormat["construct"];

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
        key?: C.IPairKeyFormat["construct"],
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

    public get key(): C.IPairKeyFormat["construct"] | undefined {

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

        key?: C.IPairKeyFormat["sign"];

        encoding?: E;

    }): C.IOutputType[E] {

        try {

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
        catch (e) {

            if (e.message && e.message.includes("invalid digest type")) {

                throw new Errors.E_HASH_ALGO_INVALID({
                    "metadata": {
                        "sign": this._signAlgo,
                        "hash": this._algo
                    }
                });
            }

            throw e;
        }
    }

    public signStream<E extends C.ValidEncoding>(opts: {

        message: $Stream.Readable;

        key?: C.IPairKeyFormat["sign"];

        encoding?: E;

    }): Promise<C.IOutputType[E]> {

        return new Promise<C.IOutputType[E]>((resolve, reject) => {

            const hasher = $Crypto.createSign(this._algo);

            opts.message.pipe(hasher).once("finish", (): void => {

                let data: C.IOutputType[E];

                try {

                    data = Enc.convert(
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
                catch (e) {

                    if (e.message && e.message.includes("invalid digest type")) {

                        return reject(new Errors.E_HASH_ALGO_INVALID({
                            "metadata": {
                                "sign": this._signAlgo,
                                "hash": this._algo
                            }
                        }));
                    }

                    return reject(e);
                }

                resolve(data);
            });
        });
    }

    public verify<E extends keyof C.IOutputType>(opts: {

        message: string | Buffer;

        signature: C.IOutputType[E];

        key?: C.IPairKeyFormat["verify"];

        encoding?: E;

    }): boolean {

        try {

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
        catch (e) {

            if (e.message && e.message.includes("invalid digest type")) {

                throw new Errors.E_HASH_ALGO_INVALID({
                    "metadata": {
                        "sign": this._signAlgo,
                        "hash": this._algo
                    }
                });
            }

            throw e;
        }
    }

    public verifyStream<E extends keyof C.IOutputType>(opts: {

        message: $Stream.Readable;

        signature: C.IOutputType[E];

        key?: C.IPairKeyFormat["verify"];

        encoding?: E;

    }): Promise<boolean> {

        return new Promise<boolean>((resolve, reject) => {

            const hasher = $Crypto.createVerify(this._algo);

            opts.message.pipe(hasher).once("finish", (): void => {

                let result: boolean = false;

                try {

                    result = hasher.verify(
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
                catch (e) {

                    if (e.message && e.message.includes("invalid digest type")) {

                        return reject(new Errors.E_HASH_ALGO_INVALID({
                            "metadata": {
                                "sign": this._signAlgo,
                                "hash": this._algo
                            }
                        }));
                    }

                    return reject(e);
                }

                resolve(result);
            });
        });
    }
}
