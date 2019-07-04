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

import * as C from "./Common";
import * as Enc from "./Encodings";
import * as $Crypto from "crypto";
import * as $Stream from "stream";

class HMACSigner<D extends C.ValidEncoding>
implements C.ISigner<C.IHMACKeyFormat, D> {

    private _key?: C.IHMACKeyFormat["construct"];

    private _algo: C.ValidHashAlgoritms;

    private _encoding: C.ValidEncoding;

    public constructor(
        algo: C.ValidHashAlgoritms,
        key?: C.IHMACKeyFormat["construct"],
        encoding: C.ValidEncoding = "buffer",
    ) {

        this._algo = algo;
        this._key = key;
        this._encoding = encoding;
    }

    public get key(): C.IHMACKeyFormat["construct"] | undefined {

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

        key?: C.IHMACKeyFormat["sign"];

        encoding?: E;

    }): C.IOutputType[E] {

        const hasher = $Crypto.createHmac(this._algo, opts.key || this._key as string);

        hasher.update(opts.message);

        return Enc.convert(
            hasher.digest(),
            (opts.encoding || this._encoding) as any,
            "buffer"
        );
    }

    public signStream<E extends C.ValidEncoding>(opts: {

        message: $Stream.Readable;

        key?: C.IHMACKeyFormat["sign"];

        encoding?: E;

    }): Promise<C.IOutputType[E]> {

        return new Promise<C.IOutputType[E]>((resolve, reject) => {

            try {

                const hmac = $Crypto.createHmac(
                    this._algo, opts.key ||
                    this._key as string
                );

                opts.message.pipe(hmac).on("finish", () => {

                    try {

                        const data = hmac.read();

                        if (data) {

                            resolve(Enc.convert(
                                data as Buffer,
                                (opts.encoding || this._encoding) as any,
                                "buffer"
                            ));
                        }
                    }
                    catch (e) {

                        reject(e);
                    }
                });
            }
            catch (e) {

                reject(e);
            }
        });
    }

    public verify<E extends keyof C.IOutputType>(opts: {

        message: string | Buffer;

        signature: C.IOutputType[E];

        key?: C.IHMACKeyFormat["verify"];

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

    public async verifyStream<E extends keyof C.IOutputType>(opts: {

        message: $Stream.Readable;

        signature: C.IOutputType[E];

        key?: C.IHMACKeyFormat["verify"];

        encoding?: E;

    }): Promise<boolean> {

        return !Enc.compare(
            await this.signStream({
                message: opts.message,
                key: opts.key,
                encoding: "buffer"
            }),
            opts.signature,
            "buffer",
            (opts.encoding || this._encoding)
        );
    }
}

/**
 * Create a HMAC signer object.
 *
 * @param opts The options of signer.
 */
export function createHMACSigner<D extends C.ValidEncoding = "buffer">(
    opts: C.ISignerOptions<C.IHMACKeyFormat, D>
): C.ISigner<C.IHMACKeyFormat, D> {

    return new HMACSigner<D>(
        opts.hash,
        opts.key,
        opts.encoding
    );
}
