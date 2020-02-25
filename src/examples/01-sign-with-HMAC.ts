/**
 *  Copyright 2020 Angus.Fenying <fenying@litert.org>
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

// tslint:disable:no-console

import * as Signs from "../lib";
import * as $fs from "fs";
import { printable } from "./utils";

const KEY = "hello world!";

const FAKE_KEY = "world hello!";

const CONTENT = "Hello, how are you?";

const ENCODINGS: Signs.TSignature[] = ["base64", "buffer", "hex", "base64url"];

for (const ENC of ENCODINGS) {

    for (let a of Signs.HMAC.getSupportedAlgorithms()) {

        const signer = Signs.HMAC.createSigner(
            a,
            KEY,
            ENC
        );

        const fakeSigner = Signs.HMAC.createSigner(
            a,
            FAKE_KEY,
            ENC
        );

        const result = signer.sign(CONTENT);

        console.debug(`[${ENC}][${signer.hashAlgorithm}]: Result = ${printable(result)}`);

        if (
            signer.verify(CONTENT, result) &&
            !fakeSigner.verify(CONTENT, result) &&
            Signs.HMAC.verify(a, CONTENT, Signs.HMAC.sign(a, CONTENT, KEY), KEY)
        ) {

            console.info(`[${ENC}][${signer.hashAlgorithm}] Verification matched.`);
        }
        else {

            console.error(`[${ENC}][${signer.hashAlgorithm}] Verification failed.`);
        }
    }
}

(async () => {

    for (const ENC of ENCODINGS) {

        for (let a of Signs.HMAC.getSupportedAlgorithms()) {

            const signer = Signs.HMAC.createSigner(
                a,
                KEY,
                ENC
            );

            const fakeSigner = Signs.HMAC.createSigner(
                a,
                FAKE_KEY,
                ENC
            );

            const result = await signer.sign(
                $fs.createReadStream(`${__dirname}/../test/bigfile.dat`)
            );

            console.debug(`[${ENC}][stream][${signer.hashAlgorithm}]: Result = ${printable(result)}`);

            if (
                (await signer.verify(
                    $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                    result
                )) &&
                (!await fakeSigner.verify(
                    $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                    result
                )) &&
                (await Signs.HMAC.verify(
                    a,
                    $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                    await Signs.HMAC.sign(
                        a,
                        $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                        KEY
                    ),
                    KEY
                ))
            ) {

                console.info(`[${ENC}][stream][${signer.hashAlgorithm}] Verification matched.`);
            }
            else {

                console.error(`[${ENC}][stream][${signer.hashAlgorithm}] Verification failed.`);
            }
        }
    }
})();
