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

// tslint:disable:no-console

import * as Signs from "../lib";
import * as $fs from "fs";

const KEY = "hello world!";

const FAKE_KEY = "world hello!";

const CONTENT = "Hello, how are you?";

for (let a of Signs.HMAC.getSupportedAlgorithms()) {

    const signer = Signs.HMAC.createSigner(
        a,
        KEY,
        "base64"
    );

    const fakeSigner = Signs.HMAC.createSigner(
        a,
        FAKE_KEY,
        "base64"
    );

    const result = signer.sign(CONTENT);

    console.debug(`[${signer.hashAlgorithm}]: Result = ${result}`);

    if (
        signer.verify(CONTENT, result) &&
        !fakeSigner.verify(CONTENT, result) &&
        Signs.HMAC.sign(a, CONTENT, KEY).toString("base64") === result &&
        Signs.HMAC.verify(a, CONTENT, Buffer.from(result, "base64"), KEY)
    ) {

        console.info(`[${signer.hashAlgorithm}] Verification matched.`);
    }
    else {

        console.error(`[${signer.hashAlgorithm}] Verification failed.`);
    }
}

(async () => {

    for (let a of Signs.HMAC.getSupportedAlgorithms()) {

        const signer = Signs.HMAC.createSigner(
            a,
            KEY,
            "base64"
        );

        const fakeSigner = Signs.HMAC.createSigner(
            a,
            FAKE_KEY,
            "base64"
        );

        const result = await signer.sign(
            $fs.createReadStream(`${__dirname}/../test/bigfile.dat`)
        );

        console.debug(`[${signer.hashAlgorithm}][Stream]: Result = ${result}`);

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
                Buffer.from(result, "base64"),
                KEY
            )) &&
            ((await Signs.HMAC.sign(
                a,
                $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                KEY
            )).toString("base64") === result)
        ) {

            console.info(`[${signer.hashAlgorithm}][Stream] Verification matched.`);
        }
        else {

            console.error(`[${signer.hashAlgorithm}][Stream] Verification failed.`);
        }
    }
})();
