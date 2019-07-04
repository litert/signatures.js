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

for (let a of Signs.listHashAlgorithms()) {

    const signer = Signs.createHMACSigner({
        hash: a,
        encoding: "base64"
    });

    const result = signer.sign({
        message: CONTENT,
        key: KEY
    });

    console.debug(`[${signer.algorithm.name}]: Result = ${result}`);

    if (signer.verify({
        message: CONTENT,
        signature: result,
        key: KEY
    }) && !signer.verify({
        message: CONTENT,
        signature: result,
        key: FAKE_KEY
    })) {

        console.info(`[${signer.algorithm.name}] Verification matched.`);
    }
    else {

        console.error(`[${signer.algorithm.name}] Verification failed.`);
    }
}

(async () => {

    for (let a of Signs.listHashAlgorithms()) {

        const signer = Signs.createHMACSigner({
            hash: a,
            encoding: "base64"
        });

        const result = await signer.signStream({
            message: $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
            key: KEY
        });

        console.debug(`[${signer.algorithm.name}][Stream]: Result = ${result}`);

        if ((await signer.verifyStream({
            message: $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
            signature: result,
            key: KEY
        })) && !(await signer.verifyStream({
            message: $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
            signature: result,
            key: FAKE_KEY
        }))) {

            console.info(`[${signer.algorithm.name}][Stream] Verification matched.`);
        }
        else {

            console.error(`[${signer.algorithm.name}][Stream] Verification failed.`);
        }
    }
})();
