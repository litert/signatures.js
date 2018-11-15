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

// tslint:disable:no-console

import * as Signs from "../lib";
import * as $FS from "fs";

const PRI_KEY = $FS.readFileSync(`${__dirname}/../test/rsa-priv.pem`, {
    encoding: "utf8"
});

const PUB_KEY = $FS.readFileSync(`${__dirname}/../test/rsa-pub.pem`, {
    encoding: "utf8"
});

const WRONG_PUB_KEY = $FS.readFileSync(`${__dirname}/../test/rsa-wrong-pub.pem`, {
    encoding: "utf8"
});

const CONTENT = "Hello, how are you?";

for (let a of Signs.listHashAlgorithms()) {

    const signer = Signs.createRSASigner({
        "key": {
            "private": PRI_KEY,
            "public": PUB_KEY
        },
        "hash": a,
        "encoding": "base64",
        "padding": "pss-mgf1"
    });

    try {

        const signResult = signer.sign({
            message: CONTENT
        });

        const verifyResult = signer.verify({
            message: CONTENT,
            signature: signResult
        });

        const verifyResultWWK = signer.verify({
            message: CONTENT,
            signature: signResult,
            key: WRONG_PUB_KEY
        });

        console.debug(`[${signer.algorithm.name}]: Result ${signResult}`);

        if (verifyResult && !verifyResultWWK) {

            console.info(`[${signer.algorithm.name}] Verification matched.`);
        }
        else {

            console.error(`[${signer.algorithm.name}] Verification failed.`);
        }
    }
    catch {

        console.error(`[${signer.algorithm.name}] Not supported with RSASSA-PSS.`);
    }
}
