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

const CONTENT = "Hello, how are you?";

for (let a of Signs.listHashAlgorithms()) {

    try {

        const signer = Signs.createECDSASigner({
            "key": {
                "private": $FS.readFileSync(`${__dirname}/../test/ec${
                    Signs.HASH_OUTPUT_BITS[a]
                }-priv.pem`, {
                    encoding: "utf8"
                }),
                "public": $FS.readFileSync(`${__dirname}/../test/ec${
                    Signs.HASH_OUTPUT_BITS[a]
                }-pub.pem`, {
                    encoding: "utf8"
                })
            },
            "hash": a,
            "encoding": "base64"
        });

        const signResult = signer.sign({
            message: CONTENT
        });

        const verifyResult = signer.verify({
            message: CONTENT,
            signature: signResult
        });

        console.debug(`[${signer.algorithm.name}]: Result ${signResult}`);

        if (verifyResult) {

            console.info(`[${signer.algorithm.name}] Verification matched.`);
        }
        else {

            console.error(`[${signer.algorithm.name}] Verification failed.`);
        }
    }
    catch (e) {

        console.error(`Hash algorithm "${a}"(${Signs.HASH_OUTPUT_BITS[a]}-bits) not supported in ECDSA.`);
    }
}
