/**
 *  Copyright 2021 Angus.Fenying <fenying@litert.org>
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

import * as Signs from '../lib';
import * as $fs from 'fs';

const DEBUG_DIR = `${__dirname}/../data`;

const PRI_KEY = $fs.readFileSync(`${DEBUG_DIR}/rsa-priv.pem`, {
    encoding: 'utf8'
});

const PUB_KEY = $fs.readFileSync(`${DEBUG_DIR}/rsa-pub.pem`, {
    encoding: 'utf8'
});

const FAKE_PUB_KEY = $fs.readFileSync(`${DEBUG_DIR}/rsa-wrong-pub.pem`, {
    encoding: 'utf8'
});

const CONTENT = 'Hello, how are you?';

const BIG_FILE_PATH = `${DEBUG_DIR}/bigfile.dat`;

(async () => {

    for (let algo of Signs.RSA.getSupportedAlgorithms()) {

        const algoName = `rsa-${algo}`;

        try {
            // do some text signing

            const textResult = Signs.RSA.sign(algo, PRI_KEY, CONTENT);

            const verifyResult = Signs.RSA.verify(
                algo, 
                PUB_KEY,
                CONTENT,
                textResult,
            ) && !Signs.RSA.verify(
                algo, 
                FAKE_PUB_KEY,
                CONTENT,
                textResult,
            );

            if (verifyResult) {

                console.info(`[${algoName}][Text] Verification matched.`);
            }
            else {

                console.error(`[${algoName}][Text] Verification failed.`);
            }
        }
        catch (e) {

            console.error(`[${algoName}][Text] Not supported with RSASSA-PKCS1-v1.5.`);
        }

        try {
            // do some file signing

            const fileResult = await Signs.RSA.signStream(
                algo,
                PRI_KEY,
                $fs.createReadStream(BIG_FILE_PATH)
            );

            const verifyResult = await Signs.RSA.verifyStream(
                algo, 
                PUB_KEY,
                $fs.createReadStream(BIG_FILE_PATH),
                fileResult,
            ) && !await Signs.RSA.verifyStream(
                algo, 
                FAKE_PUB_KEY,
                $fs.createReadStream(BIG_FILE_PATH),
                fileResult,
            );

            if (verifyResult) {

                console.info(`[${algoName}][File] Verification matched.`);
            }
            else {

                console.error(`[${algoName}][File] Verification failed.`);
            }
        }
        catch (e) {

            console.error(`[${algoName}][File] Not supported with RSASSA-PKCS1-v1.5.`);
        }
    }
})();
