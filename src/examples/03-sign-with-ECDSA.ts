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

const CONTENT = 'Hello, how are you?';

const ECDSA_FORMAT = 'ieee-p1363'; // 'ieee-p1363'

const DEBUG_DIR = `${__dirname}/../data`;

const BIG_FILE_PATH = `${DEBUG_DIR}/bigfile.dat`;

Signs.ECDSA.enableNativeP1363();
(async () => {

    for (let algo of Signs.ECDSA.getSupportedAlgorithms()) {

        const algoName = `ecdsa-${algo}`;

        const outBits = algo === 'sha1' ? 160 :
                        /^sha\d{3}$/.test(algo) ? parseInt(algo.slice(3)) :
                        /^sha3-\d{3}$/.test(algo) ? parseInt(algo.slice(5)) :
                        512;

        const PRI_KEY = $fs.readFileSync(
            `${DEBUG_DIR}/ec${outBits}-priv.pem`,
            { encoding: 'utf8' }
        );

        const PUB_KEY = $fs.readFileSync(
            `${DEBUG_DIR}/ec${outBits}-pub.pem`,
            { encoding: 'utf8' }
        );

        const FAKE_PUB_KEY = $fs.readFileSync(
            `${DEBUG_DIR}/ec${outBits}-wrong-pub.pem`,
            { encoding: 'utf8' }
        );

        try {
            // do some text signing

            const textResult = Signs.ECDSA.sign(algo, PRI_KEY, CONTENT, { 'format': ECDSA_FORMAT });

            const verifyResult = Signs.ECDSA.verify(
                algo, 
                PUB_KEY,
                CONTENT,
                textResult,
                { 'format': ECDSA_FORMAT }
            ) && !Signs.ECDSA.verify(
                algo, 
                FAKE_PUB_KEY,
                CONTENT,
                textResult,
                { 'format': ECDSA_FORMAT }
            );

            if (verifyResult) {

                console.info(`[${algoName}][Text] Verification matched.`);
            }
            else {

                console.error(`[${algoName}][Text] Verification failed.`);
            }
        }
        catch (e) {

            console.error(`[${algoName}][Text] Not supported with ECDSA.`);
        }

        try {
            // do some file signing

            const fileResult = await Signs.ECDSA.signStream(
                algo,
                PRI_KEY,
                $fs.createReadStream(BIG_FILE_PATH),
                { 'format': ECDSA_FORMAT }
            );

            const verifyResult = await Signs.ECDSA.verifyStream(
                algo, 
                PUB_KEY,
                $fs.createReadStream(BIG_FILE_PATH),
                fileResult,
                { 'format': ECDSA_FORMAT }
            ) && !await Signs.ECDSA.verifyStream(
                algo, 
                FAKE_PUB_KEY,
                $fs.createReadStream(BIG_FILE_PATH),
                fileResult,
                { 'format': ECDSA_FORMAT }
            );

            // console.debug(`[${algo}]: Result ${printable(signResult)}`);

            if (verifyResult) {

                console.info(`[${algoName}][File] Verification matched.`);
            }
            else {

                console.error(`[${algoName}][File] Verification failed.`);
            }
        }
        catch (e) {

            console.error(`[${algoName}][File] Not supported with ECDSA.`);
        }
    }
})();
