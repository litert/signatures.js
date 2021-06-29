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

const KEY = 'hello world!';

const FAKE_KEY = 'world hello!';

const CONTENT = 'Hello, how are you?';

const DEBUG_DIR = `${__dirname}/../data`;

const BIG_FILE_PATH = `${DEBUG_DIR}/bigfile.dat`;

(async () => {

    for (let algo of Signs.HMAC.getSupportedAlgorithms()) {

        const algoName = `hmac-${algo}`;

        const signer = Signs.HMAC.createSigner(algo, KEY);

        const fakeSigner = Signs.HMAC.createSigner(algo, FAKE_KEY);

        const result = signer.sign(CONTENT);
        const fileResult = await signer.signStream($fs.createReadStream(BIG_FILE_PATH));

        if (
            signer.verify(CONTENT, result)
            && !fakeSigner.verify(CONTENT, result)
            && Signs.HMAC.verify(algo, KEY, CONTENT, result) 
            && !Signs.HMAC.verify(algo, FAKE_KEY, CONTENT, result)
            
            && await signer.verifyStream($fs.createReadStream(BIG_FILE_PATH), fileResult)
            && !await fakeSigner.verifyStream($fs.createReadStream(BIG_FILE_PATH), fileResult)
            && await Signs.HMAC.verifyStream(algo, KEY, $fs.createReadStream(BIG_FILE_PATH), fileResult)
            && !await Signs.HMAC.verifyStream(algo, FAKE_KEY, $fs.createReadStream(BIG_FILE_PATH), fileResult)
            && 1
        ) {

            console.info(`[${algoName}] Verification matched.`);
        }
        else {

            console.error(`[${algoName}] Verification failed.`);
        }
    }
    

})();
