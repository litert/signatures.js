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

const CONTENT = 'Hello, how are you?\n';

const DEBUG_DIR = `${__dirname}/../data`;

const BIG_FILE_PATH = `${DEBUG_DIR}/bigfile.dat`;

(async () => {

    for (let algoName of Signs.Hash.getSupportedAlgorithms()) {

        const signer = Signs.Hash.createHasher(algoName);

        const result = signer.hash(CONTENT);
        const fileResult = await signer.hashStream($fs.createReadStream(BIG_FILE_PATH));

        if (
            Signs.Hash.hash(algoName, CONTENT).compare(result) === 0
            && (await Signs.Hash.hashStream(algoName, $fs.createReadStream(BIG_FILE_PATH))).compare(fileResult) === 0
        ) {

            console.info(`[${algoName}] Ok [Content: ${result.toString('hex')}, File: ${fileResult.toString('hex')}].`);
        }
        else {

            console.error(`[${algoName}] Failed.`);
        }
    }
    
})();
