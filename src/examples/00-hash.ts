/**
 * Copyright 2025 Angus.Fenying <fenying@litert.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as NodeFS from 'node:fs';
import * as LibSg from '../lib';

const CONTENT = 'Hello, how are you?\n';

const DEBUG_DIR = `${__dirname}/../data`;

const BIG_FILE_PATH = `${DEBUG_DIR}/bigfile.dat`;

(async () => {

    const hashS256 = LibSg.Hash.hash('sha256', CONTENT);

    console.log('[sha256] Hash:', hashS256.toString('hex'));

    const hashStreamS512 = await LibSg.Hash.hashStream('sha512', NodeFS.createReadStream(BIG_FILE_PATH));

    console.log('[sha512-stream] Hash:', hashStreamS512.toString('hex'));

    const hasherMD5 = LibSg.Hash.createHasher('md5');

    console.log('[md5] Hash:', hasherMD5.hash(CONTENT).toString('hex'));
    console.log('[md5-stream] Hash:', (await hasherMD5.hashStream(NodeFS.createReadStream(BIG_FILE_PATH))).toString('hex'));
})();
