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
import * as LibSig from '../lib';

const KEY = 'hello world!';

const CONTENT = 'Hello, how are you?';

const DEBUG_DIR = `${__dirname}/../data`;

const BIG_FILE_PATH = `${DEBUG_DIR}/bigfile.dat`;

(async () => {

    const sigS256 = LibSig.HMAC.sign('sha256', KEY, CONTENT);

    if (LibSig.HMAC.verify('sha256', KEY, CONTENT, sigS256)) {

        console.log('[hmac-sha256] Signature verification passed.');
    }
    else {

        console.error('[hmac-sha256] Signature verification failed.');
    }

    const sigS512 = await LibSig.HMAC.signStream('sha512', KEY, NodeFS.createReadStream(BIG_FILE_PATH));

    if (await LibSig.HMAC.verifyStream('sha512', KEY, NodeFS.createReadStream(BIG_FILE_PATH), sigS512)) {

        console.log('[hmac-sha512-stream] Signature verification passed.');
    }
    else {

        console.error('[hmac-sha512-stream] Signature verification failed.');
    }

})();
