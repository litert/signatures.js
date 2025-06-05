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

const testData = 'Hello, how are you?';

const DEBUG_DIR = `${__dirname}/../data`;

(async () => {

    const sigEd25519 = LibSig.EdDSA.sign(
        NodeFS.readFileSync(`${DEBUG_DIR}/ed25519-priv.pem`, { encoding: 'utf8' }),
        testData,
    );

    if (!LibSig.EdDSA.verify(
        NodeFS.readFileSync(`${DEBUG_DIR}/ed25519-pub.pem`, { encoding: 'utf8' }),
        testData,
        sigEd25519,
    )) {
        console.error('[ed25519] Signature verification failed.');
    }
    else {

        console.log('[ed25519] Signature verification passed.');
    }

    const sigEd448 = LibSig.EdDSA.sign(
        NodeFS.readFileSync(`${DEBUG_DIR}/ed448-priv.pem`, { encoding: 'utf8' }),
        testData,
    );

    if (!LibSig.EdDSA.verify(
        NodeFS.readFileSync(`${DEBUG_DIR}/ed448-pub.pem`, { encoding: 'utf8' }),
        testData,
        sigEd448,
    )) {
        console.error('[ed448] Signature verification failed.');
    }
    else {

        console.log('[ed448] Signature verification passed.');
    }

    // No stream support for EDDSA yet.
})();
