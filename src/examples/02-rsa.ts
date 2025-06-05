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

const DEBUG_DIR = `${__dirname}/../data`;

const PRI_KEY = NodeFS.readFileSync(`${DEBUG_DIR}/rsa-priv-2048.pem`, {
    encoding: 'utf8'
});

const PUB_KEY = NodeFS.readFileSync(`${DEBUG_DIR}/rsa-pub-2048.pem`, {
    encoding: 'utf8'
});

const CONTENT = 'Hello, how are you?';

const BIG_FILE_PATH = `${DEBUG_DIR}/bigfile.dat`;

(async () => {

    const sigRsaS256 = LibSig.RSA.sign(
        'sha256',
        PRI_KEY,
        CONTENT,
    );

    if (LibSig.RSA.verify(
        'sha256',
        PUB_KEY,
        CONTENT,
        sigRsaS256
    )) {

        console.log('[rsa-sha256] Signature verification passed.');
    }
    else {

        console.error('[rsa-sha256] Signature verification failed.');
    }

    const sigRsaS512Stream = await LibSig.RSA.signStream(
        'sha512',
        PRI_KEY,
        NodeFS.createReadStream(BIG_FILE_PATH),
    );

    if (await LibSig.RSA.verifyStream(
        'sha512',
        PUB_KEY,
        NodeFS.createReadStream(BIG_FILE_PATH),
        sigRsaS512Stream
    )) {

        console.log('[rsa-sha512-stream] Signature verification passed.');
    }
    else {

        console.error('[rsa-sha512-stream] Signature verification failed.');
    }

    const rsaS384Signer = LibSig.RSA.createSigner(
        'sha384',
        PUB_KEY,
        PRI_KEY,
    );

    const sigRsaS384 = rsaS384Signer.sign(CONTENT);

    if (rsaS384Signer.verify(CONTENT, sigRsaS384)) {

        console.log('[rsa-sha384] Signature verification passed.');
    }
    else {

        console.error('[rsa-sha384] Signature verification failed.');
    }

    const sigS384Stream = await rsaS384Signer.signStream(
        NodeFS.createReadStream(BIG_FILE_PATH),
    );

    if (await rsaS384Signer.verifyStream(
        NodeFS.createReadStream(BIG_FILE_PATH),
        sigS384Stream
    )) {

        console.log('[rsa-sha384-stream] Signature verification passed.');
    }
    else {

        console.error('[rsa-sha384-stream] Signature verification failed.');
    }

})();
