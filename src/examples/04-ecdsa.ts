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

const PRI_KEY = NodeFS.readFileSync(`${DEBUG_DIR}/ec256-priv.pem`, {
    encoding: 'utf8'
});

const PUB_KEY = NodeFS.readFileSync(`${DEBUG_DIR}/ec256-pub.pem`, {
    encoding: 'utf8'
});

const CONTENT = 'Hello, how are you?';

const BIG_FILE_PATH = `${DEBUG_DIR}/bigfile.dat`;

(async () => {

    const sigEcdsaS256 = LibSig.EcDSA.sign(
        'sha256',
        PRI_KEY,
        CONTENT,
    );

    if (LibSig.EcDSA.verify(
        'sha256',
        PUB_KEY,
        CONTENT,
        sigEcdsaS256
    )) {

        console.log('[ecdsa-sha256] Signature verification passed.');
    }
    else {

        console.error('[ecdsa-sha256] Signature verification failed.');
    }

    const sigEcdsaS512Stream = await LibSig.EcDSA.signStream(
        'sha512',
        PRI_KEY,
        NodeFS.createReadStream(BIG_FILE_PATH),
    );

    if (await LibSig.EcDSA.verifyStream(
        'sha512',
        PUB_KEY,
        NodeFS.createReadStream(BIG_FILE_PATH),
        sigEcdsaS512Stream
    )) {

        console.log('[ecdsa-sha512-stream] Signature verification passed.');
    }
    else {

        console.error('[ecdsa-sha512-stream] Signature verification failed.');
    }

    const ecdsaS384Signer = LibSig.EcDSA.createSigner(
        'sha384',
        PUB_KEY,
        PRI_KEY,
    );

    const sigEcdsaS384 = ecdsaS384Signer.sign(CONTENT);

    if (ecdsaS384Signer.verify(CONTENT, sigEcdsaS384)) {

        console.log('[ecdsa-sha384] Signature verification passed.');
    }
    else {

        console.error('[ecdsa-sha384] Signature verification failed.');
    }

    const sigS384Stream = await ecdsaS384Signer.signStream(
        NodeFS.createReadStream(BIG_FILE_PATH),
    );

    if (await ecdsaS384Signer.verifyStream(
        NodeFS.createReadStream(BIG_FILE_PATH),
        sigS384Stream
    )) {

        console.log('[ecdsa-sha384-stream] Signature verification passed.');
    }
    else {

        console.error('[ecdsa-sha384-stream] Signature verification failed.');
    }

})();
