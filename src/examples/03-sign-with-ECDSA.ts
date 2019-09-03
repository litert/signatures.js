/**
 *  Copyright 2019 Angus.Fenying <fenying@litert.org>
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
import * as $fs from "fs";
import { printable } from "./utils";

const CONTENT = "Hello, how are you?";

const ENCODINGS: Signs.TSignature[] = ["base64", "buffer", "hex", "base64url"];

for (const ENC of ENCODINGS) {

    for (let a of Signs.ECDSA.getSupportedAlgorithms()) {

        const PRI_KEY = $fs.readFileSync(
            `${__dirname}/../test/ec${Signs.HASH_OUTPUT_BITS[a]}-priv.pem`,
            { encoding: "utf8" }
        );

        const PUB_KEY = $fs.readFileSync(
            `${__dirname}/../test/ec${Signs.HASH_OUTPUT_BITS[a]}-pub.pem`,
            { encoding: "utf8" }
        );

        const FAKE_PUB_KEY = $fs.readFileSync(
            `${__dirname}/../test/ec${Signs.HASH_OUTPUT_BITS[a]}-wrong-pub.pem`,
            { encoding: "utf8" }
        );

        const signer = Signs.ECDSA.createSigner(
            a,
            PUB_KEY,
            PRI_KEY,
            Signs.EECDSAFormat.IEEE_P1363,
            ENC
        );

        const fakeSigner = Signs.ECDSA.createSigner(
            a,
            FAKE_PUB_KEY,
            PRI_KEY,
            Signs.EECDSAFormat.IEEE_P1363,
            ENC
        );

        try {

            const signResult = signer.sign(CONTENT);

            const verifyResult = signer.verify(
                CONTENT,
                signResult
            ) && !fakeSigner.verify(CONTENT, signResult) &&
            Signs.ECDSA.verify(
                a,
                CONTENT,
                Signs.ECDSA.sign(a, CONTENT, { key: PRI_KEY, password: "" }),
                PUB_KEY
            );

            console.debug(`[${ENC}][${signer.hashAlgorithm}]: Result ${printable(signResult)}`);

            if (verifyResult) {

                console.info(`[${ENC}][${signer.hashAlgorithm}] Verification matched.`);
            }
            else {

                console.error(`[${ENC}][${signer.hashAlgorithm}] Verification failed.`);
            }
        }
        catch (e) {

            console.error(`[${ENC}][${signer.hashAlgorithm}] Not supported with RSASSA-PKCS1-v1.5.`);
        }
    }
}

(async () => {

    for (const ENC of ENCODINGS) {

        for (let a of Signs.ECDSA.getSupportedAlgorithms()) {

            const PRI_KEY = $fs.readFileSync(
                `${__dirname}/../test/ec${Signs.HASH_OUTPUT_BITS[a]}-priv.pem`,
                { encoding: "utf8" }
            );

            const PUB_KEY = $fs.readFileSync(
                `${__dirname}/../test/ec${Signs.HASH_OUTPUT_BITS[a]}-pub.pem`,
                { encoding: "utf8" }
            );

            const FAKE_PUB_KEY = $fs.readFileSync(
                `${__dirname}/../test/ec${Signs.HASH_OUTPUT_BITS[a]}-wrong-pub.pem`,
                { encoding: "utf8" }
            );

            const signer = Signs.ECDSA.createSigner(
                a,
                PUB_KEY,
                PRI_KEY,
                Signs.EECDSAFormat.IEEE_P1363,
                ENC
            );

            const fakeSigner = Signs.ECDSA.createSigner(
                a,
                FAKE_PUB_KEY,
                PRI_KEY,
                Signs.EECDSAFormat.IEEE_P1363,
                ENC
            );

            try {

                const signResult = await signer.sign(
                    $fs.createReadStream(`${__dirname}/../test/bigfile.dat`)
                );

                const verifyResult = (await signer.verify(
                    $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                    signResult
                )) && (!await fakeSigner.verify(
                    $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                    signResult
                )) &&
                (await Signs.ECDSA.verify(
                    a,
                    $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                    await Signs.ECDSA.sign(
                        a,
                        $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                        {
                            key: PRI_KEY,
                            password: ""
                        }
                    ),
                    PUB_KEY
                ));

                console.debug(`[${ENC}][${signer.hashAlgorithm}][Stream]: Result ${printable(signResult)}`);

                if (verifyResult) {

                    console.info(`[${ENC}][${signer.hashAlgorithm}][Stream] Verification matched.`);
                }
                else {

                    console.error(`[${ENC}][${signer.hashAlgorithm}][Stream] Verification failed.`);
                }
            }
            catch (e) {

                console.error(`[${ENC}][${signer.hashAlgorithm}][Stream] Not supported with RSASSA-PKCS1-v1.5.`);
            }
        }
    }
})();
