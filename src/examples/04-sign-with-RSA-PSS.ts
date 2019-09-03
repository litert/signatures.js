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

const PRI_KEY = $fs.readFileSync(`${__dirname}/../test/rsa-priv.pem`, {
    encoding: "utf8"
});

const PUB_KEY = $fs.readFileSync(`${__dirname}/../test/rsa-pub.pem`, {
    encoding: "utf8"
});

const FAKE_PUB_KEY = $fs.readFileSync(`${__dirname}/../test/rsa-wrong-pub.pem`, {
    encoding: "utf8"
});

const CONTENT = "Hello, how are you?";

for (let a of Signs.RSA.getSupportedAlgorithms()) {

    const signer = Signs.RSA.createSigner(
        a,
        PUB_KEY,
        PRI_KEY,
        Signs.ERSAPadding.PSS_MGF1,
        "base64"
    );

    const fakeSigner = Signs.RSA.createSigner(
        a,
        FAKE_PUB_KEY,
        PRI_KEY,
        Signs.ERSAPadding.PSS_MGF1,
        "base64"
    );

    try {

        const signResult = signer.sign(CONTENT);

        const verifyResult = signer.verify(
            CONTENT,
            signResult
        )
        && !fakeSigner.verify(CONTENT, signResult)
        && Signs.RSA.verify(a, CONTENT, Buffer.from(signResult, "base64"), PUB_KEY, {
            padding: Signs.ERSAPadding.PSS_MGF1
        });

        console.debug(`[${signer.hashAlgorithm}]: Result ${signResult}`);

        if (verifyResult) {

            console.info(`[${signer.hashAlgorithm}] Verification matched.`);
        }
        else {

            console.error(`[${signer.hashAlgorithm}] Verification failed.`);
        }
    }
    catch (e) {

        console.error(`[${signer.hashAlgorithm}] Not supported with RSASSA-PKCS1-v1.5.`);
    }
}

(async () => {

    for (let a of Signs.RSA.getSupportedAlgorithms()) {

        const signer = Signs.RSA.createSigner(
            a,
            PUB_KEY,
            PRI_KEY,
            Signs.ERSAPadding.PSS_MGF1,
            "base64"
        );

        const fakeSigner = Signs.RSA.createSigner(
            a,
            FAKE_PUB_KEY,
            PRI_KEY,
            Signs.ERSAPadding.PSS_MGF1,
            "base64"
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
            (await Signs.RSA.verify(
                a,
                $fs.createReadStream(`${__dirname}/../test/bigfile.dat`),
                Buffer.from(signResult, "base64"),
                PUB_KEY,
                { padding: Signs.ERSAPadding.PSS_MGF1 }
            ));

            console.debug(`[${signer.hashAlgorithm}][Stream]: Result ${signResult}`);

            if (verifyResult) {

                console.info(`[${signer.hashAlgorithm}][Stream] Verification matched.`);
            }
            else {

                console.error(`[${signer.hashAlgorithm}][Stream] Verification failed.`);
            }
        }
        catch (e) {

            console.error(`[${signer.hashAlgorithm}][Stream] Not supported with RSASSA-PKCS1-v1.5.`);
        }
    }

})();
