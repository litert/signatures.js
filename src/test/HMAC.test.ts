import * as NodeTest from 'node:test';
import * as NodeAssert from 'node:assert';
import * as NodeCrypto from 'node:crypto';
import * as NodeFS from 'node:fs';
import * as LibHMAC from '../lib/HMAC';
import { opensslHmac } from './utils-openssl-cli';

const TMP_DIR = `${__dirname}/../data`;
const TMP_FILE_IN = `${TMP_DIR}/hmac.tmp`;
const TMP_FILE_OUT = `${TMP_DIR}/hmac-openssl.tmp`;

NodeFS.mkdirSync(TMP_DIR, { recursive: true });

NodeTest.describe('HMAC', async () => {

    await NodeTest.describe('function sign/verify', async () => {

        for (const alg of LibHMAC.getSupportedAlgorithms()) {

            await NodeTest.it(`hmac-${alg}`, async () => {

                const d = NodeCrypto.randomBytes(256).toString('hex');
                const k = NodeCrypto.randomBytes(32).toString('hex');

                const signer = LibHMAC.createSigner(alg, k);

                const sig1Hex = await opensslHmac(alg, k, TMP_FILE_OUT, d);
                const sig2 = LibHMAC.sign(alg, k, d);
                const sig3 = signer.sign(d);

                NodeAssert.strictEqual(signer.hashAlgorithm, alg);
                NodeAssert.strictEqual(signer.signAlgorithm, 'hmac');

                NodeAssert.strictEqual(sig1Hex, sig2.toString('hex'));
                NodeAssert.strictEqual(sig1Hex, sig3.toString('hex'));
                
                NodeAssert.strictEqual(
                    LibHMAC.verify(
                        alg,
                        k,
                        d,
                        Buffer.from(sig1Hex, 'hex')
                    ),
                    true
                );

                NodeAssert.strictEqual(
                    signer.verify(d, Buffer.from(sig1Hex, 'hex')),
                    true
                );
            });
        }
    });

    await NodeTest.describe('function signStream/verifyStream', async () => {

        for (const alg of LibHMAC.getSupportedAlgorithms()) {

            await NodeTest.it(`hmac-${alg}`, async () => {

                const d = NodeCrypto.randomBytes(256).toString('hex');
                const k = NodeCrypto.randomBytes(32).toString('hex');

                NodeFS.writeFileSync(TMP_FILE_IN, d);

                const signer = LibHMAC.createSigner(alg, k);
                const sig1Hex = await opensslHmac(alg, k, TMP_FILE_OUT, d);
                const sig2 = await LibHMAC.signStream(alg, k, NodeFS.createReadStream(TMP_FILE_IN));
                const sig3 = await signer.signStream(NodeFS.createReadStream(TMP_FILE_IN));

                NodeAssert.strictEqual(sig1Hex, sig2.toString('hex'));
                NodeAssert.strictEqual(sig1Hex, sig3.toString('hex'));

                NodeAssert.strictEqual(
                    await LibHMAC.verifyStream(
                        alg,
                        k,
                        NodeFS.createReadStream(TMP_FILE_IN),
                        Buffer.from(sig1Hex, 'hex')
                    ),
                    true
                );

                NodeAssert.strictEqual(
                    await signer.verifyStream(NodeFS.createReadStream(TMP_FILE_IN), Buffer.from(sig1Hex, 'hex')),
                    true
                );
            });
        }
    });
});
