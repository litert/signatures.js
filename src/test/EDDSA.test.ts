import * as NodeTest from 'node:test';
import * as NodeAssert from 'node:assert';
import * as NodeCrypto from 'node:crypto';
import * as NodeFS from 'node:fs';
import * as LibEDDSA from '../lib/EDDSA';
import * as Errors from '../lib/Errors';
import { opensslSign, opensslVerify } from './utils-openssl-cli';

const TMP_DIR = `${__dirname}/../data`;
const TMP_FILE_OUT = `${TMP_DIR}/eddsa-openssl.tmp`;
const TMP_SIG = `${TMP_DIR}/eddsa.sig`;

const RSA_PUB_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/rsa-pub-1024.pem`, { 'encoding': 'utf-8' });
const RSA_PUB_KEY = NodeCrypto.createPublicKey({
    key: RSA_PUB_KEY_PEM,
    format: 'pem',
});

const RSA_PRIV_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/rsa-priv-1024.pem`, { 'encoding': 'utf-8' });
const RSA_PRIV_KEY = NodeCrypto.createPrivateKey({
    key: RSA_PRIV_KEY_PEM,
    format: 'pem',
});

const EC_PUB_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/ec128-pub.pem`, { 'encoding': 'utf-8' });
const EC_PUB_KEY = NodeCrypto.createPublicKey({
    key: EC_PUB_KEY_PEM,
    format: 'pem',
});

const ED25519_PUB_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/ed25519-pub.pem`, { 'encoding': 'utf-8' });
const ED25519_PUB_KEY = NodeCrypto.createPublicKey({
    key: ED25519_PUB_KEY_PEM,
    format: 'pem',
});

const ED25519_PRIV_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/ed25519-priv.pem`, { 'encoding': 'utf-8' });
const ED25519_PRIV_KEY = NodeCrypto.createPrivateKey({
    key: ED25519_PRIV_KEY_PEM,
    format: 'pem',
});

const ED448_PUB_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/ed448-pub.pem`, { 'encoding': 'utf-8' });
const ED448_PUB_KEY = NodeCrypto.createPublicKey({
    key: ED448_PUB_KEY_PEM,
    format: 'pem',
});

const ED448_PRIV_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/ed448-priv.pem`, { 'encoding': 'utf-8' });
const ED448_PRIV_KEY = NodeCrypto.createPrivateKey({
    key: ED448_PRIV_KEY_PEM,
    format: 'pem',
});

NodeFS.mkdirSync(TMP_DIR, { recursive: true });

NodeTest.describe('EDDSA', async () => {

    await NodeTest.describe('function sign/verify', async () => {

        for (const keyType of ['ed25519', 'ed448'] as const) {

            await testFnSignVerify(
                `eddsa-${keyType}`,
                `${TMP_DIR}/${keyType}-priv.pem`,
                `${TMP_DIR}/${keyType}-pub.pem`,
                keyType,
                {},
                `${TMP_DIR}/${keyType}-wrong-priv.pem`
            );

            await testFnSignVerify(
                `eddsa-${keyType}-with-key-passphrase`,
                `${TMP_DIR}/${keyType}-passphrase-priv.pem`,
                `${TMP_DIR}/${keyType}-passphrase-pub.pem`,
                keyType,
                { 'keyPassphrase': 'test_pass' }
            );
        }

        const badPrivKeys = [
            '',
            'abc',
            Buffer.from(''),
            RSA_PUB_KEY,
            EC_PUB_KEY,
            RSA_PUB_KEY_PEM,
            EC_PUB_KEY,
        ];

        const badPubKeys = [
            '',
            'abc',
            Buffer.from(''),
        ];

        for (const k of badPrivKeys) {

            try {

                LibEDDSA.sign(k, 'test');
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_SIGN_FAILED, true);
            }
        }

        for (const k of badPubKeys) {

            try {

                LibEDDSA.verify(k, 'test', Buffer.from('test'));
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_VERIFY_FAILED, true);
            }
        }

        for (const k of badPrivKeys) {

            try {

                LibEDDSA.sign(k, 'test', { 'keyPassphrase': 'test_pass' });
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_SIGN_FAILED, true);
            }
        }
    });

    await NodeTest.describe('class EcdsaSigner', async () => {

        NodeTest.it('should throw exception if no keys provided', async () => {

            try {
                LibEDDSA.createSigner(
                    '',
                    '',
                    'ed25519',
                );
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NO_KEY_PROVIDED, true);
            }
        });

        NodeTest.it('should throw exception if key can not be used', async () => {

            for (const [alg, pub, key, err] of [
                [ // key algorithm mismatch
                    'ed25519',
                    ED25519_PUB_KEY,
                    ED448_PRIV_KEY,
                    Errors.E_KEY_PAIR_MISMATCH,
                ],
                [ // key algorithm mismatch
                    null,
                    ED25519_PUB_KEY,
                    ED448_PRIV_KEY,
                    Errors.E_KEY_PAIR_MISMATCH,
                ],
                [ // key algorithm mismatch
                    'ed25519',
                    ED448_PUB_KEY,
                    ED25519_PRIV_KEY,
                    Errors.E_KEY_PAIR_MISMATCH,
                ],
                [ // key algorithm mismatch
                    null,
                    ED448_PUB_KEY,
                    ED25519_PRIV_KEY,
                    Errors.E_KEY_PAIR_MISMATCH,
                ],
                [ // key algorithm mismatch
                    'ed25519',
                    ED448_PUB_KEY.export({
                        'type': 'spki',
                        'format': 'pem',
                    }),
                    ED25519_PRIV_KEY.export({
                        'type': 'pkcs8',
                        'format': 'pem',
                    }),
                    Errors.E_KEY_PAIR_MISMATCH,
                ],
                [ // invalid public key content
                    'ed25519',
                    'shit',
                    ED25519_PRIV_KEY,
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid public key type
                    'ed25519',
                    ED25519_PRIV_KEY,
                    'shit',
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid public key algorithm
                    'ed25519',
                    RSA_PUB_KEY,
                    ED25519_PUB_KEY,
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid private key content
                    'ed25519',
                    ED25519_PUB_KEY,
                    'shit',
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
                [ // invalid private key type
                    'ed25519',
                    ED25519_PUB_KEY,
                    ED25519_PUB_KEY,
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
                [ // invalid private key algorithm
                    'ed25519',
                    ED25519_PUB_KEY,
                    RSA_PRIV_KEY,
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
            ] as const) {

                try {
                    LibEDDSA.createSigner(pub, key, alg);
                    NodeAssert.fail('Expected exception to be thrown');
                }
                catch (e) {

                    NodeAssert.strictEqual(e instanceof err, true);
                }
            }
        });

        NodeTest.it('should throw error when signing without private key', async () => {

            const pub = NodeFS.readFileSync(`${TMP_DIR}/ed25519-pub.pem`, { 'encoding': 'utf-8' });

            const signer = LibEDDSA.createSigner(pub, null);

            NodeAssert.strictEqual(signer.hashAlgorithm, 'ed25519');
            NodeAssert.strictEqual(signer.signAlgorithm, 'eddsa');

            try {
                signer.sign('test data');
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NO_PRIVATE_KEY, true);
            }
        });

        NodeTest.it('should throw error when verifying without public key', async () => {

            const key = NodeFS.readFileSync(`${TMP_DIR}/ed25519-priv.pem`, { 'encoding': 'utf-8' });

            const signer = LibEDDSA.createSigner(null, key);

            NodeAssert.strictEqual(signer.hashAlgorithm, 'ed25519');
            NodeAssert.strictEqual(signer.signAlgorithm, 'eddsa');

            try {
                signer.verify('test data', Buffer.from('test signature'));
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NO_PUBLIC_KEY, true);
            }
        });
    });

    await NodeTest.describe('function signStream/verifyStream', async () => {

        NodeTest.it('should throw exception if signStream is called', async () => {

            NodeFS.writeFileSync(TMP_FILE_OUT, 'test data');

            const pub = NodeFS.readFileSync(`${TMP_DIR}/ed25519-pub.pem`, { 'encoding': 'utf-8' });
            const key = NodeFS.readFileSync(`${TMP_DIR}/ed25519-priv.pem`, { 'encoding': 'utf-8' });

            const signer = LibEDDSA.createSigner(pub, key);

            try {

                await signer.signStream(NodeFS.createReadStream(TMP_FILE_OUT));
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NOT_IMPLEMENTED, true);
            }
        });

        NodeTest.it('should throw exception if verifyStream is called', async () => {

            NodeFS.writeFileSync(TMP_FILE_OUT, 'test data');

            const pub = NodeFS.readFileSync(`${TMP_DIR}/ed25519-pub.pem`, { 'encoding': 'utf-8' });
            const key = NodeFS.readFileSync(`${TMP_DIR}/ed25519-priv.pem`, { 'encoding': 'utf-8' });

            const signer = LibEDDSA.createSigner(pub, key);

            try {

                await signer.verifyStream(NodeFS.createReadStream(TMP_FILE_OUT), NodeCrypto.randomBytes(64));
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NOT_IMPLEMENTED, true);
            }
        });
    });
});

function testFnSignVerify(
    title: string,
    keyPath: string,
    pubPath: string,
    alg: LibEDDSA.IAlgorithms,
    opts?: LibEDDSA.IEddsaOptions,
    badKeyPath: string = keyPath,
) {

    return NodeTest.it(title, async () => {

        const data = NodeCrypto.randomBytes(256).toString('hex');

        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });
        const key = NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' });

        const signer = LibEDDSA.createSigner(pub, key, alg, opts);

        const sig1Hex = await opensslSign('', keyPath, TMP_FILE_OUT, data);
        const sig1 = Buffer.from(sig1Hex, 'hex');
        const sig2 = signer.sign(data);
        const sig3 = LibEDDSA.sign(key, data, opts);

        NodeAssert.strictEqual(signer.hashAlgorithm, alg);
        NodeAssert.strictEqual(signer.signAlgorithm, 'eddsa');

        NodeAssert.strictEqual(LibEDDSA.verify(pub, data, sig1), true);
        NodeAssert.strictEqual(LibEDDSA.verify(pub, data, sig2), true);
        NodeAssert.strictEqual(LibEDDSA.verify(pub, data, sig3), true);

        NodeAssert.strictEqual(signer.verify(data, sig1), true);
        NodeAssert.strictEqual(signer.verify(data, sig2), true);
        NodeAssert.strictEqual(signer.verify(data, sig3), true);

        NodeAssert.strictEqual(await opensslVerify('', pubPath, TMP_FILE_OUT, TMP_SIG, data, sig2), true);
        NodeAssert.strictEqual(await opensslVerify('', pubPath, TMP_FILE_OUT, TMP_SIG, data, sig3), true);

        if (badKeyPath !== keyPath) {

            const badKey = NodeFS.readFileSync(badKeyPath, { 'encoding': 'utf-8' });
            const badSigner = LibEDDSA.createSigner(pub, badKey, alg, opts);

            const badSig1Hex = await opensslSign('', badKeyPath, TMP_FILE_OUT, data);
            const badSig1 = Buffer.from(badSig1Hex, 'hex');
            const badSig2 = badSigner.sign(data);
            const badSig3 = LibEDDSA.sign(badKey, data, opts);

            NodeAssert.strictEqual(LibEDDSA.verify(pub, data, badSig1), false);
            NodeAssert.strictEqual(LibEDDSA.verify(pub, data, badSig2), false);
            NodeAssert.strictEqual(LibEDDSA.verify(pub, data, badSig3), false);

            NodeAssert.strictEqual(badSigner.verify(data, badSig1), false);
            NodeAssert.strictEqual(badSigner.verify(data, badSig2), false);
            NodeAssert.strictEqual(badSigner.verify(data, badSig3), false);

            NodeAssert.strictEqual(await opensslVerify('', pubPath, TMP_FILE_OUT, TMP_SIG, data, badSig2), false);
            NodeAssert.strictEqual(await opensslVerify('', pubPath, TMP_FILE_OUT, TMP_SIG, data, badSig3), false);
        }
    });
}
