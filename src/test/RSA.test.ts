import * as NodeTest from 'node:test';
import * as NodeAssert from 'node:assert';
import * as NodeCrypto from 'node:crypto';
import * as NodeFS from 'node:fs';
import * as LibRSA from '../lib/RSA';
import * as Errors from '../lib/Errors';
import { opensslSign, opensslVerify } from './utils-openssl-cli';

const TMP_DIR = `${__dirname}/../data`;
const TMP_FILE_OUT = `${TMP_DIR}/rsa-openssl.tmp`;
const TMP_FILE_IN = `${TMP_DIR}/rsa.tmp`;
const TMP_SIG = `${TMP_DIR}/rsa.sig`;

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

const RSA_2048_PUB_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/rsa-pub-2048.pem`, { 'encoding': 'utf-8' });
const RSA_2048_PUB_KEY = NodeCrypto.createPublicKey({
    key: RSA_2048_PUB_KEY_PEM,
    format: 'pem',
});

const RSA_2048_PRIV_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/rsa-priv-2048.pem`, { 'encoding': 'utf-8' });
const RSA_2048_PRIV_KEY = NodeCrypto.createPrivateKey({
    key: RSA_2048_PRIV_KEY_PEM,
    format: 'pem',
});

const RSA_1024_PRIV_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/rsa-priv-1024.pem`, { 'encoding': 'utf-8' });
const RSA_1024_PRIV_KEY = NodeCrypto.createPrivateKey({
    key: RSA_1024_PRIV_KEY_PEM,
    format: 'pem',
});

NodeFS.mkdirSync(TMP_DIR, { recursive: true });

NodeTest.describe('RSA', async () => {

    await NodeTest.describe('function sign/verify', async () => {

        for (const keyLen of [1024, 2048, 3072, 4096]) {

            for (const alg of LibRSA.getSupportedAlgorithms()) {

                await testFnSignVerify(
                    `rsa-${keyLen}-${alg}`,
                    `${TMP_DIR}/rsa-priv-${keyLen}.pem`,
                    `${TMP_DIR}/rsa-pub-${keyLen}.pem`,
                    alg,
                    {},
                    `${TMP_DIR}/rsa-wrong-priv-${keyLen}.pem`
                );

                await testFnSignVerify(
                    `rsa-${keyLen}-${alg}-with-key-passphrase`,
                    `${TMP_DIR}/rsa-passphrase-priv-${keyLen}.pem`,
                    `${TMP_DIR}/rsa-passphrase-pub-${keyLen}.pem`,
                    alg,
                    { 'keyPassphrase': 'test_pass' }
                );
            }
        }

        NodeTest.it('should throw an error if the key is not valid', () => {

            // Bad private keys
            for (const [key, error, opts] of [
                ['', Errors.E_SIGN_FAILED, {}],
                ['abc', Errors.E_SIGN_FAILED, {}],
                [Buffer.from('abc'), Errors.E_SIGN_FAILED, {}],
                [ED25519_PUB_KEY, Errors.E_INVALID_PRIVATE_KEY, {}],
                [ED25519_PRIV_KEY, Errors.E_INVALID_PRIVATE_KEY, {}],
            ] as const) {

                try {

                    LibRSA.sign('sha256', key, 'test', opts);
                    NodeAssert.fail(`Expected exception to be thrown for key: ${key}`);
                }
                catch (e) {

                    NodeAssert.strictEqual(e instanceof error, true);
                }
            }

            // Bad public keys
            for (const [key, error, opts] of [
                ['', Errors.E_VERIFY_FAILED, {}],
                ['abc', Errors.E_VERIFY_FAILED, {}],
                [Buffer.from('abc'), Errors.E_VERIFY_FAILED, {}],
                [ED25519_PRIV_KEY, Errors.E_INVALID_PUBLIC_KEY, {}],
                [ED25519_PUB_KEY, Errors.E_INVALID_PUBLIC_KEY, {}],
            ] as const) {

                try {

                    LibRSA.verify('sha256', key, 'test', Buffer.from('test'), opts);
                    NodeAssert.fail(`Expected exception to be thrown for key: ${key}`);
                }
                catch (e) {

                    NodeAssert.strictEqual(e instanceof error, true);
                }
            }
        });
    });

    await NodeTest.describe('class RsaSigner', async () => {

        NodeTest.it('should throw exception if no keys provided', async () => {

            try {
                LibRSA.createSigner(
                    'sha256',
                    '',
                    '',
                );
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NO_KEY_PROVIDED, true);
            }
        });

        NodeTest.it('should throw exception if key can not be used', async () => {

            for (const [pub, key, err] of [
                [ // key algorithm mismatch
                    RSA_2048_PUB_KEY,
                    RSA_1024_PRIV_KEY,
                    Errors.E_KEY_PAIR_MISMATCH,
                ],
                [ // invalid public key content
                    'shit',
                    RSA_2048_PRIV_KEY,
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid public key type
                    RSA_2048_PRIV_KEY,
                    'shit',
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid public key algorithm
                    ED25519_PUB_KEY,
                    RSA_2048_PUB_KEY,
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid private key content
                    RSA_2048_PUB_KEY,
                    'shit',
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
                [ // invalid private key type
                    RSA_2048_PUB_KEY,
                    RSA_2048_PUB_KEY,
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
                [ // invalid private key algorithm
                    RSA_2048_PUB_KEY,
                    ED25519_PRIV_KEY,
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
                [ // invalid public key value type
                    123 as unknown as NodeCrypto.KeyObject,
                    RSA_2048_PUB_KEY,
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid private key value type
                    RSA_2048_PUB_KEY,
                    123 as unknown as NodeCrypto.KeyObject,
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
            ] as const) {

                try {
                    LibRSA.createSigner('sha256', pub, key);
                    NodeAssert.fail('Expected exception to be thrown');
                }
                catch (e) {

                    NodeAssert.strictEqual(e instanceof err, true);
                }
            }
        });

        NodeTest.it('should throw error when signing without private key', async () => {

            const pub = NodeFS.readFileSync(`${TMP_DIR}/rsa-pub-1024.pem`, { 'encoding': 'utf-8' });

            const signer = LibRSA.createSigner('sha256', pub, null);

            NodeAssert.strictEqual(signer.hashAlgorithm, 'sha256');
            NodeAssert.strictEqual(signer.signAlgorithm, 'rsa');

            try {
                signer.sign('test data');
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NO_PRIVATE_KEY, true);
            }
            try {
                await signer.signStream(NodeFS.createReadStream(`${TMP_DIR}/rsa-pub-1024.pem`));
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NO_PRIVATE_KEY, true);
            }
        });

        NodeTest.it('should throw error when verifying without public key', async () => {

            const key = NodeFS.readFileSync(`${TMP_DIR}/rsa-priv-1024.pem`, { 'encoding': 'utf-8' });

            const signer = LibRSA.createSigner('sha256', null, key);

            NodeAssert.strictEqual(signer.hashAlgorithm, 'sha256');
            NodeAssert.strictEqual(signer.signAlgorithm, 'rsa');

            try {
                signer.verify('test data', Buffer.from('test signature'));
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NO_PUBLIC_KEY, true);
            }

            try {
                await signer.verifyStream(NodeFS.createReadStream(`${TMP_DIR}/rsa-pub-1024.pem`), Buffer.from('test signature'));
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_NO_PUBLIC_KEY, true);
            }
        });

        NodeTest.it('should throw error when failed to sign', async () => {

            const key = NodeFS.readFileSync(`${TMP_DIR}/rsa-priv-1024.pem`, { 'encoding': 'utf-8' });

            const signer = LibRSA.createSigner('sha256', null, key, {
                padding: 'pss-mgf1',
                saltLength: 32123, // Invalid salt length for RSA-1024
            });

            NodeAssert.strictEqual(signer.hashAlgorithm, 'sha256');
            NodeAssert.strictEqual(signer.signAlgorithm, 'rsa');

            try {
                signer.sign('test data');
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_SIGN_FAILED, true);
            }

            try {
                await signer.signStream(NodeFS.createReadStream(`${TMP_DIR}/rsa-pub-1024.pem`));
                NodeAssert.fail('Expected exception to be thrown');
            }
            catch (e) {

                NodeAssert.strictEqual(e instanceof Errors.E_SIGN_FAILED, true);
            }
        });
    });

    await NodeTest.describe('function signStream/verifyStream', async () => {

        for (const keyLen of [1024, 2048, 3072, 4096]) {

            for (const alg of LibRSA.getSupportedAlgorithms()) {

                await testFnSignVerifyStream(
                    `rsa-${keyLen}-${alg}`,
                    `${TMP_DIR}/rsa-priv-${keyLen}.pem`,
                    `${TMP_DIR}/rsa-pub-${keyLen}.pem`,
                    alg,
                    {},
                    `${TMP_DIR}/rsa-wrong-priv-${keyLen}.pem`
                );

                await testFnSignVerifyStream(
                    `rsa-${keyLen}-${alg}-with-key-passphrase`,
                    `${TMP_DIR}/rsa-passphrase-priv-${keyLen}.pem`,
                    `${TMP_DIR}/rsa-passphrase-pub-${keyLen}.pem`,
                    alg,
                    { 'keyPassphrase': 'test_pass' }
                );
            }
        }
    });
});

function testFnSignVerify(
    title: string,
    keyPath: string,
    pubPath: string,
    alg: LibRSA.IAlgorithms,
    opts?: LibRSA.IRsaOptions,
    badKeyPath: string = keyPath,
) {

    return NodeTest.it(title, async () => {

        const data = NodeCrypto.randomBytes(256).toString('hex');

        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });
        const key = NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' });

        const signer = LibRSA.createSigner(alg, pub, key, opts);

        const sig1Hex = await opensslSign(alg, keyPath, TMP_FILE_OUT, data);
        const sig1 = Buffer.from(sig1Hex, 'hex');
        const sig2 = signer.sign(data);
        const sig3 = LibRSA.sign(alg, key, data, opts);

        NodeAssert.strictEqual(signer.hashAlgorithm, alg);
        NodeAssert.strictEqual(signer.signAlgorithm, 'rsa');

        NodeAssert.strictEqual(LibRSA.verify(alg, pub, data, sig1, opts), true);
        NodeAssert.strictEqual(LibRSA.verify(alg, pub, data, sig2, opts), true);
        NodeAssert.strictEqual(LibRSA.verify(alg, pub, data, sig3, opts), true);

        NodeAssert.strictEqual(signer.verify(data, sig1), true);
        NodeAssert.strictEqual(signer.verify(data, sig2), true);
        NodeAssert.strictEqual(signer.verify(data, sig3), true);

        NodeAssert.strictEqual(await opensslVerify(alg, pubPath, TMP_FILE_OUT, TMP_SIG, data, sig2), true);
        NodeAssert.strictEqual(await opensslVerify(alg, pubPath, TMP_FILE_OUT, TMP_SIG, data, sig3), true);

        if (badKeyPath !== keyPath) {

            const badKey = NodeFS.readFileSync(badKeyPath, { 'encoding': 'utf-8' });
            const badSigner = LibRSA.createSigner(alg, pub, badKey, opts);

            const badSig1Hex = await opensslSign(alg, badKeyPath, TMP_FILE_OUT, data);
            const badSig1 = Buffer.from(badSig1Hex, 'hex');
            const badSig2 = badSigner.sign(data);
            const badSig3 = LibRSA.sign(alg, badKey, data, opts);

            NodeAssert.strictEqual(LibRSA.verify(alg, pub, data, badSig1, opts), false);
            NodeAssert.strictEqual(LibRSA.verify(alg, pub, data, badSig2, opts), false);
            NodeAssert.strictEqual(LibRSA.verify(alg, pub, data, badSig3, opts), false);

            NodeAssert.strictEqual(badSigner.verify(data, badSig1), false);
            NodeAssert.strictEqual(badSigner.verify(data, badSig2), false);
            NodeAssert.strictEqual(badSigner.verify(data, badSig3), false);

            NodeAssert.strictEqual(await opensslVerify(alg, pubPath, TMP_FILE_OUT, TMP_SIG, data, badSig2), false);
            NodeAssert.strictEqual(await opensslVerify(alg, pubPath, TMP_FILE_OUT, TMP_SIG, data, badSig3), false);
        }
    });
}

function testFnSignVerifyStream(
    title: string,
    keyPath: string,
    pubPath: string,
    alg: LibRSA.IAlgorithms,
    opts?: LibRSA.IRsaOptions,
    badKeyPath: string = keyPath,
) {

    return NodeTest.it(title, async () => {

        const data = NodeCrypto.randomBytes(256).toString('hex');

        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });
        const key = NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' });

        NodeFS.writeFileSync(TMP_FILE_IN, data);

        const signer = LibRSA.createSigner(alg, pub, key, opts);

        const sig1Hex = await opensslSign(alg, keyPath, TMP_FILE_OUT, data);
        const sig1 = Buffer.from(sig1Hex, 'hex');
        const sig2 = await signer.signStream(getStream());
        const sig3 = await LibRSA.signStream(alg, key, getStream(), opts);

        function getStream() {

            return NodeFS.createReadStream(TMP_FILE_IN);
        }

        NodeAssert.strictEqual(signer.hashAlgorithm, alg);
        NodeAssert.strictEqual(signer.signAlgorithm, 'rsa');

        NodeAssert.strictEqual(await LibRSA.verifyStream(alg, pub, getStream(), sig1, opts), true);
        NodeAssert.strictEqual(await LibRSA.verifyStream(alg, pub, getStream(), sig2, opts), true);
        NodeAssert.strictEqual(await LibRSA.verifyStream(alg, pub, getStream(), sig3, opts), true);

        NodeAssert.strictEqual(await signer.verifyStream(getStream(), sig1), true);
        NodeAssert.strictEqual(await signer.verifyStream(getStream(), sig2), true);
        NodeAssert.strictEqual(await signer.verifyStream(getStream(), sig3), true);

        NodeAssert.strictEqual(await opensslVerify(alg, pubPath, TMP_FILE_OUT, TMP_SIG, data, sig2), true);
        NodeAssert.strictEqual(await opensslVerify(alg, pubPath, TMP_FILE_OUT, TMP_SIG, data, sig3), true);

        if (badKeyPath !== keyPath) {

            const badKey = NodeFS.readFileSync(badKeyPath, { 'encoding': 'utf-8' });

            const badSigner = LibRSA.createSigner(alg, pub, badKey, opts);

            const badSig1Hex = await opensslSign(alg, badKeyPath, TMP_FILE_OUT, data);
            const badSig1 = Buffer.from(badSig1Hex, 'hex');
            const badSig2 = await badSigner.signStream(getStream());
            const badSig3 = await LibRSA.signStream(alg, badKey, getStream(), opts);

            NodeAssert.strictEqual(await LibRSA.verifyStream(alg, pub, getStream(), badSig1, opts), false);
            NodeAssert.strictEqual(await LibRSA.verifyStream(alg, pub, getStream(), badSig2, opts), false);
            NodeAssert.strictEqual(await LibRSA.verifyStream(alg, pub, getStream(), badSig3, opts), false);

            NodeAssert.strictEqual(await badSigner.verifyStream(getStream(), badSig1), false);
            NodeAssert.strictEqual(await badSigner.verifyStream(getStream(), badSig2), false);
            NodeAssert.strictEqual(await badSigner.verifyStream(getStream(), badSig3), false);

            NodeAssert.strictEqual(await opensslVerify(alg, pubPath, TMP_FILE_OUT, TMP_SIG, data, badSig2), false);
            NodeAssert.strictEqual(await opensslVerify(alg, pubPath, TMP_FILE_OUT, TMP_SIG, data, badSig3), false);
        }
    });
}

