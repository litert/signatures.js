import * as NodeAssert from 'node:assert';
import * as NodeCrypto from 'node:crypto';
import * as NodeFS from 'node:fs';
import * as NodeTest from 'node:test';
import * as LibECDSA from '../lib/ECDSA';
import * as Errors from '../lib/Errors';
import { opensslSign, opensslVerify } from './utils-openssl-cli';

const TMP_DIR = `${__dirname}/../data`;

NodeFS.mkdirSync(TMP_DIR, { recursive: true });

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

const EC128_PUB_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/ec128-pub.pem`, { 'encoding': 'utf-8' });
const EC128_PUB_KEY = NodeCrypto.createPublicKey({
    key: EC128_PUB_KEY_PEM,
    format: 'pem',
});

const EC128_PRIV_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/ec128-priv.pem`, { 'encoding': 'utf-8' });
const EC128_PRIV_KEY = NodeCrypto.createPrivateKey({
    key: EC128_PRIV_KEY_PEM,
    format: 'pem',
});

const EC256_PRIV_KEY_PEM = NodeFS.readFileSync(`${TMP_DIR}/ec256-priv.pem`, { 'encoding': 'utf-8' });
const EC256_PRIV_KEY = NodeCrypto.createPrivateKey({
    key: EC256_PRIV_KEY_PEM,
    format: 'pem',
});

function testFnSignP1363(alg: LibECDSA.IAlgorithms, keyLen: string) {

    return NodeTest.it(`ecdsa-${alg}-with-ec${keyLen}-ieee-p1363`, async () => {

        const d = NodeCrypto.randomBytes(256).toString('hex');
        const keyPath = `${TMP_DIR}/ec${keyLen}-priv.pem`;
        const pubPath = `${TMP_DIR}/ec${keyLen}-pub.pem`;
        const tmpPathData = `${TMP_DIR}/ecdsa-sign-${alg}-data.tmp`;
        const tmpPathSig = `${TMP_DIR}/ecdsa-sign-${alg}-sig.tmp`;
        const key = NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' });
        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });

        const signer = LibECDSA.createSigner(
            alg,
            pub,
            NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' }),
            { format: 'ieee-p1363' }
        );

        const sig1 = LibECDSA.sign(alg, key, d, { format: 'ieee-p1363' });
        const sig2 = signer.sign(d);

        NodeFS.writeFileSync(tmpPathData, d);

        NodeAssert.strictEqual(
            await opensslVerify(alg, pubPath, tmpPathData, tmpPathSig, d, LibECDSA.p1363ToDER(sig1)),
            true
        );

        NodeAssert.strictEqual(
            await opensslVerify(alg, pubPath, tmpPathData, tmpPathSig, d, LibECDSA.p1363ToDER(sig2)),
            true
        );

        NodeAssert.strictEqual(
            LibECDSA.verify(alg, pub, d, sig1, { format: 'ieee-p1363' }),
            true
        );

        NodeAssert.strictEqual(
            LibECDSA.verify(alg, pub, d, sig2, { format: 'ieee-p1363' }),
            true
        );

        NodeAssert.strictEqual(
            signer.verify(d, sig1),
            true
        );

        NodeAssert.strictEqual(
            signer.verify(d, sig2),
            true
        );
    });
}

function testFnSignDER(alg: LibECDSA.IAlgorithms, keyLen: string) {

    return NodeTest.it(`ecdsa-${alg}-with-ec${keyLen}-der`, async () => {

        const d = NodeCrypto.randomBytes(256).toString('hex');
        const keyPath = `${TMP_DIR}/ec${keyLen}-priv.pem`;
        const pubPath = `${TMP_DIR}/ec${keyLen}-pub.pem`;
        const tmpPathData = `${TMP_DIR}/ecdsa-sign-${alg}-data.tmp`;
        const tmpPathSig = `${TMP_DIR}/ecdsa-sign-${alg}-sig.tmp`;
        const key = NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' });
        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });

        const signer = LibECDSA.createSigner(
            alg,
            pub,
            NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' }),
            { format: 'der' }
        );

        const sig1 = LibECDSA.sign(alg, key, d, { format: 'der' });
        const sig2 = signer.sign(d);

        NodeFS.writeFileSync(tmpPathData, d);

        NodeAssert.strictEqual(
            await opensslVerify(alg, pubPath, tmpPathData, tmpPathSig, d, sig1),
            true
        );

        NodeAssert.strictEqual(
            await opensslVerify(alg, pubPath, tmpPathData, tmpPathSig, d, sig2),
            true
        );

        NodeAssert.strictEqual(
            LibECDSA.verify(alg, pub, d, sig1, { format: 'der' }),
            true
        );

        NodeAssert.strictEqual(
            LibECDSA.verify(alg, pub, d, sig2, { format: 'der' }),
            true
        );

        NodeAssert.strictEqual(
            signer.verify(d, sig1),
            true
        );

        NodeAssert.strictEqual(
            signer.verify(d, sig2),
            true
        );
    });
}

function testFnVerifyStreamDER(alg: LibECDSA.IAlgorithms, keyLen: string) {

    return NodeTest.it(`ecdsa-${alg}-with-ec${keyLen}-der`, async () => {

        const d = NodeCrypto.randomBytes(256).toString('hex');
        const keyPath = `${TMP_DIR}/ec${keyLen}-priv.pem`;
        const pubPath = `${TMP_DIR}/ec${keyLen}-pub.pem`;
        const tmpPathIn = `${TMP_DIR}/ecdsa-verify-stream-${alg}-in.tmp`;
        const tmpPathOut = `${TMP_DIR}/ecdsa-verify-stream-${alg}-openssl.tmp`;
        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });

        const signer = LibECDSA.createSigner(
            alg,
            pub,
            NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' }),
            { format: 'der' }
        );

        NodeAssert.strictEqual(signer.hashAlgorithm, alg);
        NodeAssert.strictEqual(signer.signAlgorithm, 'ecdsa');

        NodeFS.writeFileSync(tmpPathIn, d);

        const osSig = await opensslSign(alg, keyPath, tmpPathOut, d);

        NodeAssert.strictEqual(
            await LibECDSA.verifyStream(alg, pub, NodeFS.createReadStream(tmpPathIn), Buffer.from(osSig, 'hex'), { format: 'der' }),
            true
        );

        NodeAssert.strictEqual(
            await signer.verifyStream(NodeFS.createReadStream(tmpPathIn), Buffer.from(osSig, 'hex')),
            true
        );
    });
}

function testFnVerifyStreamP1363(alg: LibECDSA.IAlgorithms, keyLen: string) {

    return NodeTest.it(`ecdsa-${alg}-with-ec${keyLen}-ieee-p1363`, async () => {

        const d = NodeCrypto.randomBytes(256).toString('hex');
        const keyPath = `${TMP_DIR}/ec${keyLen}-priv.pem`;
        const pubPath = `${TMP_DIR}/ec${keyLen}-pub.pem`;
        const tmpPathIn = `${TMP_DIR}/ecdsa-verify-stream-${alg}-in.tmp`;
        const tmpPathOut = `${TMP_DIR}/ecdsa-verify-stream-${alg}-openssl.tmp`;
        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });

        const signer = LibECDSA.createSigner(
            alg,
            pub,
            NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' }),
            { format: 'ieee-p1363' }
        );

        NodeFS.writeFileSync(tmpPathIn, d);

        const osSig = LibECDSA.derToP1363(Buffer.from(await opensslSign(alg, keyPath, tmpPathOut, d), 'hex'));

        NodeAssert.strictEqual(
            await LibECDSA.verifyStream(alg, pub, NodeFS.createReadStream(tmpPathIn), osSig, { format: 'ieee-p1363' }),
            true
        );

        NodeAssert.strictEqual(
            await signer.verifyStream(NodeFS.createReadStream(tmpPathIn), osSig),
            true
        );
    });
}

function testFnSignStreamDER(alg: LibECDSA.IAlgorithms, keyLen: string) {

    return NodeTest.it(`ecdsa-${alg}-with-ec${keyLen}-der`, async () => {

        const d = NodeCrypto.randomBytes(256).toString('hex');
        const keyPath = `${TMP_DIR}/ec${keyLen}-priv.pem`;
        const pubPath = `${TMP_DIR}/ec${keyLen}-pub.pem`;
        const tmpPathData = `${TMP_DIR}/ecdsa-sign-${alg}-data.tmp`;
        const tmpPathSig = `${TMP_DIR}/ecdsa-sign-${alg}-sig.tmp`;
        const key = NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' });
        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });

        NodeFS.writeFileSync(tmpPathData, d);

        const signer = LibECDSA.createSigner(
            alg,
            pub,
            key,
            { format: 'der' }
        );

        const sig1 = await LibECDSA.signStream(
            alg,
            key,
            NodeFS.createReadStream(tmpPathData),
            { format: 'der' }
        );

        const sig2 = await signer.signStream(NodeFS.createReadStream(tmpPathData));

        NodeAssert.strictEqual(
            await opensslVerify(alg, pubPath, tmpPathData, tmpPathSig, d, sig1),
            true
        );

        NodeAssert.strictEqual(
            await opensslVerify(alg, pubPath, tmpPathData, tmpPathSig, d, sig2),
            true
        );

        NodeAssert.strictEqual(
            await LibECDSA.verifyStream(
                alg,
                pub,
                NodeFS.createReadStream(tmpPathData),
                sig1,
                { format: 'der' }
            ),
            true
        );

        NodeAssert.strictEqual(
            await LibECDSA.verifyStream(
                alg,
                pub,
                NodeFS.createReadStream(tmpPathData),
                sig2,
                { format: 'der' }
            ),
            true
        );

        NodeAssert.strictEqual(
            await signer.verifyStream(
                NodeFS.createReadStream(tmpPathData),
                sig1
            ),
            true
        );

        NodeAssert.strictEqual(
            await signer.verifyStream(
                NodeFS.createReadStream(tmpPathData),
                sig2
            ),
            true
        );
    });
}

function testFnSignStreamP1363(alg: LibECDSA.IAlgorithms, keyLen: string) {

    return NodeTest.it(`ecdsa-${alg}-with-ec${keyLen}-ieee-p1363`, async () => {

        const d = NodeCrypto.randomBytes(256).toString('hex');
        const keyPath = `${TMP_DIR}/ec${keyLen}-priv.pem`;
        const pubPath = `${TMP_DIR}/ec${keyLen}-pub.pem`;
        const tmpPathData = `${TMP_DIR}/ecdsa-sign-${alg}-data.tmp`;
        const tmpPathSig = `${TMP_DIR}/ecdsa-sign-${alg}-sig.tmp`;
        const key = NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' });
        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });

        const signer = LibECDSA.createSigner(
            alg,
            pub,
            NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' }),
            { format: 'ieee-p1363' }
        );

        NodeFS.writeFileSync(tmpPathData, d);

        const sig1 = await LibECDSA.signStream(
            alg,
            key,
            NodeFS.createReadStream(tmpPathData),
            { format: 'ieee-p1363' }
        );

        const sig2 = await signer.signStream(NodeFS.createReadStream(tmpPathData));

        NodeAssert.strictEqual(
            await opensslVerify(alg, pubPath, tmpPathData, tmpPathSig, d, LibECDSA.p1363ToDER(sig1)),
            true
        );

        NodeAssert.strictEqual(
            await opensslVerify(alg, pubPath, tmpPathData, tmpPathSig, d, LibECDSA.p1363ToDER(sig2)),
            true
        );

        NodeAssert.strictEqual(
            await LibECDSA.verifyStream(
                alg,
                pub,
                NodeFS.createReadStream(tmpPathData),
                sig1,
                { format: 'ieee-p1363' }
            ),
            true
        );

        NodeAssert.strictEqual(
            await LibECDSA.verifyStream(
                alg,
                pub,
                NodeFS.createReadStream(tmpPathData),
                sig2,
                { format: 'ieee-p1363' }
            ),
            true
        );

        NodeAssert.strictEqual(
            await signer.verifyStream(
                NodeFS.createReadStream(tmpPathData),
                sig1
            ),
            true
        );

        NodeAssert.strictEqual(
            await signer.verifyStream(
                NodeFS.createReadStream(tmpPathData),
                sig2
            ),
            true
        );
    });
}

function testFnVerifyP1363(alg: LibECDSA.IAlgorithms, keyLen: string) {

    return NodeTest.it(`ecdsa-${alg}-with-ec${keyLen}-ieee-p1363`, async () => {

        const d = NodeCrypto.randomBytes(256).toString('hex');
        const keyPath = `${TMP_DIR}/ec${keyLen}-priv.pem`;
        const pubPath = `${TMP_DIR}/ec${keyLen}-pub.pem`;
        const tmpPath = `${TMP_DIR}/ecdsa-verify-${alg}.tmp`;
        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });

        const osSig = LibECDSA.derToP1363(Buffer.from(await opensslSign(alg, keyPath, tmpPath, d), 'hex'));

        NodeAssert.strictEqual(
            LibECDSA.verify(alg, pub, d, osSig, { format: 'ieee-p1363' }),
            true
        );

        const signer = LibECDSA.createSigner(
            alg,
            pub,
            NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' }),
            { format: 'ieee-p1363' }
        );

        NodeAssert.strictEqual(
            signer.verify(d, osSig),
            true
        );
    });
}

function testFnVerifyDER(alg: LibECDSA.IAlgorithms, keyLen: string) {

    return NodeTest.it(`ecdsa-${alg}-with-ec${keyLen}-der`, async () => {

        const d = NodeCrypto.randomBytes(256).toString('hex');
        const keyPath = `${TMP_DIR}/ec${keyLen}-priv.pem`;
        const pubPath = `${TMP_DIR}/ec${keyLen}-pub.pem`;
        const tmpPath = `${TMP_DIR}/ecdsa-verify-${alg}.tmp`;
        const pub = NodeFS.readFileSync(pubPath, { 'encoding': 'utf-8' });

        const osSig = await opensslSign(alg, keyPath, tmpPath, d);

        NodeAssert.strictEqual(
            LibECDSA.verify(alg, pub, d, Buffer.from(osSig, 'hex'), { format: 'der' }),
            true
        );

        const signer = LibECDSA.createSigner(
            alg,
            pub,
            NodeFS.readFileSync(keyPath, { 'encoding': 'utf-8' }),
            { format: 'der' }
        );

        NodeAssert.strictEqual(
            signer.verify(d, Buffer.from(osSig, 'hex')),
            true
        );
    });
}

NodeTest.describe('ECDSA', async () => {

    await NodeTest.describe('function verify', async () => {

        for (const alg of LibECDSA.getSupportedAlgorithms()) {

            for (const keyLen of ['128', '256', '384', '512']) {

                await testFnVerifyDER(alg, keyLen);

                await testFnVerifyP1363(alg, keyLen);
            }
        }
    });

    await NodeTest.describe('function sign', async () => {

        for (const alg of LibECDSA.getSupportedAlgorithms()) {

            for (const keyLen of ['128', '256', '384', '512']) {

                await testFnSignDER(alg, keyLen);

                await testFnSignP1363(alg, keyLen);
            }
        }
    });

    await NodeTest.describe('function verifyStream', async () => {

        for (const alg of LibECDSA.getSupportedAlgorithms()) {

            for (const keyLen of ['128', '256', '384', '512']) {

                await testFnVerifyStreamDER(alg, keyLen);

                await testFnVerifyStreamP1363(alg, keyLen);
            }
        }
    });

    await NodeTest.describe('function signStream', async () => {

        for (const alg of LibECDSA.getSupportedAlgorithms()) {

            for (const keyLen of ['128', '256', '384', '512']) {

                await testFnSignStreamDER(alg, keyLen);

                await testFnSignStreamP1363(alg, keyLen);
            }
        }
    });

    await NodeTest.describe('error branches', async () => {

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

                    LibECDSA.sign('sha256', key, 'test', opts);
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

                    LibECDSA.verify('sha256', key, 'test', Buffer.from('test'), opts);
                    NodeAssert.fail(`Expected exception to be thrown for key: ${key}`);
                }
                catch (e) {

                    NodeAssert.strictEqual(e instanceof error, true);
                }
            }
        });
    });

    await NodeTest.describe('class EcdsaSigner', async () => {

        NodeTest.it('should throw exception if no keys provided', async () => {

            try {
                LibECDSA.createSigner(
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
                    EC128_PUB_KEY,
                    EC256_PRIV_KEY,
                    Errors.E_KEY_PAIR_MISMATCH,
                ],
                [ // invalid public key content
                    'shit',
                    EC128_PRIV_KEY,
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid public key type
                    EC128_PRIV_KEY,
                    'shit',
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid public key algorithm
                    ED25519_PUB_KEY,
                    EC128_PUB_KEY,
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid private key content
                    EC128_PUB_KEY,
                    'shit',
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
                [ // invalid private key type
                    EC128_PUB_KEY,
                    EC128_PUB_KEY,
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
                [ // invalid private key algorithm
                    EC128_PUB_KEY,
                    ED25519_PRIV_KEY,
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
                [ // invalid public key value type
                    123 as unknown as NodeCrypto.KeyObject,
                    EC128_PUB_KEY,
                    Errors.E_INVALID_PUBLIC_KEY,
                ],
                [ // invalid private key value type
                    EC128_PUB_KEY,
                    123 as unknown as NodeCrypto.KeyObject,
                    Errors.E_INVALID_PRIVATE_KEY,
                ],
            ] as const) {

                try {
                    LibECDSA.createSigner('sha256', pub, key);
                    NodeAssert.fail('Expected exception to be thrown');
                }
                catch (e) {

                    NodeAssert.strictEqual(e instanceof err, true);
                }
            }
        });

        NodeTest.it('should throw error when signing without private key', async () => {

            const pub = EC128_PUB_KEY_PEM;

            const signer = LibECDSA.createSigner('sha256', pub, null);

            NodeAssert.strictEqual(signer.hashAlgorithm, 'sha256');
            NodeAssert.strictEqual(signer.signAlgorithm, 'ecdsa');

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

            const key = EC256_PRIV_KEY_PEM;

            const signer = LibECDSA.createSigner('sha256', null, key);

            NodeAssert.strictEqual(signer.hashAlgorithm, 'sha256');
            NodeAssert.strictEqual(signer.signAlgorithm, 'ecdsa');

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
    });

});
