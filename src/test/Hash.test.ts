import * as NodeTest from 'node:test';
import * as NodeAssert from 'node:assert';
import * as NodeCrypto from 'node:crypto';
import * as NodeFS from 'node:fs';
import * as LibHash from '../lib/Hash';
import { opensslHash } from './utils-openssl-cli';

const TMP_DIR = `${__dirname}/../data`;

NodeTest.describe('Hash/Digest', async () => {

    await NodeTest.describe('function hash()', async () => {

        for (const alg of LibHash.getSupportedAlgorithms()) {

            await NodeTest.it(`hash-${alg}`, async () => {

                const tmpFile = `${TMP_DIR}/hash-hash-${alg}.tmp`;

                const data = NodeCrypto.randomBytes(256).toString('hex');

                NodeAssert.strictEqual(
                    LibHash.hash(alg, data).toString('hex'),
                    await opensslHash(alg, tmpFile, data)
                );
            });
        }
    });

    await NodeTest.describe('function hashStream()', async () => {

        for (const alg of LibHash.getSupportedAlgorithms()) {

            await NodeTest.it(`hash-${alg}`, async () => {

                const data = NodeCrypto.randomBytes(256).toString('hex');

                const tmpFileIn = `${TMP_DIR}/hash-hash-${alg}-in.tmp`;
                const tmpFileOut = `${TMP_DIR}/hash-hash-${alg}-out.tmp`;

                NodeFS.writeFileSync(tmpFileIn, data);

                NodeAssert.strictEqual(
                    (await LibHash.hashStream(
                        alg,
                        NodeFS.createReadStream(tmpFileIn),
                    )).toString('hex'),
                    await opensslHash(alg, tmpFileOut, data),
                );
            });
        }
    });

    await NodeTest.describe('function createHasher()', async () => {

        for (const alg of LibHash.getSupportedAlgorithms()) {

            await NodeTest.it(`hash-${alg}`, async () => {

                const data = NodeCrypto.randomBytes(256).toString('hex');

                const tmpFileIn = `${TMP_DIR}/hash-hash-${alg}-in.tmp`;
                const tmpFileOut = `${TMP_DIR}/hash-hash-${alg}-out.tmp`;

                NodeFS.writeFileSync(tmpFileIn, data);

                const hasher = LibHash.createHasher(alg);

                NodeAssert.strictEqual(hasher.algorithm, alg);

                NodeAssert.strictEqual(
                    hasher.hash(data).toString('hex'),
                    await opensslHash(alg, tmpFileOut, data),
                );

                NodeAssert.strictEqual(
                    (await hasher.hashStream(NodeFS.createReadStream(tmpFileIn))).toString('hex'),
                    await opensslHash(alg, tmpFileOut, data),
                );
            });
        }
    });
});
