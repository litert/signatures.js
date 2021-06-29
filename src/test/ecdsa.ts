import * as $Assert from 'assert';
import * as $CP from 'child_process';
import * as $Crypto from 'crypto';
import * as $Sign from '../lib';
import * as $FS from 'fs';

const TMP_DIR = `${__dirname}/../data`;
const TMP_FILE = `${TMP_DIR}/ecdsa.tmp`;
const TMP_SIG = `${TMP_DIR}/ecdsa.sig`;

$FS.mkdirSync(TMP_DIR, { recursive: true });

function ecdsaSignWithOpenSSLCommand(
    algo: string,
    keyPath: string,
    message: string,
    callback: (err: any, signature: string) => void
): void {

    $FS.writeFileSync(TMP_FILE, message);

    $CP.exec(
        `openssl dgst -${algo} -hex -sign ${keyPath} ${TMP_FILE}`,
        function(err, stdout, stderr): void {
            if (err || stderr) {

                callback(err ?? stderr, '');
            }
            else {

                callback(null, stdout.trim().toLowerCase().match(/\w+$/)![0]);
            }
        }
    );
}

function ecdsaVerifyWithOpenSSLCommand(
    algo: string,
    keyPath: string,
    message: string,
    signature: Buffer,
    callback: (result: boolean) => void
): void {

    $FS.writeFileSync(TMP_FILE, message);
    $FS.writeFileSync(TMP_SIG, signature);

    $CP.exec(
        `openssl dgst -${algo} -hex -signature ${TMP_SIG} -verify ${keyPath} ${TMP_FILE}`,
        function(err, stdout, stderr): void {
            if (err || stderr) {

                callback(false);
            }
            else {

                callback(stdout.trim() === 'Verified OK');
            }
        }
    );
}

describe('ECDSA', function() {

    describe('api.verify(openssl.sign(data))', function() {

        for (const ALGO of $Sign.ECDSA.getSupportedAlgorithms()) {

            it(`ecdsa-${ALGO}`, function(callback) {

                const CONTENT = $Crypto.randomBytes(256).toString('hex');
                const PRIV_KEY_PATH = `${TMP_DIR}/ec512-priv.pem`;
                const PUB_KEY_PATH = `${TMP_DIR}/ec512-pub.pem`;
                // const PRIV_KEY = $FS.readFileSync(PRIV_KEY_PATH, {'encoding': 'utf-8'});
                const PUB_KEY = $FS.readFileSync(PUB_KEY_PATH, {'encoding': 'utf-8'});

                ecdsaSignWithOpenSSLCommand(ALGO, PRIV_KEY_PATH, CONTENT, (e, s) => {

                    if (e) {
                        $Assert.fail(e);
                    }
                    else {

                        $Assert.strictEqual(
                            $Sign.ECDSA.verify(ALGO, PUB_KEY, CONTENT, Buffer.from(s, 'hex'), { format: 'der' }),
                            true
                        );
                    }

                    callback();
                });
            });
        }
    });

    describe('openssl.verify(api.sign(data))', function() {

        for (const ALGO of $Sign.ECDSA.getSupportedAlgorithms()) {

            it(`ecdsa-${ALGO}`, function(callback) {

                const CONTENT = $Crypto.randomBytes(256).toString('hex');
                const PRIV_KEY_PATH = `${TMP_DIR}/ec512-priv.pem`;
                const PUB_KEY_PATH = `${TMP_DIR}/ec512-pub.pem`;
                const PRIV_KEY = $FS.readFileSync(PRIV_KEY_PATH, {'encoding': 'utf-8'});
                // const PUB_KEY = $FS.readFileSync(PUB_KEY_PATH, {'encoding': 'utf-8'});

                const sig = $Sign.ECDSA.sign(ALGO, PRIV_KEY, CONTENT, { format: 'der' });

                ecdsaVerifyWithOpenSSLCommand(ALGO, PUB_KEY_PATH, CONTENT, sig, (s) => {

                    if (s) {
                        $Assert.ok(true);
                    }
                    else {
                        $Assert.fail();
                    }

                    callback();
                });
            });
        }
    });
});
