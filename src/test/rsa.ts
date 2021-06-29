import * as $Assert from 'assert';
import * as $CP from 'child_process';
import * as $Crypto from 'crypto';
import * as $Sign from '../lib';
import * as $FS from 'fs';

const TMP_DIR = `${__dirname}/../data`;
const TMP_FILE = `${TMP_DIR}/rsa.tmp`;
const TMP_SIG = `${TMP_DIR}/rsa.sig`;

$FS.mkdirSync(TMP_DIR, { recursive: true });

function rsaSignWithOpenSSLCommand(
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

function rsaVerifyWithOpenSSLCommand(
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

describe('RSA', function() {

    describe('api.verify(openssl.sign(data))', function() {

        for (const ALGO of $Sign.RSA.getSupportedAlgorithms()) {

            it(`rsa-${ALGO}`, function(callback) {

                const CONTENT = $Crypto.randomBytes(256).toString('hex');
                const PRIV_KEY_PATH = `${TMP_DIR}/rsa-priv.pem`;
                const PUB_KEY_PATH = `${TMP_DIR}/rsa-pub.pem`;
                // const PRIV_KEY = $FS.readFileSync(PRIV_KEY_PATH, {'encoding': 'utf-8'});
                const PUB_KEY = $FS.readFileSync(PUB_KEY_PATH, {'encoding': 'utf-8'});

                rsaSignWithOpenSSLCommand(ALGO, PRIV_KEY_PATH, CONTENT, (e, s) => {

                    if (e) {
                        $Assert.fail(e);
                    }
                    else {

                        $Assert.strictEqual(
                            $Sign.RSA.verify(ALGO, PUB_KEY, CONTENT, Buffer.from(s, 'hex')),
                            true
                        );
                    }

                    callback();
                });
            });
        }
    });

    describe('openssl.verify(api.sign(data))', function() {

        for (const ALGO of $Sign.RSA.getSupportedAlgorithms()) {

            it(`rsa-${ALGO}`, function(callback) {

                const CONTENT = $Crypto.randomBytes(256).toString('hex');
                const PRIV_KEY_PATH = `${TMP_DIR}/rsa-priv.pem`;
                const PUB_KEY_PATH = `${TMP_DIR}/rsa-pub.pem`;
                const PRIV_KEY = $FS.readFileSync(PRIV_KEY_PATH, {'encoding': 'utf-8'});
                // const PUB_KEY = $FS.readFileSync(PUB_KEY_PATH, {'encoding': 'utf-8'});

                const sig = $Sign.RSA.sign(ALGO, PRIV_KEY, CONTENT);

                rsaVerifyWithOpenSSLCommand(ALGO, PUB_KEY_PATH, CONTENT, sig, (s) => {

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
