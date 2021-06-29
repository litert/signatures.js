import * as $Assert from 'assert';
import * as $CP from 'child_process';
import * as $Crypto from 'crypto';
import * as $Sign from '../lib';
import * as $FS from 'fs';

const TMP_DIR = `${__dirname}/../data`;
const TMP_FILE = `${TMP_DIR}/hmac.tmp`;

$FS.mkdirSync(TMP_DIR, { recursive: true });

function hmacSignWithOpenSSLAsHex(
    algo: string,
    key: string,
    message: string,
    callback: (err: any, signature: string) => void
): void {

    $FS.writeFileSync(TMP_FILE, message);

    $CP.exec(
        `openssl dgst -${algo} -hex -hmac "${key}" ${TMP_FILE}`,
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

describe('HMAC', function() {

    describe('api.verify(openssl.sign(data))', function() {

        for (const ALGO of $Sign.HMAC.getSupportedAlgorithms()) {

            it(`hmac-${ALGO}`, function(callback) {

                const CONTENT = $Crypto.randomBytes(256).toString('hex');
                const KEY = $Crypto.randomBytes(32).toString('hex');

                hmacSignWithOpenSSLAsHex(ALGO, KEY, CONTENT, (e, s) => {

                    if (e) {
                        $Assert.fail(e);
                    }
                    else {

                        $Assert.strictEqual(
                            $Sign.HMAC.verify(ALGO, KEY, CONTENT, Buffer.from(s, 'hex')),
                            true
                        );
                    }

                    callback();
                });
            });
        }
    });

    describe('api.verifyStream(openssl.sign(data))', function() {

        for (const ALGO of $Sign.HMAC.getSupportedAlgorithms()) {

            it(`hmac-${ALGO}`, function(callback) {

                const CONTENT = $Crypto.randomBytes(256).toString('hex');
                const KEY = $Crypto.randomBytes(32).toString('hex');

                hmacSignWithOpenSSLAsHex(ALGO, KEY, CONTENT, (e, s) => {

                    if (e) {
                        callback(e);
                    }
                    else {

                        $Sign.HMAC.verifyStream(ALGO, KEY, $FS.createReadStream(TMP_FILE), Buffer.from(s, 'hex'))
                        .then((v) => {

                            $Assert.strictEqual(v, true);
                            callback();
                        })
                        .catch((e) => callback(e))
                    }
                });
            });
        }
    });

    describe('signer.verify(openssl.sign(data))', function() {

        for (const ALGO of $Sign.HMAC.getSupportedAlgorithms()) {

            it(`hmac-${ALGO}`, function(callback) {

                const CONTENT = $Crypto.randomBytes(256).toString('hex');
                const KEY = $Crypto.randomBytes(32).toString('hex');

                hmacSignWithOpenSSLAsHex(ALGO, KEY, CONTENT, (e, s) => {

                    if (e) {
                        $Assert.fail(e);
                    }
                    else {

                        const signer = $Sign.HMAC.createSigner(ALGO, KEY);

                        $Assert.strictEqual(
                            signer.verify(CONTENT, Buffer.from(s, 'hex')),
                            true
                        );
                    }

                    callback();
                });
            });
        }
    });

    describe('signer.verifyStream(openssl.sign(data))', function() {

        for (const ALGO of $Sign.HMAC.getSupportedAlgorithms()) {

            it(`hmac-${ALGO}`, function(callback) {

                const CONTENT = $Crypto.randomBytes(256).toString('hex');
                const KEY = $Crypto.randomBytes(32).toString('hex');

                hmacSignWithOpenSSLAsHex(ALGO, KEY, CONTENT, (e, s) => {

                    if (e) {
                        callback(e);
                    }
                    else {

                        const signer = $Sign.HMAC.createSigner(ALGO, KEY);

                        signer.verifyStream($FS.createReadStream(TMP_FILE), Buffer.from(s, 'hex'))
                        .then((v) => {

                            $Assert.strictEqual(v, true);
                            callback();
                        })
                        .catch((e) => callback(e))
                    }
                });
            });
        }
    });
});
