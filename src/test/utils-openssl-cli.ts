import * as NodeFS from 'node:fs';
import * as NodeCP from 'node:child_process';

export function opensslHmac(
    algo: string,
    key: string,
    tmpPath: string,
    message: string,
): Promise<string> {

    NodeFS.writeFileSync(tmpPath, message);

    return new Promise((resolve, reject) => {
        NodeCP.exec(
            `openssl dgst -${algo} -hex -hmac "${key}" ${tmpPath}`,
            function(err, stdout, stderr): void {
                if (err || stderr) {

                    reject(err ?? stderr);
                }
                else {

                    resolve(stdout.trim().toLowerCase().match(/\w+$/)![0]);
                }
            }
        );
    });
}

export function opensslHash(
    algo: string,
    tmpFile: string,
    message: string,
): Promise<string> {
    
    NodeFS.writeFileSync(tmpFile, message);

    return new Promise((resolve, reject) => {
        NodeCP.exec(
            `openssl dgst -${algo} -hex ${tmpFile}`,
            function(err, stdout, stderr): void {
                if (err || stderr) {

                    reject(err ?? stderr);
                }
                else {

                    resolve(stdout.trim().toLowerCase().match(/\w+$/)![0]);
                }
            }
        );
    });
}

export function opensslSign(
    algo: string,
    keyPath: string,
    tmpPath: string,
    message: string,
): Promise<string> {

    NodeFS.writeFileSync(tmpPath, message);

    return new Promise((resolve, reject) => {
        NodeCP.exec(
            `openssl dgst ${algo ? `-${algo}` : ''} -hex -sign ${keyPath} ${tmpPath}`,
            function(err, stdout, stderr): void {
                if (err || stderr) {

                    reject(err ?? stderr);
                }
                else {

                    resolve(stdout.trim().toLowerCase().match(/\w+$/)![0]);
                }
            }
        );
    });
}

export function opensslVerify(
    algo: string,
    keyPath: string,
    tmpPathData: string,
    tmpPathSig: string,
    message: string,
    signature: Buffer,
): Promise<boolean> {

    NodeFS.writeFileSync(tmpPathData, message);
    NodeFS.writeFileSync(tmpPathSig, signature);

    return new Promise((resolve) => {
        NodeCP.exec(
            `openssl dgst ${algo ? `-${algo}` : ''} -hex -signature ${tmpPathSig} -verify ${keyPath} ${tmpPathData}`,
            function(err, stdout, stderr): void {
                if (err || stderr) {

                    resolve(false);
                }
                else {

                    resolve(stdout.trim() === 'Verified OK');
                }
            }
        );
    });
}
