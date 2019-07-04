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

/**
 * This method helps recover R/S to the DER form, with padding if necessary.
 *
 * @param {Buffer} input The R/S to be recovered.
 */
function _ecdsaRecoverRS(input: Buffer): Buffer {

    let start: number = 0;

    while (input[start] === 0) {
        start++;
    }

    if (input[start] <= 0x7F) {

        return input.slice(start);
    }

    if (start > 0) {

        return input.slice(start - 1);
    }

    let output = Buffer.alloc(input.length + 1);

    input.copy(output, 1);
    output[0] = 0;

    return output;
}

/**
 * This method helps transform signature from DER format to P1363 format.
 *
 * @param {Buffer} der  The signature in DER format.
 *
 * @returns {Buffer}  Return the signature in P1363 format.
 */
export function ecdsaDERToP1363(der: Buffer): Buffer {

    let base = 0;

    /**
     * Using long form length if it's larger than 0x7F.
     *
     * @see https://stackoverflow.com/a/47099047
     */
    if (der[1] === 0x81) {

        base++;
    }

    let rL = der[base + 3];
    let sL = der[base + 5 + rL];

    let r = der.slice(base + 4, base + 4 + rL);
    let s = der.slice(base + 6 + rL, base + 6 + rL + sL);

    /**
     * Remove the prepended 0x00 byte of R/S.
     */
    switch (rL) {
    case 21:
    case 29:
    case 33:
    case 49:
    case 67:
        r = r.slice(1);
    }

    switch (sL) {
    case 21:
    case 29:
    case 33:
    case 49:
    case 67:
        s = s.slice(1);
    }

    return Buffer.concat([r, s]);
}

/**
 * This method helps transform signature from DER format to P1363 format.
 *
 * @param {Buffer} rs   The signature in P1363 format.
 *
 * @returns {Buffer}  Return the signature in DER format.
 */
export function ecdsaP1363ToDER(rs: Buffer): Buffer {

    let base = 0;

    let r: Buffer;
    let s: Buffer;

    const hL = rs.length / 2;

    /**
     * Prepend a 0x00 byte to R or S if it starts with a byte larger than 0x79.
     *
     * Because a integer starts with a byte larger than 0x79 means negative.
     *
     * @see https://bitcointalk.org/index.php?topic=215205.msg2258789#msg2258789
     */
    r = _ecdsaRecoverRS(rs.slice(0, hL));
    s = _ecdsaRecoverRS(rs.slice(hL));

    /**
     * Using long form length if it's larger than 0x7F.
     *
     * @see https://stackoverflow.com/a/47099047
     */
    if (4 + s.length + r.length > 0x7f) {

        base++;
    }

    const der = Buffer.alloc(base + 6 + s.length + r.length);

    if (base) {

        der[1] = 0x81;
    }

    der[0] = 0x30;
    der[base + 1] = 4 + s.length + r.length;
    der[base + r.length + 4] = der[base + 2] = 0x02;
    der[base + r.length + 5] = s.length;
    der[base + 3] = r.length;
    r.copy(der, base + 4);
    s.copy(der, base + 6 + r.length);

    return der;
}
