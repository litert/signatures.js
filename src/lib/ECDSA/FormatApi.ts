/**
 * Copyright 2025 Angus.Fenying <fenying@litert.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * This method helps recover R/S to the DER form, with padding if necessary.
 *
 * @param {Buffer} input The R/S to be recovered.
 */
function ecdsaRecoverRS(input: Buffer): Buffer {

    let start: number = 0;

    while (input[start] === 0) {
        start++;
    }

    if (input[start] <= 0x7F) {

        return input.subarray(start);
    }

    if (start > 0) {

        return input.subarray(start - 1);
    }

    const output = Buffer.alloc(input.length + 1);

    input.copy(output, 1);
    output[0] = 0;

    return output;
}

const UINT32_READ_BUFFER = Buffer.alloc(4);

function derReadLength(bf: Buffer, offset: number): [number, number] {

    let length = bf[offset++];

    /**
     * Using long form length if it's larger than 0x7F.
     *
     * @see https://stackoverflow.com/a/47099047
     */
    if (length > 0x7F) {

        const lLen = length & 0x7F;
        UINT32_READ_BUFFER.fill(0);
        bf.copy(UINT32_READ_BUFFER, 4 - lLen, offset, offset + lLen);
        length = UINT32_READ_BUFFER.readUInt32BE(0);
        offset += lLen;
    }

    return [length, offset];
}

function removePrependZero(bf: Buffer): Buffer {

    let i = 0;

    for (; i < bf.length && !bf[i]; i++);

    if (i === bf.length) {

        return bf.subarray(0, 1);
    }

    return bf.subarray(i);
}

/**
 * This method helps transform signature from DER format to IEEE-P1363 format.
 *
 * @param {Buffer} der  The signature in DER format.
 *
 * @returns {Buffer}  Return the signature in IEEE-P1363 format.
 */
export function derToP1363(der: Buffer): Buffer {

    let ctx: [number, number] = [0, 0];

    let [, offset] = derReadLength(der, 1);

    ctx = derReadLength(der, ++offset);
    offset = ctx[1];

    const r = removePrependZero(der.subarray(offset, offset + ctx[0]));

    offset += ctx[0];

    ctx = derReadLength(der, ++offset);

    offset = ctx[1];

    const s = removePrependZero(der.subarray(offset, offset + ctx[0]));

    if (s.length > r.length) {

        return Buffer.concat([Buffer.alloc(s.length - r.length), r, s]);
    }
    else if (r.length > s.length) {

        return Buffer.concat([r, Buffer.alloc(r.length - s.length), s]);
    }

    return Buffer.concat([r, s]);
}

/**
 * This method helps transform signature from DER format to IEEE-P1363 format.
 *
 * @param {Buffer} p1363   The signature in IEEE-P1363 format.
 *
 * @returns {Buffer}  Return the signature in DER format.
 */
export function p1363ToDER(p1363: Buffer): Buffer {

    let base = 0;

    const hL = p1363.length / 2;

    /**
     * Prepend a 0x00 byte to R or S if it starts with a byte larger than 0x79.
     *
     * Because a integer starts with a byte larger than 0x79 means negative.
     *
     * @see https://bitcointalk.org/index.php?topic=215205.msg2258789#msg2258789
     */
    const r = ecdsaRecoverRS(p1363.subarray(0, hL));
    const s = ecdsaRecoverRS(p1363.subarray(hL));

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
