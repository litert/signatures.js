/**
 *  Copyright 2020 Angus.Fenying <fenying@litert.org>
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

export function _getEncoderName(output: string, encLib: string, vn: string): string {

    switch (output) {
        case `base64`: return `${encLib}.bufferToBase64(${vn})`;
        case `base64url`: return `${encLib}.bufferToBase64Url(${vn})`;
        case `hex`: return `${encLib}.bufferToHex(${vn})`;
        default: return vn;
    }
}

export function _getDecoderName(input: string, encLib: string, vn: string): string {

    switch (input) {
        case `base64`: return `${vn} = ${encLib}.bufferFromBase64(${vn});`;
        case `base64url`: return `${vn} = ${encLib}.bufferFromBase64Url(${vn});`;
        case `hex`: return `${vn} = ${encLib}.bufferFromHex(${vn});`;
        default: return vn;
    }
}
