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

// tslint:disable:no-console
// tslint:disable:no-var-requires

/**
 * All test data from https://jwt.io.
 */

import * as Signs from "../lib";
import * as Enc from "@litert/encodings";

const RSASSA_KEY_PRIV = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw
33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW
+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS
3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp
uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE
2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0
GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K
Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY
6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5
fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523
Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP
FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----`;

const RSASSA_KEY_PUB = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----`;

const RSASSA_PSS_KEY_PRIV = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAnYvEIhEL/kFoSYjX2pVNLKb235RjZaZfrq08hLfhXor+Cu7Q
OtElkclahwvBJuE7/PlrgXhFO4rT+AnHXWAPADmlUmAf11HTmRMg1UVjpNLsZBCI
Rgma5W2lei0chEmsDHQsz/6C8m9I1gqBesQe8AeZ/HwxhTazY2erCSjrVvg7uV4X
Of/Y0d1qxhBMjqe+RxV/RyOXT8woqlOtjhMJ1+vretB2sE0GwSH7bfCsjWE3yqGp
8fZ+qYDHCT39VbcXwwrz32FZmZVZXPicC6InvRN7u7+cBnCYeS+bsuApAyat0Wk4
93pKHQ/5ruxI3oF+AGepc9B/o8kOzrYVqU/PUwIDAQABAoIBAQCCBWJmFxmFyedO
oOA8JnHdwyIFnUp3Dtryp0hF5BfcVeuZjERP9mICMmJDB+Ftu/8tJY+i92Zz4HxV
vYRKvMdEkU6ucGR26LIwKAg12yGEWwr6/mXpH241oMsrzOU3DDIwyQRe2BasDEnZ
VCxN7GP4Bt3/8WNRJLbh+CHA2oN3bvUhGFWj6Reoqk0XPXbM6Y/ThphzJ7lf/HjZ
880Gaf64kucdKCakKzt3N7tGdkjzkLx1+d2GcPLkNlNm7EyAmURZUzfwBGT3Ekjx
ltGeDsiQLJQXBVifsJY2TI0WKH3c7PmVJgVSpOEAp6tkxq09mPKZX1Z6Cr1LUh8s
Hcm/qkkZAoGBAMsmWEHGjZCFNy0F347s7qadL0KqedXnwheexE6ZC8qsbNtVWM2c
E4mOeJVYyXLX0y6pmY0fVwuQMOgR5+1cd7Ps9x6izkrDttaAumBKpjcyyp9AFGUX
zaEXf89jb2BH/z1J7yry4vW6vZOyeP0Vr69mOb0irc5ik5jK0uqvW4e/AoGBAMaI
O9vbwsQvY7MSmJXJXaoBpjnqTx0j6V3DIEezy+IltaMqhWk/J46YPi6RJ0j1wtG5
e9ldbId4LUJvpg4E8u+sXw4bzjZm7bMdcpcUc2Lkdsfbqe3JVETwX1B6rMHe7X6O
vT+hzPPoDYgFFU98BOZsKhIxuvNM4ipRPakzob1tAoGBAIwVvPZefHAT7KBXVHmy
WD78VQKbm7gtQGIZUTUBxGfVzprQl5Pw9Gf+npgdyYwv16htuzzdR6DppU/iSRQc
l06zMRUnHynfG81+pwaPc17M33xBK88qQtm64p+X6c1y2EbjHNF4+5iHVQLsJxIe
Si+hRl9t8nxG7ZCHDDpZAbzxAoGADu2vkpizzIzDsnNzhc/eeyoklbZIvKg2pBZI
Fxwt+JNdVSedYIyfLNnF0zqW+aWBQMPxzCZ6QrWGsbgzhFpa6irL+wOcPfr/ZLiS
JUokYwtK4zxhSsAY1hY9FJAk7W8V7K5PDLnd73lDizbWo2Nv+uOnRjb3F9RwLT5u
pIp9XwECgYEAre+anMp/k27tMH+/rIPEySzmcgL1tfhhsg+XiaO7fnSwH7VoBe1F
rvuvhNfk9LkfqNDP8/ByiiDwd2c3ECoNftFww2qYQfVginpkXS/P/OE1/3wZWhxO
AvZnYd7W4BdQOf/LzVeRRtGneoOK90KO9gewdtOAntEPL2kJXqNbxeE=
-----END RSA PRIVATE KEY-----`;

const RSASSA_PSS_KEY_PUB = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnYvEIhEL/kFoSYjX2pVN
LKb235RjZaZfrq08hLfhXor+Cu7QOtElkclahwvBJuE7/PlrgXhFO4rT+AnHXWAP
ADmlUmAf11HTmRMg1UVjpNLsZBCIRgma5W2lei0chEmsDHQsz/6C8m9I1gqBesQe
8AeZ/HwxhTazY2erCSjrVvg7uV4XOf/Y0d1qxhBMjqe+RxV/RyOXT8woqlOtjhMJ
1+vretB2sE0GwSH7bfCsjWE3yqGp8fZ+qYDHCT39VbcXwwrz32FZmZVZXPicC6In
vRN7u7+cBnCYeS+bsuApAyat0Wk493pKHQ/5ruxI3oF+AGepc9B/o8kOzrYVqU/P
UwIDAQAB
-----END PUBLIC KEY-----`;

interface ITestItem {

    "name": string;

    "key": string | Buffer | {
        "private": Signs.IAsymmetricKey | string | Buffer,
        "public": string | Buffer
    };

    "hashAlgo": string;

    "signAlgo": string;

    "header": any;

    "payload": any;

    "signature": string;
}

const TESTS: Record<string, ITestItem> = {
    HS256: {
        "name": "HS256",
        "key": "-fxppX-TAWx6ps4Mqbfz_VP7kPNyV8lXqh562onbFl0Rs6rj",
        "hashAlgo": "sha256",
        "signAlgo": "hmac",
        "header": {
            "alg": "HS256",
            "typ": "JWT"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022
        },
        "signature": "EpxeIXdFQyI8N1A0tpkVqYcKaaRH3A48a6TY3tZ8e4c"
    },
    HS384: {
        "name": "HS384",
        "key": "vhSFEzf3KaFHdKFGkiMfmR4W-YelUUXGNByJAMO6mp7_7SnC",
        "hashAlgo": "sha384",
        "signAlgo": "hmac",
        "header": {
            "alg": "HS384",
            "typ": "JWT"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022
        },
        "signature": "b0IaeQh45hspBIXRZ66o0nqpwodFzI_tVd_3MF0qOrZRzcYtMljo8-W7Mn-c_o7z"
    },
    HS512: {
        "name": "HS512",
        "key": "y3g7HQrv2Pc490iWpbbvhQF3kXY1UFCHHYH0t18yJmffV3Rh",
        "hashAlgo": "sha512",
        "signAlgo": "hmac",
        "header": {
            "alg": "HS512",
            "typ": "JWT"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022
        },
        "signature": "JqakV0mXUsC1NIDFh0qXkpVhJgmYa36LDkM3NuIdQE78XNvla99-c4E04amXuLVI" +
                     "7U2A0nbT8ZYlT3ZjAvrHIw"
    },
    RS256: {
        "name": "RS256",
        "key": {
            "private": RSASSA_KEY_PRIV,
            "public": RSASSA_KEY_PUB
        },
        "hashAlgo": "sha256",
        "signAlgo": "rsassa-pkcs1-v1_5",
        "header": {
            "alg": "RS256",
            "typ": "JWT"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        },
        "signature": "TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJ" +
                     "iN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kron" +
                     "Kb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
    },
    RS384: {
        "name": "RS384",
        "key": {
            "private": RSASSA_KEY_PRIV,
            "public": RSASSA_KEY_PUB
        },
        "hashAlgo": "sha384",
        "signAlgo": "rsassa-pkcs1-v1_5",
        "header": {
            "alg": "RS384",
            "typ": "JWT"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        },
        "signature": "CN9hqUMdVb5LGo06Geb8ap1qYfbJ4rEZIMqTE9gxA2m6GGmsXkznRxzoFpAzQUey" +
                     "9q5HehRTk_-TxYydN3QtFPfrTbAHep7PLhp3XhdvTJ1ok__UBjv4aP6UWTF-Rflr" +
                     "3qeC18LdlM4nyKL7ZwSGDzytWihGod5vn4GAXErUUE4"
    },
    RS512: {
        "name": "RS512",
        "key": {
            "private": RSASSA_KEY_PRIV,
            "public": RSASSA_KEY_PUB
        },
        "hashAlgo": "sha512",
        "signAlgo": "rsassa-pkcs1-v1_5",
        "header": {
            "alg": "RS512",
            "typ": "JWT"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        },
        "signature": "MejLezWY6hjGgbIXkq6Qbvx_-q5vWaTR6qPiNHphvla-XaZD3up1DN6Ib5AEOVtu" +
                     "B3fC9l-0L36noK4qQA79lhpSK3gozXO6XPIcCp4C8MU_ACzGtYe7IwGnnK3Emr6I" +
                     "HQE0bpGinHX1Ak1pAuwJNawaQ6Nvmz2ozZPsyxmiwoo"
    },
    ES256: {
        "name": "ES256",
        "key": {
            "private": `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----`,
            "public": `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`
        },
        "hashAlgo": "sha256",
        "signAlgo": "ecdsa",
        "header": {
            "alg": "ES256",
            "typ": "JWT"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        },
        "signature": "PyjqTCYOYBNM3W9MfxE5tFtdx_3NYxQiQveK78BcNgGntSE6hnWuBVMIG9Z_8vt8" +
                     "CpkG-S2K_lMkkgMFvwcqWw"
    },
    ES384: {
        "name": "ES384",
        "key": {
            "private": `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCAHpFQ62QnGCEvYh/pE9QmR1C9aLcDItRbslbmhen/h1tt8AyMhske
enT+rAyyPhGgBwYFK4EEACKhZANiAAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+
T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLU
PeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
-----END EC PRIVATE KEY-----`,
            "public": `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----`
        },
        "hashAlgo": "sha384",
        "signAlgo": "ecdsa",
        "header": {
            "alg": "ES384",
            "typ": "JWT",
            "kid": "iTqXXI0zbAnJCKDaobfhkM1f-6rMSpTfyZMRp_2tKI8"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        },
        "signature": "wq0FZi5RWjZenUMoRfb9idTLcs0UlAotStTQhzojohujybyw097qYxaokhEnwda9" +
                     "s6wolHToEwupvdzTt8-_YpFGW-AIDwFoN4pzVnEgkgkteTUm3GoVndGOIrXOKu2b"
    },
    ES512: {
        "name": "ES512",
        "key": {
            "private": `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBiyAa7aRHFDCh2qga9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx
0pDrmCV9mbroFtfEa0XVfKuMAxxfZ6LM/yKgBwYFK4EEACOhgYkDgYYABAGBzgdn
P798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+
duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcv
VtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12ew==
-----END EC PRIVATE KEY-----`,
            "public": `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----`
        },
        "hashAlgo": "sha512",
        "signAlgo": "ecdsa",
        "header": {
            "alg": "ES512",
            "typ": "JWT",
            "kid": "xZDfZpry4P9vZPZyG2fNBRj-7Lz5omVdm7tHoCgSNfY"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        },
        "signature": "ACGg1D8j360_s4jGni4796gIaNnucqKn3DY98PO1nGe4hG8e64WaJBgUUMU3zXZ4" +
                     "ThNTFS51r_JODbvphLBZ4lzXAYaQd2BqyLiVVbnpKdo3-2ih9Yf8bTugkekCfHvA" +
                     "DWvH95VVSr4YVba5JkN6VAuFu31in3WujC_qXFy5EidVL78P"
    },
    PS256: {
        "name": "PS256",
        "key": {
            "private": RSASSA_PSS_KEY_PRIV,
            "public": RSASSA_PSS_KEY_PUB
        },
        "hashAlgo": "sha256",
        "signAlgo": "rsassa-pss",
        "header": {
            "alg": "PS256",
            "typ": "JWT"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        },
        "signature": "eQmQFUXHY8wBVCikuEIFAp2STVBXIP63QxBKj4UMHD2cVdjGcZYd2U5xQSkxju20" +
                     "EOpn6CFONNDFIRozqtidGf2RP5mtAtf8Y-r3ClSPfMhdOgdZCAso4qk8CKScD74z" +
                     "DsRXyBZsOvI4Pu4ne8JwmIZubjqBanXsH3SyrL3SBnu0Rb1jLDhFej8sm-20dpnm" +
                     "nXlVR4nbrsEv_0UaT7bX7T7A0fOZIZBrQcfrIGOSMenNGAOSqYmmAksIjAjNoAms" +
                     "4EGQFQZNnCgrWhjlA9xgzBxXJA9txDivsqTjnMpyAz8Zgv9E8LK5x4p6H3jKjhu2" +
                     "WTLL4bQlG2vAG61-BIzI2w"
    },
    PS384: {
        "name": "PS384",
        "key": {
            "private": RSASSA_PSS_KEY_PRIV,
            "public": RSASSA_PSS_KEY_PUB
        },
        "hashAlgo": "sha384",
        "signAlgo": "rsassa-pss",
        "header": {
            "alg": "PS384",
            "typ": "JWT"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        },
        "signature": "GPLrM8J8rFeDgzEuxYlYbHchFugaxzr2O9kVmEkjonXA_DxrbTkIWosLymokgxhe" +
                     "bF3_ViKq2DE1gkQ5jdvBD4AHEdfa8lf9uuj4vDsQwdIpA_LRRCP5B6aA0ck1_pAA" +
                     "ERJQrSGlK6SDzWc0rtzjdsC8QtMmOEYrrT0CN7zEW1QXLQjyjDsX2HFKKZZXlCnh" +
                     "fLxpY18lNjFvLbdYuz-qNCTCTBKBuivbpBOqireQNWJlQb56VLT8iMkuNqCmGAKd" +
                     "XydSNyWK1LJkmpKqJ_B3z_303yTrJkKX061AqnrX_qwPxA6PAOg02PdZbqcSeGZR" +
                     "LbZDY5LsGcbCTdnoY4VD2g"
    }
};

for (let i in TESTS) {

    const item = TESTS[i];

    let signer: Signs.ISigner<"base64url">;

    switch (item.signAlgo) {
    case "ecdsa":

        signer = Signs.ECDSA.createSigner(
            item.hashAlgo as any,
            (item.key as any).public,
            (item.key as any).private,
            Signs.EECDSAFormat.IEEE_P1363,
            "base64url"
        );

        break;

    default:
    case "hmac":

        signer = Signs.HMAC.createSigner(
            item.hashAlgo as any,
            item.key as any,
            "base64url"
        );

        break;

    case "rsassa-pkcs1-v1_5":

        signer = Signs.RSA.createSigner(
            item.hashAlgo as any,
            (item.key as any).public,
            (item.key as any).private,
            Signs.ERSAPadding.PKCS1_V1_5,
            "base64url"
        );

        break;

    case "rsassa-pss":

        signer = Signs.RSA.createSigner(
            item.hashAlgo as any,
            (item.key as any).public,
            (item.key as any).private,
            Signs.ERSAPadding.PSS_MGF1,
            "base64url"
        );

        break;
    }

    const CONTENT = [
        item.header,
        item.payload
    ].map(
        (x) => Enc.base64UrlEncode(Buffer.from(JSON.stringify(x)).toString("base64"))
    ).join(".");

    const signResult = Enc.base64UrlEncode(signer.sign(CONTENT));

    const verifyResult = signer.verify(
        CONTENT,
        item.signature
    );

    if (verifyResult) {

        console.info(`[${item.name}] Verification matched.`);
    }
    else {

        console.error(`[${item.name}] Verification failed.`);

        console.error(`[${item.name}]: Result       ${signResult}`);

        console.error(Enc.bufferFromBase64Url(item.signature).toJSON().data.length);

        console.error(`[${item.name}]: Expectation  ${item.signature}`);
    }
}
