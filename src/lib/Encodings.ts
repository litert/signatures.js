import * as Enc from "@litert/encodings";

export function convert(input: any, to: string, from: string): any {

    if (from === to) {

        return input;
    }

    switch (from) {
    case "base64":
        input = Enc.bufferFromBase64(input);
        break;
    case "base64url":
        input = Enc.bufferFromBase64Url(input);
        break;
    case "hex":
        input = Enc.bufferFromHex(input);
        break;
    default:
        input = Buffer.from(input);
        break;
    }

    switch (to) {
    case "base64":
        input = Enc.bufferToBase64(input);
        break;
    case "base64url":
        input = Enc.bufferToBase64Url(input);
        break;
    case "hex":
        input = Enc.bufferToHex(input);
        break;
    default:
        break;
    }

    return input;
}

export function compare(a: any, b: any, aEncoding: string, bEncoding: string): boolean {

    return !!convert(a, "buffer", aEncoding).compare(convert(b, "buffer", bEncoding));
}
