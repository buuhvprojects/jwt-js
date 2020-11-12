import * as CryptoJS from 'crypto-js';

type WordArray = CryptoJS.lib.WordArray;
type CipherParams = CryptoJS.lib.CipherParams;
type X64Word = CryptoJS.x64.Word;

interface jwtProps {
    enc: {
        Utf8: {
            stringify(wordArray: WordArray): string;
            parse(str: string): WordArray;
        },
        Base64: {
            stringify(wordArray: WordArray): string;
            parse(str: string): WordArray;
        }
    }
}
interface req {
    headers: {
        Authorization?: string,
        authorization?: string
    }
}
interface checkJWT {
    status: boolean,
    message?: string
}
interface dataJWT {
    status: boolean,
    data?: any,
    message?: string
}

export default interface JWT {
    buildHeader: () => string;
    props: jwtProps;
    buildPayload: (params: object) => string;
    buildSignature: (prev_token: string) => string;
    checkJWT: (req: req) => checkJWT;
    data: (req: req) => dataJWT;
    ISS: string;
    SECRET_KEY: string;
}