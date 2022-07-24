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
/**
 * @todo Classe de controle de sessão onde pode ser gerado um JWT e validar o mesmo
 * @todo Depende do módulo CryptoJS - [npm i --save crypto-js]
 * @author Bruno Nascimento <br.dev.jobs@gmail.com>
 */
class JWT {
    props: jwtProps;
    ISS: string;
    SECRET_KEY: string;
    constructor(SECRET_KEY: string, ISS: string) {
        this.props = CryptoJS;
        this.buildHeader = this.buildHeader.bind(this);
        this.buildPayload = this.buildPayload.bind(this);
        this.buildSignature = this.buildSignature.bind(this);
        this.register = this.register.bind(this);
        this.checkJWT = this.checkJWT.bind(this);
        this.data = this.data.bind(this);
        this.ISS = ISS;
        this.SECRET_KEY = SECRET_KEY;
    }
    removeSpecials = (value: string) => {
        value = value.replace(/=+$/, '');
        value = value.replace(/\+/g, '-');
        value = value.replace(/\//g, '_');
        return value;
    }
    addSpecials = (value: string) => {
        value = value.replace(/=+$/, '');
        value = value.replace(/\-/g, '+');
        value = value.replace(/\_/g, '/');
        return value;
    }
    /**
     * @todo Constroi o cabeçalho do JWT
     * @returns {String} - base64
     */
    buildHeader = (): string => {
        try {
            const { enc } = this.props;
            const headerObject = {
                type: 'JWT',
                alg: 'HS256'
            };
            const headerParse = enc.Utf8.parse(JSON.stringify(headerObject));
            const headerStringify = enc.Base64.stringify(headerParse);
            return this.removeSpecials(headerStringify);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * @todo Constroi o payload/corpo(onde ficam os dados utilizados do jwt como user_id, tempo de expiração)
     * @returns {String} - base64
     */
    buildPayload = (params: object): string => {
        try {
            const { enc } = this.props;

            const toParse: string = JSON.stringify(params);
            const payloadParse = enc.Utf8.parse(toParse);
            const payloadStringify = enc.Base64.stringify(payloadParse);

            const payloadParse2 = enc.Utf8.parse(JSON.stringify(payloadStringify));
            const payloadStringify2 = enc.Base64.stringify(payloadParse2);

            const payload = this.removeSpecials(payloadStringify2);
            const encripted = CryptoJS.AES.encrypt(payload, this.SECRET_KEY)
            .toString();

            return this.removeSpecials(encripted);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * @todo Constroi a assinatura do JWT
     * @returns {String} - base64
     */
    buildSignature = (prev_token: string): string => {
        try {
            const { enc } = this.props;
            const hash = CryptoJS.HmacSHA256(prev_token, this.SECRET_KEY);
            const prev_signature = enc.Base64.stringify(hash);
            return this.removeSpecials(prev_signature);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * @todo Verifica se o token é valido
     * @param {req} - dados da requisição
     * @returns {Object} - status e o conteúdo
     */
    checkJWT = (req: req): checkJWT => {
        try {
            const { enc } = this.props;

            const token = req.headers['Authorization'] || req.headers['authorization'];
            if (/Bearer( )(.+){1}/g.test(token) === false) {
                return {
                    status: false,
                    message: 'Invalid access token'
                };
            }
            const access_token = token.replace(/Bearer /g, '');
            let split = access_token.split('.');
            if (split.length < 3) {
                return {
                    status: false,
                    message: 'Invalid access token'
                };
            }
            const headerJWT = split[0];
            if (headerJWT !== this.buildHeader()) {
                return {
                    status: false,
                    message: 'Invalid access token header'
                };
            }
            const payloadJWT = split[1];
            const signature = split[2];
            const prev_token = headerJWT + '.' + payloadJWT;
            const prev_signature = this.buildSignature(prev_token);
            if (signature === prev_signature) {

                const payload = CryptoJS.AES.decrypt(this.addSpecials(split[1]), this.SECRET_KEY).toString(CryptoJS.enc.Utf8);
                let words = enc.Base64.parse(payload);

                const textString = JSON.parse(Buffer.from(JSON.parse(enc.Utf8.stringify(words)), 'base64').toString('binary'));
                if (textString.expires) {
                    if (textString.expires <= new Date().getTime()) {
                        return {
                            status: false
                        }
                    }
                    else {
                        return {
                            status: true
                        };
                    }
                }
                else {
                    return {
                        status: true
                    };
                }
            }
            else {
                return {
                    status: false,
                    message: 'Invalid access token'
                };
            }
        }
        catch (error) {
            return {
                status: false,
                message: error.message
            };
        }
    };
    /**
     * @todo Retorna os dados contidos no JWT
     * @param {req} - dados da requisição
     * @returns {Object} - status e conteúdo
     */
    data = (req: req): dataJWT => {
        try {
            const { enc } = this.props;
            const token = req.headers['Authorization'] || req.headers['authorization'];

            const access_token = token.replace(/Bearer /g, '');
            const split = access_token.split('.');

            const payload = CryptoJS.AES.decrypt(this.addSpecials(split[1]), this.SECRET_KEY).toString(CryptoJS.enc.Utf8);
            let words = enc.Base64.parse(payload);

            const textString = JSON.parse(Buffer.from(JSON.parse(enc.Utf8.stringify(words)), 'base64').toString('binary'));
            return {
                status: true,
                data: textString
            };
        }
        catch (error) {
            return {
                status: false,
                message: error.message
            };
        }
    };
    /**
     * Registra um JWT
     * @return String
     */
    register = (params: object = {}): string => {
        try {
            params['iss'] = this.ISS;
            let headerJWT = this.buildHeader();
            let payloadJWT = this.buildPayload(params);
            let prev_token = headerJWT + '.' + payloadJWT;
            const signature = this.buildSignature(prev_token);
            const jwt = headerJWT + '.' + payloadJWT + '.' + signature;
            return jwt;
        }
        catch (error) {
            throw error;
        }
    }
}

export default JWT;