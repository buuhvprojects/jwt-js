import * as CryptoJS from 'crypto-js';
declare type WordArray = CryptoJS.lib.WordArray;
interface jwtProps {
    enc: {
        Utf8: {
            stringify(wordArray: WordArray): string;
            parse(str: string): WordArray;
        };
        Base64: {
            stringify(wordArray: WordArray): string;
            parse(str: string): WordArray;
        };
    };
}
interface req {
    headers: {
        Authorization?: string;
        authorization?: string;
    };
}
interface checkJWT {
    status: boolean;
    message?: string;
}
interface dataJWT {
    status: boolean;
    data?: any;
    message?: string;
}
/**
 * @todo Classe de controle de sessão onde pode ser gerado um JWT e validar o mesmo
 * @todo Depende do módulo CryptoJS - [npm i --save crypto-js]
 * @author Bruno Nascimento <br.dev.jobs@gmail.com>
 */
declare class JWT {
    props: jwtProps;
    ISS: string;
    SECRET_KEY: string;
    constructor(SECRET_KEY: string, ISS: string);
    /**
     * @todo Constroi o cabeçalho do JWT
     * @returns {String} - base64
     */
    buildHeader: () => string;
    /**
     * @todo Constroi o payload/corpo(onde ficam os dados utilizados do jwt como user_id, tempo de expiração)
     * @returns {String} - base64
     */
    buildPayload: (params: object) => string;
    /**
     * @todo Constroi a assinatura do JWT
     * @returns {String} - base64
     */
    buildSignature: (prev_token: string) => string;
    /**
     * @todo Verifica se o token é valido
     * @param {req} - dados da requisição
     * @returns {Object} - status e o conteúdo
     */
    checkJWT: (req: req) => checkJWT;
    /**
     * @todo Retorna os dados contidos no JWT
     * @param {req} - dados da requisição
     * @returns {Object} - status e conteúdo
     */
    data: (req: req) => dataJWT;
    /**
     * Registra um JWT
     * @return String
     */
    register: (params?: object) => string;
}
export default JWT;
