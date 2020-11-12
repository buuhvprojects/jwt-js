"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var CryptoJS = require("crypto-js");
/**
 * @todo Classe de controle de sessão onde pode ser gerado um JWT e validar o mesmo
 * @todo Depende do módulo CryptoJS - [npm i --save crypto-js]
 * @author Bruno Nascimento <br.dev.jobs@gmail.com>
 */
var JWT = /** @class */ (function () {
    function JWT(SECRET_KEY, ISS) {
        var _this = this;
        /**
         * Registra um JWT
         * @return String
         */
        this.register = function (params) {
            if (params === void 0) { params = {}; }
            try {
                params['iss'] = _this.ISS;
                var headerJWT = _this.buildHeader();
                var payloadJWT = _this.buildPayload(params);
                var prev_token = headerJWT + '.' + payloadJWT;
                var signature = _this.buildSignature(prev_token);
                var jwt = headerJWT + '.' + payloadJWT + '.' + signature;
                return jwt;
            }
            catch (error) {
                throw error;
            }
        };
        /**
         * @todo Constroi o cabeçalho do JWT
         * @returns {String} - base64
         */
        this.buildHeader = function () {
            try {
                var enc = _this.props.enc;
                var headerObject = {
                    type: 'JWT',
                    alg: 'HS256'
                };
                var headerParse = enc.Utf8.parse(JSON.stringify(headerObject));
                var headerStringify = enc.Base64.stringify(headerParse);
                var header = headerStringify.replace(/=+$/, '');
                header = header.replace(/\+/g, '-');
                header = header.replace(/\//g, '_');
                return header;
            }
            catch (error) {
                throw error;
            }
        };
        /**
         * @todo Constroi o payload/corpo(onde ficam os dados utilizados do jwt como user_id, tempo de expiração)
         * @returns {String} - base64
         */
        this.buildPayload = function (params) {
            try {
                var enc = _this.props.enc;
                var toParse = JSON.stringify(params);
                var payloadParse = enc.Utf8.parse(toParse);
                var payloadStringify = enc.Base64.stringify(payloadParse);
                var payloadParse2 = enc.Utf8.parse(JSON.stringify(payloadStringify));
                var payloadStringify2 = enc.Base64.stringify(payloadParse2);
                var payload = payloadStringify2.replace(/=+$/, '');
                payload = payload.replace(/\+/g, '-');
                payload = payload.replace(/\//g, '_');
                return payload;
            }
            catch (error) {
                throw error;
            }
        };
        /**
         * @todo Constroi a assinatura do JWT
         * @returns {String} - base64
         */
        this.buildSignature = function (prev_token) {
            try {
                var enc = _this.props.enc;
                var hash = CryptoJS.HmacSHA256(prev_token, SECRET_KEY);
                var prev_signature = enc.Base64.stringify(hash);
                prev_signature = prev_signature.replace(/=+$/, '');
                prev_signature = prev_signature.replace(/\+/g, '-');
                prev_signature = prev_signature.replace(/\//g, '_');
                return prev_signature;
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
        this.checkJWT = function (req) {
            try {
                var enc = _this.props.enc;
                var token = req.headers['Authorization'] || req.headers['authorization'];
                if (/Bearer( )(.+){1}/g.test(token) === false) {
                    return {
                        status: false,
                        message: 'Invalid access token'
                    };
                }
                var access_token = token.replace(/Bearer /g, '');
                var split = access_token.split('.');
                if (split.length < 3) {
                    return {
                        status: false,
                        message: 'Invalid access token'
                    };
                }
                var headerJWT = split[0];
                if (headerJWT !== _this.buildHeader()) {
                    return {
                        status: false,
                        message: 'Invalid access token header'
                    };
                }
                var payloadJWT = split[1];
                var signature = split[2];
                var prev_token = headerJWT + '.' + payloadJWT;
                var prev_signature = _this.buildSignature(prev_token);
                if (signature === prev_signature) {
                    var words = enc.Base64.parse(split[1]);
                    var textString = JSON.parse(enc.Utf8.stringify(words));
                    if (textString.expires && (textString.expires >= new Date().getTime()))
                        return {
                            status: true
                        };
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
        this.data = function (req) {
            try {
                var enc = _this.props.enc;
                var token = req.headers['Authorization'] || req.headers['authorization'];
                var access_token = token.replace(/Bearer /g, '');
                var split = access_token.split('.');
                var words = enc.Base64.parse(JSON.parse(enc.Utf8.stringify(enc.Base64.parse(split[1]))));
                var textString = JSON.parse(enc.Utf8.stringify(words));
                var words2 = enc.Utf8.stringify(textString);
                var textString2 = enc.Base64.parse(words2);
                return {
                    status: true,
                    data: textString2
                };
            }
            catch (error) {
                return {
                    status: false,
                    message: error.message
                };
            }
        };
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
    return JWT;
}());
exports.default = JWT;
//# sourceMappingURL=index.js.map