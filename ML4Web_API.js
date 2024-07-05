var JS_Crypto_API = (function() {
    function H(L) {
        ML4WebLog.log("JS_Crypto_API Init() start...");
        magicjs.init(ConfigObject.MAGICJS_LIC);
        L(0, {
            result: "JS_Crypto_API init success..."
        })
    }

    function w(L, P) {
        ML4WebLog.log("base64encode by javascript");
        var N = "";
        try {
            var N = magicjs.base64.encode(L);
            if (typeof P === "function") {
                P(0, {
                    result: N
                })
            } else {
                return N
            }
        } catch (O) {
            if (typeof P === "function") {
                P(O.code, {
                    errCode: 888,
                    errMsg: O.message
                })
            } else {
                return N
            }
        }
    }

    function p(L, P) {
        ML4WebLog.log("base64decode by javascript");
        var N = "";
        try {
            var N = magicjs.base64.decode(L);
            if (typeof P === "function") {
                P(0, {
                    result: N
                })
            } else {
                return N
            }
        } catch (O) {
            if (typeof P === "function") {
                P(O.code, {
                    errCode: 888,
                    errMsg: O.message
                })
            } else {
                return N
            }
        }
    }

    function t(O, S, L, T) {
        ML4WebLog.log("genHmac by javascript");
        try {
            var N = magicjs.hmac.create(O);
            N.init(magicjs.base64.decode(S));
            N.update(L);
            var P = N.generate();
            var Q = magicjs.base64.encode(P);
            T(0, {
                Base64Result: Q
            })
        } catch (R) {
            T(ML4WebLog.getErrCode("Crypto_JS_genHmac"), {
                errCode: 888,
                errMsg: R.message
            })
        }
    }

    function r(P, S, O, Q, T) {
        ML4WebLog.log("verifyHmac by javascript");
        try {
            var N = magicjs.hmac.create(P);
            N.init(magicjs.base64.decode(S));
            N.update(O);
            var L = N.verify(magicjs.base64.decode(Q));
            T(0, {
                result: L
            })
        } catch (R) {
            T(ML4WebLog.getErrCode("Crypto_JS_verifyHmac"), {
                errCode: 888,
                errMsg: R.message
            })
        }
    }

    function J(N, T, L, O, U) {
        ML4WebLog.log("encrypt by javascript");
        try {
            var Q = magicjs.cipher.create(true, N, magicjs.base64.decode(T));
            Q.init(magicjs.base64.decode(L));
            Q.update(O);
            Q.finish();
            var S = magicjs.base64.encode(Q.output);
            var P = magicjs.hex.encode(Q.output);
            if (typeof(U) == "undefined") {
                return {
                    errCode: 0,
                    Base64Result: S,
                    HexResult: P
                }
            } else {
                U(0, {
                    Base64Result: S,
                    HexResult: P
                })
            }
        } catch (R) {
            if (typeof(U) == "undefined") {
                ML4WebLog.log("- encrypt Error = " + R.message);
                return {
                    errCode: ML4WebLog.getErrCode("Crypto_JS_encrypt"),
                    errMsg: R.message
                }
            } else {
                U(ML4WebLog.getErrCode("Crypto_JS_encrypt"), {
                    errCode: 888,
                    errMsg: R.message
                })
            }
        }
    }

    function m(P, T, N, O, S) {
        ML4WebLog.log("decrypt by javascript");
        try {
            var L = magicjs.cipher.create(false, P, magicjs.base64.decode(T));
            L.init(magicjs.base64.decode(N));
            L.update(magicjs.base64.decode(O));
            L.finish();
            var R = L.output.data;
            S(0, {
                stringResult: R
            })
        } catch (Q) {
            S(ML4WebLog.getErrCode("Crypto_JS_decrypt"), {
                errCode: 888,
                errMsg: Q.message
            })
        }
    }

    function l(O, T, N, V, S, U) {
        ML4WebLog.log("sign by javascript");
        try {
            var al = "";
            if (N != null) {
                N = ML4WebApi.ml4web_crypto_api.SD_api(N);
                al = magicjs.pkcs5.decrypt(T, N)
            } else {
                if (typeof(T) == "string") {
                    al = magicjs.priKey.create(T)
                } else {
                    al = T
                }
            }
            var aa = "";
            var af = {};
            if (typeof(O) == "string") {
                aa = magicjs.x509Cert.create(O)
            } else {
                aa = O
            }
            var af = {};
            if (S != null || S != undefined) {
                var ad = "OPT_NONE";
                var ag = "OPT_USE_CONTNET_INFO";
                var L = "OPT_NO_CONTENT";
                var W = "OPT_SIGNKOREA_FORMAT";
                var X = "OPT_HASHED_CONTENT";
                var ae = "OPT_NO_SIGNED_ATTRIBUTES";
                var Z = "OPT_CONTNET_TYPE_ARCCERT";
                var aj = "rsa15";
                var Y = "rsa20";
                var an = "RSASSA-PKCS1-V1_5";
                var ai = "RSA-PSS";
                var R = "RSA-OAEP";
                var ak = "none";
                if (S.ds_pki_sign != undefined) {
                    var ac = 0;
                    var ah = 0;
                    for (var ab = 0; ab < S.ds_pki_sign.length; ab++) {
                        switch (S.ds_pki_sign[ab]) {
                            case ad:
                                ah = magicjs.pkcs7.signedData.format.none;
                                break;
                            case ag:
                                ah = magicjs.pkcs7.signedData.format.useContentInfo;
                                break;
                            case L:
                                ah = magicjs.pkcs7.signedData.format.noContent;
                                break;
                            case W:
                                ah = magicjs.pkcs7.signedData.format.signGateFormat;
                                break;
                            case X:
                                ah = magicjs.pkcs7.signedData.format.hashedContent;
                                break;
                            case ae:
                                ah = magicjs.pkcs7.signedData.format.noSignedAttributes;
                                break;
                            case Z:
                                ak = Z;
                                break
                        }
                        if (ab == 0) {
                            ac = ah
                        } else {
                            ac = ac | ah
                        }
                    }
                    af.format = ac
                }
                if (S.ds_pki_rsa != undefined) {
                    if (S.ds_pki_rsa == Y) {
                        af.scheme = ai;
                        if (S.ds_pki_hash != undefined) {
                            af.md = S.ds_pki_hash
                        }
                    } else {
                        af.scheme = an
                    }
                }
            }
            ML4WebLog.log("sign by javascript : Option " + JSON.stringify(af));
            var P = null;
            if (S.ds_pki_signdata != "") {
                P = magicjs.pkcs7.signedData.create(S.ds_pki_signdata)
            } else {
                P = magicjs.pkcs7.signedData.create()
            }
            if (S.ds_msg_decode == "true") {
                P.content = magicjs.base64.decode(V)
            } else {
                if (S.ds_msg_decode == "hash") {
                    P.content = magicjs.hex.decode(V)
                } else {
                    P.content = V
                }
            }
            if (ak === Z) {
                P.contentType = "1.2.410.200032.2.1"
            }
            var Q = null;
            if (S.ds_pki_signdata != "" && S.ds_pki_signData !== undefined) {
                P.addSign(aa, al, af);
                Q = magicjs.base64.encode(P.toDer().data)
            } else {
                P.sign(aa, al, af);
                Q = magicjs.base64.encode(P.toDer().data)
            }
            if (typeof U === "function") {
                U(0, {
                    stringResult: Q
                })
            } else {
                return {
                    code: 0,
                    data: Q
                }
            }
        } catch (am) {
            U(ML4WebLog.getErrCode("Crypto_JS_sign"), {
                errCode: 888,
                errMsg: am.message
            })
        }
    }

    function s(N, Q, L, T, P, R) {
        ML4WebLog.log("signature by javascript");
        try {
            var ab = "";
            if (L != null) {
                L = ML4WebApi.ml4web_crypto_api.SD_api(L);
                ab = magicjs.pkcs5.decrypt(Q, L)
            } else {
                if (typeof(Q) == "string") {
                    ab = magicjs.priKey.create(Q)
                } else {
                    ab = Q
                }
            }
            var V = "";
            var X = {};
            if (typeof(N) == "string") {
                V = magicjs.x509Cert.create(N)
            } else {
                V = N
            }
            if (ab.algorithm == "kcdsa") {
                X.pubKey = V.pubKey;
                if (P.ds_pki_hash != undefined) {
                    X.md = P.ds_pki_hash
                }
            } else {
                if (P != null || P != undefined) {
                    var aa = "rsa15";
                    var U = "rsa20";
                    var ae = "RSASSA-PKCS1-V1_5";
                    var Z = "RSA-PSS";
                    var S = "RSA-OAEP";
                    if (P.ds_pki_sign != undefined) {
                        var W = 0;
                        var Y = 0
                    }
                    if (P.ds_pki_rsa != undefined) {
                        if (P.ds_pki_rsa == U) {
                            X.scheme = Z;
                            if (P.ds_pki_hash != undefined) {
                                X.md = P.ds_pki_hash
                            }
                        } else {
                            X.scheme = ae;
                            if (P.ds_pki_hash != undefined) {
                                X.md = P.ds_pki_hash
                            }
                        }
                    }
                }
            }
            if (T === null || T === "") {
                var ad = V.subject;
                T = ML4WebApi.makeReverseDN(ad)
            }
            var O = magicjs.base64.encode(ab.generateSignature(T, X.md, X));
            R(0, {
                stringResult: O
            })
        } catch (ac) {
            R(ML4WebLog.getErrCode("Crypto_JS_sign"), {
                errCode: 888,
                errMsg: ac.message
            })
        }
    }

    function v(O, Y, U, Q, R, X) {
        ML4WebLog.log("autoSign by javascript");
        try {
            var L;
            var T = magicjs.pkcs7.signedData.format.none;
            var W = magicjs.pkcs7.signedData.create();
            var V = "none";
            if (typeof(Q) == "undefined" || Q == null) {
                T = magicjs.pkcs7.signedData.format.useContentInfo
            } else {
                if (typeof(Q.sign) == "object") {
                    T = magicjs.pkcs7.signedData.format.none;
                    for (var P = 0; P < Q.sign.length; P++) {
                        if (Q.sign[P].toUpperCase() === "OPT_NONE") {
                            T = T | magicjs.pkcs7.signedData.format.none
                        } else {
                            if (Q.sign[P].toUpperCase() === "OPT_USE_CONTNET_INFO") {
                                T = T | magicjs.pkcs7.signedData.format.useContentInfo
                            } else {
                                if (Q.sign[P].toUpperCase() === "OPT_NO_CONTENT") {
                                    T = T | magicjs.pkcs7.signedData.format.noContent
                                } else {
                                    if (Q.sign[P].toUpperCase() === "OPT_SIGNKOREA_FORMAT") {
                                        T = T | magicjs.pkcs7.signedData.format.signGateFormat
                                    } else {
                                        if (Q.sign[P].toUpperCase() === "OPT_HASHED_CONTENT") {
                                            T = T | magicjs.pkcs7.signedData.format.hashedContent
                                        } else {
                                            if (Q.sign[P].toUpperCase() === "OPT_NO_SIGNEDATTRIBUTES") {
                                                T = T | magicjs.pkcs7.signedData.format.noSignedAttributes
                                            } else {
                                                if (Q.sign[P].toUpperCase() === "OPT_CONTNET_TYPE_ARCCERT") {
                                                    V = Q.sign[P].toUpperCase()
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            L = {
                format: T,
                scheme: "RSASSA-PKCS1-V1_5"
            };
            privateKey = ML4WebApi.decryptSecurekey(O, U);
            if (L.format & magicjs.pkcs7.signedData.format.hashedContent) {
                W.content = magicjs.hex.decode(R)
            } else {
                W.content = magicjs.utf8.encode(R)
            }
            if (V === "OPT_CONTNET_TYPE_ARCCERT") {
                W.contentType = "1.2.410.200032.2.1"
            }
            W.sign(magicjs.x509Cert.create(Y, false), privateKey, L);
            var N = magicjs.base64.encode(W.toDer().data);
            if (typeof X === "function") {
                X(0, {
                    stringResult: N
                })
            } else {
                return {
                    code: 0,
                    data: N
                }
            }
        } catch (S) {
            X(ML4WebLog.getErrCode("Crypto_JS_sign"), {
                errCode: 888,
                errMsg: S.message
            })
        }
    }

    function c(S, N, T, V, U) {
        ML4WebLog.log("envelopedData by javascript");
        try {
            var Q = magicjs.x509Cert.create(S);
            var P = magicjs.pkcs7.envelopedData.create();
            P.content = N;
            var L = null;
            if (V == null) {
                L = {
                    scheme: "RSAES-PKCS1-V1_5"
                }
            } else {
                L = V
            }
            L = {
                scheme: "RSAES-PKCS1-V1_5"
            };
            P.addRecipient(Q, L);
            P.encrypt(T);
            var O = magicjs.base64.encode(P.toDer().data);
            U(0, {
                stringResult: O
            })
        } catch (R) {
            U(ML4WebLog.getErrCode("Crypto_JS_envelopedData"), {
                errCode: 888,
                errMsg: R.message
            })
        }
    }

    function C(W, ah, T, af, ac, N, S, R) {
        ML4WebLog.log("signedEnvelopedData by javascript");
        try {
            var P = magicjs.x509Cert.create(W);
            var O = magicjs.x509Cert.create(ah);
            var aj = magicjs.pkcs5.decrypt(T, af);
            var Z = {};
            var Y = {};
            var X = "OPT_NONE";
            var aa = "OPT_USE_CONTNET_INFO";
            var L = "OPT_NO_CONTENT";
            var U = "OPT_SIGNKOREA_FORMAT";
            var ae = "rsa15";
            var V = "rsa20";
            var ai = "RSASSA-PKCS1-V1_5";
            var ad = "RSA-PSS";
            var Q = "RSA-OAEP";
            Z.scheme = ai;
            Y.scheme = ai;
            if (S != null || S != undefined) {
                if (S.ds_pki_rsa != undefined) {
                    if (S.ds_pki_rsa == V) {
                        Z.scheme = Q;
                        Y.scheme = ad;
                        if (S.ds_pki_hash != undefined) {
                            Z.md = S.ds_pki_hash;
                            Y.md = S.ds_pki_hash
                        }
                    }
                }
            }
            var ab = magicjs.pkcs7.signedAndEnvData.create();
            ab.content = ac;
            ab.addRecipient(P, Z);
            ab.signAndEnv(O, aj, N, Y);
            R(0, {
                stringResult: magicjs.base64.encode(ab.toPem())
            })
        } catch (ag) {
            R(ML4WebLog.getErrCode("Crypto_JS_signedEnvelopedData"), {
                errCode: 888,
                errMsg: ag.message
            })
        }
    }

    function I(T, L, O, R, S) {
        ML4WebLog.log("verifyVID by javascript");
        try {
            var N = magicjs.pkcs5.decrypt(L, O);
            var P = magicjs.x509Cert.create(T);
            var U = P.verifyVID(N.getRandomNum(), R);
            S(0, {
                result: U
            })
        } catch (Q) {
            S(ML4WebLog.getErrCode("Crypto_JS_verifyVID"), {
                errCode: 888,
                errMsg: Q.message
            })
        }
    }

    function A(N, R) {
        ML4WebLog.log("generateRandom by javascript");
        try {
            var P = magicjs.generateRandomBytes(N);
            var L = magicjs.base64.encode(P);
            var O = magicjs.hex.encode(P);
            if (typeof(R) == "undefined") {
                return {
                    errCode: 0,
                    result: L,
                    resulthex: O
                }
            } else {
                R(0, {
                    result: L,
                    resulthex: O
                })
            }
        } catch (Q) {
            if (typeof(R) == "undefined") {
                ML4WebLog.log("- genHash Error = " + Q.message);
                return {
                    errCode: ML4WebLog.getErrCode("Crypto_JS_generateRandom"),
                    errMsg: Q.message
                }
            } else {
                R(ML4WebLog.getErrCode("Crypto_JS_generateRandom"), {
                    errCode: 888,
                    errMsg: Q.message
                })
            }
        }
    }

    function u(N, P, R) {
        ML4WebLog.log("genKeypair by javascript");
        try {
            var L = magicjs.generateKeyPair(N, {
                bits: P
            });
            var O = {};
            O.ds_pki_pubkey = magicjs.base64.encode(L.publicKey.toDer().data);
            O.ds_pki_prikey = magicjs.base64.encode(L.privateKey.toDer().data);
            R(0, {
                result: O
            })
        } catch (Q) {
            R(ML4WebLog.getErrCode("Crypto_JS_genKeypair"), {
                errCode: 888,
                errMsg: Q.message
            })
        }
    }

    function K(N, L, T) {
        ML4WebLog.log("genHash by javascript");
        try {
            var Q = magicjs.md.create(N);
            Q.update(L);
            var S = Q.digest();
            var P = magicjs.base64.encode(S);
            var O = magicjs.hex.encode(S);
            if (typeof(T) == "undefined") {
                return {
                    errCode: 0,
                    hash: P,
                    resulthex: O
                }
            } else {
                T(0, {
                    hash: P,
                    resulthex: O
                })
            }
        } catch (R) {
            if (typeof(T) == "undefined") {
                ML4WebLog.log("- genHash Error = " + R.message);
                return {
                    errCode: ML4WebLog.getErrCode("Crypto_JS_genHash"),
                    errMsg: R.message
                }
            } else {
                T(ML4WebLog.getErrCode("Crypto_JS_genHash"), {
                    errCode: 888,
                    errMsg: R.message
                })
            }
        }
    }

    function j(L, O, P, U) {
        ML4WebLog.log("genHashCount by javascript");
        try {
            var T = magicjs.md.create(L);
            var R = O;
            while (P--) {
                R = T.digest(R)
            }
            var S = magicjs.base64.encode(R);
            var N = magicjs.hex.encode(R);
            U(0, {
                hash: S,
                resulthex: N
            })
        } catch (Q) {
            U(ML4WebLog.getErrCode("Crypto_JS_genHash"), {
                errCode: 888,
                errMsg: Q.message
            })
        }
    }

    function E(P, N, R) {
        ML4WebLog.log("prikeyDecrypt by javascript");
        N = ML4WebApi.ml4web_crypto_api.SD_api(N);
        try {
            var L = magicjs.pkcs5.decrypt(P, N);
            var Q = magicjs.base64.encode(L.toDer().data);
            if (typeof(R) == "undefined") {
                return {
                    errCode: 0,
                    Base64String: Q,
                    priKeyInfo: L
                }
            } else {
                R(0, {
                    Base64String: Q
                })
            }
        } catch (O) {
            if (typeof(R) == "undefined") {
                ML4WebLog.log("- prikeyDecrypt Error = " + O.message);
                return {
                    errCode: ML4WebLog.getErrCode("Crypto_JS_prikeyDecrypt"),
                    errMsg: O.message
                }
            } else {
                R(ML4WebLog.getErrCode("Crypto_JS_prikeyDecrypt"), {
                    errCode: 888,
                    errMsg: O.message
                })
            }
        }
    }

    function o(R, N, P, S) {
        ML4WebLog.log("prikeyEncrypt by javascript");
        try {
            var U = null;
            if (P == null) {
                U = {};
                U.algorithm = "seed"
            } else {
                U.algorithm = P
            }
            var T = magicjs.priKey.create(R);
            var Q = magicjs.pkcs5.encrypt(T, N, U);
            var L = magicjs.base64.encode(Q);
            S(0, {
                Base64String: L
            })
        } catch (O) {
            S(ML4WebLog.getErrCode("Crypto_JS_prikeyEncrypt"), {
                errCode: 888,
                errMsg: O.message
            })
        }
    }

    function g(N, P, R) {
        ML4WebLog.log("getVIDRandom by javascript");
        try {
            P = ML4WebApi.ml4web_crypto_api.SD_api(P);
            var O = magicjs.pkcs5.decrypt(N, P);
            var L = magicjs.base64.encode(O.getRandomNum());
            R(0, {
                result: L
            })
        } catch (Q) {
            R(ML4WebLog.getErrCode("Crypto_JS_getVIDRandom"), {
                errCode: 888,
                errMsg: Q.message
            })
        }
    }

    function a(W, L, O, T, V) {
        ML4WebLog.log("getVIDRandomHash by javascript");
        try {
            var Q = magicjs.x509Cert.create(W);
            var N = magicjs.pkcs5.decrypt(L, O);
            var S = N.getRandomNum();
            if (S == null) {
                return null
            }
            var U = Q.makeVID(S, T, 2);
            var R = magicjs.base64.encode(U);
            V(0, {
                result: R
            })
        } catch (P) {
            V(ML4WebLog.getErrCode("Crypto_JS_getVIDRandom"), {
                errCode: 888,
                errMsg: P.message
            })
        }
    }

    function f(Y, X, P, Z) {
        ML4WebLog.log("asymEncrypt by javascript");
        try {
            var R = null;
            var L = {};
            if (P != null || P != undefined) {
                var N = "rsa15";
                var Q = "rsa20";
                var O = "RSASSA-PKCS1-V1_5";
                var W = "RSA-PSS";
                var U = "RSA-OAEP";
                if (P.ds_pki_rsa != undefined) {
                    if (P.ds_pki_rsa == Q) {
                        L.scheme = U;
                        if (P.ds_pki_hash != undefined) {
                            L.md = P.ds_pki_hash
                        }
                    } else {
                        L.scheme = O
                    }
                }
            }
            ML4WebLog.log("- asymEncrypt Option = " + JSON.stringify(L));
            var T = magicjs.x509Cert.create(Y);
            var V = T.pubKey;
            R = V.encrypt(X, L);
            var aa = magicjs.base64.encode(R);
            if (typeof(Z) == "undefined") {
                return aa
            } else {
                Z(0, {
                    result: aa
                })
            }
        } catch (S) {
            if (typeof(Z) == "undefined") {
                ML4WebLog.log("- asymEncrypt Error = " + S.message);
                return ML4WebLog.getErrCode("Crypto_JS_asymEncrypt")
            } else {
                Z(ML4WebLog.getErrCode("Crypto_JS_asymEncrypt"), {
                    errCode: 888,
                    errMsg: S.message
                })
            }
        }
    }

    function x(Z, S, O, Q, Y) {
        ML4WebLog.log("asymDecrypt by javascript");
        try {
            var L = {};
            if (Q != null || Q != undefined) {
                var N = "rsa15";
                var T = "rsa20";
                var P = "RSASSA-PKCS1-V1_5";
                var W = "RSA-PSS";
                var V = "RSA-OAEP";
                if (Q.ds_pki_rsa != undefined) {
                    if (Q.ds_pki_rsa == T) {
                        L.scheme = V;
                        if (Q.ds_pki_hash != undefined) {
                            L.md = Q.ds_pki_hash
                        }
                    } else {
                        L.scheme = P
                    }
                }
            }
            ML4WebLog.log("- asymDecrypt Option = " + JSON.stringify(L));
            var X = magicjs.pkcs5.decrypt(Z, S);
            var R = null;
            R = X.decrypt(magicjs.base64.decode(O), L);
            Y(0, {
                result: R
            })
        } catch (U) {
            Y(ML4WebLog.getErrCode("Crypto_JS_asymDecrypt"), {
                errCode: 888,
                errMsg: U.message
            })
        }
    }

    function y(L, N, R) {
        ML4WebLog.log("pfxImport by javascript");
        N = ML4WebApi.ml4web_crypto_api.SD_api(N);
        try {
            var Q = magicjs.pkcs12.create(L);
            Q.importPfx(N);
            var O = {};
            if (Q.safeContents.length < 1) {
                R(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                    errCode: 888,
                    errMsg: "pfx is empty"
                })
            }
            if (Q.safeContents.length == 1) {
                k(Q.safeContents[0].cert.toPem(), ["keyusage"], function(T, S) {
                    if (T == 0) {
                        if (S.result.keyusage.indexOf("digitalSignature") != -1) {
                            O.signcert = magicjs.base64.encode(Q.safeContents[0].cert.toDer());
                            o(magicjs.base64.encode(Q.safeContents[0].priKey.toDer()), N, null, function(V, U) {
                                if (V == "0") {
                                    O.signpri = U.Base64String
                                } else {
                                    R(ML4WebLog.getErrCode("Crypto_JS_prikeyEncrypt"), {
                                        errCode: V,
                                        errMsg: U
                                    })
                                }
                            });
                            R(0, {
                                result: O
                            })
                        } else {
                            R(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                                errCode: 888,
                                errMsg: "digitalSignature is empty"
                            })
                        }
                    } else {
                        R(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                            errCode: T,
                            errMsg: S.errMsg
                        })
                    }
                })
            } else {
                k(Q.safeContents[0].cert.toPem(), ["keyusage"], function(T, S) {
                    if (T == 0) {
                        if (S.result.keyusage.indexOf("digitalSignature") != -1) {
                            O.signcert = magicjs.base64.encode(Q.safeContents[0].cert.toDer());
                            o(magicjs.base64.encode(Q.safeContents[0].priKey.toDer()), N, null, function(V, U) {
                                if (V == "0") {
                                    O.signpri = U.Base64String;
                                    O.kmcert = magicjs.base64.encode(Q.safeContents[1].cert.toDer());
                                    o(magicjs.base64.encode(Q.safeContents[1].priKey.toDer()), N, null, function(X, W) {
                                        if (X == "0") {
                                            O.kmpri = W.Base64String;
                                            R(0, {
                                                result: O
                                            })
                                        } else {
                                            R(ML4WebLog.getErrCode("Crypto_JS_prikeyEncrypt"), {
                                                errCode: X,
                                                errMsg: W
                                            })
                                        }
                                    })
                                } else {
                                    R(ML4WebLog.getErrCode("Crypto_JS_prikeyEncrypt"), {
                                        errCode: V,
                                        errMsg: U
                                    })
                                }
                            })
                        } else {
                            O.signcert = magicjs.base64.encode(Q.safeContents[1].cert.toDer());
                            o(magicjs.base64.encode(Q.safeContents[1].priKey.toDer()), N, null, function(V, U) {
                                if (V == "0") {
                                    O.signpri = U.Base64String;
                                    O.kmcert = magicjs.base64.encode(Q.safeContents[0].cert.toDer());
                                    o(magicjs.base64.encode(Q.safeContents[0].priKey.toDer()), N, null, function(X, W) {
                                        if (X == "0") {
                                            O.kmpri = W.Base64String;
                                            R(0, {
                                                result: O
                                            })
                                        } else {
                                            R(ML4WebLog.getErrCode("Crypto_JS_prikeyEncrypt"), {
                                                errCode: X,
                                                errMsg: W
                                            })
                                        }
                                    })
                                } else {
                                    R(ML4WebLog.getErrCode("Crypto_JS_prikeyEncrypt"), {
                                        errCode: V,
                                        errMsg: U
                                    })
                                }
                            })
                        }
                    } else {
                        R(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                            errCode: T,
                            errMsg: S.errMsg
                        })
                    }
                })
            }
        } catch (P) {
            if (P.code == 184573952) {
                N = ML4WebApi.ml4web_crypto_api.HD_api(N);
                B(L, N, R)
            } else {
                R(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                    errCode: 888,
                    errMsg: P.message
                })
            }
        }
    }

    function B(L, N, S) {
        ML4WebLog.log("pfxImport by javascript");
        N = ML4WebApi.ml4web_crypto_api.SD_api(N);
        try {
            var P = {
                format: magicjs.pkcs12.format.encPriKey
            };
            var R = magicjs.pkcs12.create(L);
            R.importPfx(N, P);
            var O = {};
            if (R.safeContents.length < 1) {
                S(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                    errCode: 888,
                    errMsg: "pfx is empty"
                })
            }
            if (R.safeContents.length == 1) {
                k(R.safeContents[0].cert.toPem(), ["keyusage"], function(U, T) {
                    if (U == 0) {
                        if (T.result.keyusage.indexOf("digitalSignature") != -1) {
                            O.signcert = magicjs.base64.encode(R.safeContents[0].cert.toDer());
                            O.signpri = magicjs.base64.encode(R.safeContents[0].priKey);
                            S(0, {
                                result: O
                            })
                        } else {
                            S(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                                errCode: 888,
                                errMsg: "digitalSignature is empty"
                            })
                        }
                    } else {
                        S(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                            errCode: U,
                            errMsg: T.errMsg
                        })
                    }
                })
            } else {
                k(R.safeContents[0].cert.toPem(), ["keyusage"], function(U, T) {
                    if (U == 0) {
                        if (T.result.keyusage.indexOf("digitalSignature") != -1) {
                            O.signcert = magicjs.base64.encode(R.safeContents[0].cert.toDer());
                            O.signpri = magicjs.base64.encode(R.safeContents[0].priKey);
                            if (R.safeContents.length > 1) {
                                O.kmcert = magicjs.base64.encode(R.safeContents[1].cert.toDer());
                                O.kmpri = magicjs.base64.encode(R.safeContents[1].priKey)
                            }
                            S(0, {
                                result: O
                            })
                        } else {
                            O.signcert = magicjs.base64.encode(R.safeContents[1].cert.toDer());
                            O.signpri = magicjs.base64.encode(R.safeContents[1].priKey);
                            O.kmcert = magicjs.base64.encode(R.safeContents[0].cert.toDer());
                            O.kmpri = magicjs.base64.encode(R.safeContents[0].priKey);
                            S(0, {
                                result: O
                            })
                        }
                    } else {
                        S(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                            errCode: U,
                            errMsg: T.errMsg
                        })
                    }
                })
            }
        } catch (Q) {
            S(ML4WebLog.getErrCode("Crypto_JS_pfxImport"), {
                errCode: 888,
                errMsg: Q.message
            })
        }
    }

    function q(Q, L, T) {
        ML4WebLog.log("pfxExport by javascript");
        L = ML4WebApi.ml4web_crypto_api.SD_api(L);
        try {
            var P = magicjs.pkcs12.create();
            var S = magicjs.x509Cert.create(Q.signcert);
            var V = "";
            if (typeof(Q.pkcs5decrypt) == "undefined" || Q.pkcs5decrypt == true) {
                V = magicjs.pkcs5.decrypt(Q.signpri, L)
            } else {
                V = Q.signpri
            }
            P.safeContents.push({
                cert: S,
                priKey: V
            });
            if (Q.kmcert != null && Q.kmcert != undefined && Q.kmcert.length != 0) {
                var R = magicjs.x509Cert.create(Q.kmcert);
                var N = "";
                if (typeof(Q.pkcs5decrypt) == "undefined" || Q.pkcs5decrypt == true) {
                    N = magicjs.pkcs5.decrypt(Q.kmpri, L)
                } else {
                    N = Q.kmpri
                }
                P.safeContents.push({
                    cert: R,
                    priKey: N
                })
            }
            if (typeof(Q.pkcs5decrypt) == "undefined" || Q.pkcs5decrypt == true) {
                P.exportPfx(L, {
                    algorithm: "des-EDE3"
                })
            } else {
                P.exportPfx(L, {
                    algorithm: "des-EDE3",
                    format: magicjs.pkcs12.format.encPriKey
                })
            }
            var U = magicjs.base64.encode(P.toDer());
            T(0, {
                result: U
            })
        } catch (O) {
            T(ML4WebLog.getErrCode("Crypto_JS_pfxExport"), {
                errCode: 888,
                errMsg: O.message
            })
        }
    }

    function h(Q, L, U, T) {
        ML4WebLog.log("pfxChangePwExport by javascript");
        L = ML4WebApi.ml4web_crypto_api.SD_api(L);
        try {
            var P = magicjs.pkcs12.create();
            var S = magicjs.x509Cert.create(Q.signcert);
            var W = magicjs.pkcs5.decrypt(Q.signpri, L);
            P.safeContents.push({
                cert: S,
                priKey: W
            });
            if (Q.kmcert != null && Q.kmcert != undefined && Q.kmcert.length != 0) {
                var R = magicjs.x509Cert.create(Q.kmcert);
                var N = magicjs.pkcs5.decrypt(Q.kmpri, L);
                P.safeContents.push({
                    cert: R,
                    priKey: N
                })
            }
            P.exportPfx(U, {
                algorithm: "des-EDE3"
            });
            var V = magicjs.base64.encode(P.toDer());
            T(0, {
                result: V
            })
        } catch (O) {
            T(ML4WebLog.getErrCode("Crypto_JS_pfxChangePwExport"), {
                errCode: 888,
                errMsg: O.message
            })
        }
    }

    function k(W, T, am) {
        ML4WebLog.log("getcertInfo by javascript");
        try {
            var aw = "version";
            var V = "serialnum";
            var aB = "signaturealgorithm";
            var X = "issuername";
            var ad = "startdate";
            var ag = "enddate";
            var N = "startdatetime";
            var L = "enddatetime";
            var at = "subjectname";
            var aj = "pubkey";
            var ai = "pubkeyalgorithm";
            var Q = "keyusage";
            var au = "certpolicy";
            var P = "policyid";
            var ac = "policynotice";
            var an = "subjectaltname";
            var ae = "authkeyid";
            var ab = "subkeyid";
            var R = "crldp";
            var al = "aia";
            var ak = "realname";
            var O = magicjs.x509Cert.create(W);
            var Y = {};
            var az = {};
            var ao = O.extensions.length;
            if (ao > 0) {
                for (var ay = 0; ay < ao; ay++) {
                    if (O.extensions[ay].aki != null) {
                        az.aki = "KeyID=" + O.extensions[ay].aki.keyIdentifier.toHex() + ",\nCertificate Issuer:\n" + O.extensions[ay].aki.authorityCertIssuer + ",\nCertificate SerialNumber:\n" + O.extensions[ay].aki.authorityCertIssuer
                    } else {
                        if (O.extensions[ay].ski != null) {
                            az.subkeyid = O.extensions[ay].ski.toHex()
                        } else {
                            if (O.extensions[ay].keyUsage != null) {
                                az.keyusage = F(O.extensions[ay].keyUsage)
                            } else {
                                if (O.extensions[ay].certPolicies != null) {
                                    var ar = null;
                                    var aq = null;
                                    var ap = O.extensions[ay].certPolicies.length;
                                    for (var ax = 0; ax < ap; ax++) {
                                        az.policyid = O.extensions[ay].certPolicies[ax].policyIdentifier;
                                        if (O.extensions[ay].certPolicies[ax].cps != null) {
                                            ar = O.extensions[ay].certPolicies[ax].cps
                                        }
                                        if (O.extensions[ay].certPolicies[ax].unotice != null && O.extensions[ay].certPolicies[ax].unotice.explicitText != null) {
                                            aq = O.extensions[ay].certPolicies[ax].unotice.explicitText
                                        }
                                    }
                                    az.policynotice = aq;
                                    az.certpolicy = "policyID = " + az.policyid + ",\ncpsUri  = " + ar + ",\nUserNotice  = " + aq + ",\n"
                                } else {
                                    if (O.extensions[ay].subjectAltName != null || O.extensions[ay].issuertAltName != null) {
                                        var aa = null;
                                        if (O.extensions[ay].subjectAltName != null) {
                                            aa = O.extensions[ay].subjectAltName
                                        } else {
                                            aa = O.extensions[ay].issuertAltName
                                        }
                                        var U = aa.length;
                                        for (var ax = 0; ax < U; ax++) {
                                            if (aa[ax].otherName != null) {
                                                az.subjectaltname = "-identifyData\n- realName= " + aa[ax].otherName.realName;
                                                az.realname = aa[ax].otherName.realName;
                                                if (aa[ax].otherName.vid != null) {
                                                    az.subjectaltname += "- vid (" + aa[ax].otherName.vid.hashAlg + ")= " + aa[ax].otherName.vid.value.toHex()
                                                }
                                            }
                                        }
                                    } else {
                                        if (O.extensions[ay].crlDPs != null) {
                                            var Z = "";
                                            var aC = O.extensions[ay].crlDPs.length;
                                            for (var ax = 0; ax < aC; ax++) {
                                                Z += O.extensions[ay].crlDPs[ax].distributionPoint[0].uri + " "
                                            }
                                            az.crldp = Z
                                        } else {
                                            if (O.extensions[ay].aia != null) {
                                                var af = "";
                                                if (O.extensions[ay].aia.ocsp != null) {
                                                    af += O.extensions[ay].aia.ocsp.uri
                                                }
                                                az.aia = af
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            var av = T.length;
            for (var ay = 0; ay < av; ay++) {
                var S = null;
                switch (T[ay]) {
                    case aw:
                        Y.version = O.version;
                        break;
                    case V:
                        Y.serialnum = O.serialNum;
                        break;
                    case aB:
                        Y.signaturealgorithm = O.signAlg.name;
                        break;
                    case X:
                        Y.issuername = O.issuer;
                        break;
                    case ad:
                        var ah = O.validity.notBefore.getMonth() + 1;
                        Y.startdate = O.validity.notBefore.getFullYear() + "-" + ah + "-" + O.validity.notBefore.getDate();
                        break;
                    case ag:
                        var ah = O.validity.notAfter.getMonth() + 1;
                        Y.enddate = O.validity.notAfter.getFullYear() + "-" + ah + "-" + O.validity.notAfter.getDate();
                        break;
                    case N:
                        var ah = O.validity.notBefore.getMonth() + 1;
                        Y.startdatetime = O.validity.notBefore.getFullYear() + "-" + ah + "-" + O.validity.notBefore.getDate() + " " + O.validity.notBefore.getHours() + ":" + O.validity.notBefore.getMinutes() + ":" + O.validity.notBefore.getSeconds();
                    case L:
                        var ah = O.validity.notAfter.getMonth() + 1;
                        Y.enddatetime = O.validity.notAfter.getFullYear() + "-" + ah + "-" + O.validity.notAfter.getDate() + " " + O.validity.notAfter.getHours() + ":" + O.validity.notAfter.getMinutes() + ":" + O.validity.notAfter.getSeconds();
                        break;
                    case at:
                        Y.subjectname = O.subject;
                        break;
                    case aj:
                        Y.pubkey = O.pubKey.toDer().toHex();
                        break;
                    case ai:
                        Y.pubkeyalgorithm = O.pubKey.algorithm + " (" + O.pubKey.keyLength + " bits)";
                        break;
                    case Q:
                        Y.keyusage = az.keyusage;
                        break;
                    case au:
                        Y.certpolicy = az.certpolicy;
                        break;
                    case P:
                        Y.policyid = az.policyid;
                        break;
                    case an:
                        Y.subjectaltname = az.subjectaltname;
                        break;
                    case ae:
                        Y.authkeyid = az.authkeyid;
                        break;
                    case ab:
                        Y.subkeyid = az.subkeyid;
                        break;
                    case R:
                        Y.crldp = az.crldp;
                        break;
                    case al:
                        Y.aia = az.aia;
                        break;
                    case ak:
                        Y.realname = az.realname;
                        break;
                    case ac:
                        Y.policynotice = az.policynotice;
                        break
                }
            }
            am(0, {
                result: Y
            })
        } catch (aA) {
            am(42201, {
                errCode: 888,
                errMsg: aA.message
            })
        }
    }

    function n(L, O, N, Q, S) {
        ML4WebLog.log("prikeyChangePassword by javascript");
        try {
            var R = magicjs.pkcs5.changePassword(L, O, N);
            S(0, {
                result: magicjs.base64.encode(R)
            })
        } catch (P) {
            S(ML4WebLog.getErrCode("Crypto_JS_prikeyChangePassword"), {
                errCode: 888,
                errMsg: P.message
            })
        }
    }

    function b(O, N, L, Q, R) {
        ML4WebLog.log("certChangePassword by javascript");
        try {
            if (O == null || $.isEmptyObject(O)) {
                ML4WebLog.log("invalid param : jsonCert");
                R(100, $.i18n.prop("ER100") + "[jsonCert]");
                return
            } else {
                if (N == null || N == "") {
                    ML4WebLog.log("invalid param : sOldPassword");
                    R(100, $.i18n.prop("ER100") + "[sOldPassword]");
                    return
                } else {
                    if (L == null || L == "") {
                        ML4WebLog.log("invalid param : sNewPassword");
                        R(100, $.i18n.prop("ER100") + "[sNewPassword]");
                        return
                    } else {
                        if (typeof(O.signpri) == "undefined" || typeof(O.signpri) != "string") {
                            ML4WebLog.log("invalid param : jsonCert.signpri");
                            R(100, $.i18n.prop("ER100") + "[jsonCert.signpri]");
                            return
                        }
                    }
                }
            }
            N = ML4WebApi.ml4web_crypto_api.SD_api(N);
            L = ML4WebApi.ml4web_crypto_api.SD_api(L);
            O.signpri = magicjs.base64.encode(magicjs.pkcs5.changePassword(O.signpri, N, L));
            if (typeof(O.kmpri) != "undefined" && typeof(O.kmpri) == "string") {
                O.kmpri = magicjs.base64.encode(magicjs.pkcs5.changePassword(O.kmpri, N, L))
            }
            R(0, {
                result: O
            })
        } catch (P) {
            R(ML4WebLog.getErrCode("Crypto_JS_certChangePassword"), {
                errCode: 888,
                errMsg: P.message
            })
        }
    }

    function F(L) {
        var N = "";
        if (L.cRLSign) {
            N += "cRLSign"
        }
        if (L.dataEncipherment) {
            if (N.length) {
                N += ","
            }
            N += "dataEncipherment"
        }
        if (L.decipherOnly) {
            if (N.length) {
                N += ","
            }
            N += "decipherOnly"
        }
        if (L.digitalSignature) {
            if (N.length) {
                N += ","
            }
            N += "digitalSignature"
        }
        if (L.encipherOnly) {
            if (N.length) {
                N += ","
            }
            N += "encipherOnly"
        }
        if (L.keyAgreenment) {
            if (N.length) {
                N += ","
            }
            N += "keyAgreenment"
        }
        if (L.keyCertSign) {
            if (N.length) {
                N += ","
            }
            N += "keyCertSign"
        }
        if (L.keyEncipherment) {
            if (N.length) {
                N += ","
            }
            N += "keyEncipherment"
        }
        if (L.nonRepudiation) {
            if (N.length) {
                N += ","
            }
            N += "nonRepudiation"
        }
        return N
    }

    function e(Q, P) {
        var U = magicjs.pkcs7.signedData.create();
        var N = "";
        var T = "";
        var R = "";
        var S = "sha256";
        var O = P;
        var L;
        if (Q == "signedAttribute") {
            if (O.signTime.indexOf("T") < 0) {
                O.signTime = O.signTime.replace(" ", "T")
            }
            L = new Date(O.signTime);
            browser = ML4WebApi.get_browser_info();
            browserName = browser.name;
            if ((browserName.toLowerCase().indexOf("safari") > -1)) {
                L = new Date(L.setTime(L - (9 * 60 * 60 * 1000)))
            }
            N = {
                signingTime: L
            };
            T = U.makeTBSData(magicjs.utf8.encode(O.plainText), S, N)
        } else {
            T = magicjs.utf8.encode(O.plainText)
        }
        if (typeof(arguments[2]) != null && typeof(arguments[2]) != "undefined" && arguments[2] == 1) {
            R = "3031300d060960864801650304020105000420" + T
        } else {
            R = "3031300d060960864801650304020105000420" + G(T)
        }
        ML4WebLog.log("digestInfo : " + R);
        R = magicjs.base64.encode(R);
        ML4WebLog.log("base64 encoding digestInfo : " + R);
        return R
    }

    function G(O) {
        var L = magicjs.md.create("sha256");
        L.init();
        var N = L.digest(O);
        return N.toHex()
    }

    function D(R, T, S, P, N) {
        var V = magicjs.x509Cert.create(R);
        var Y = "RSASSA-PKCS1-V1_5";
        var U = "sha256";
        var X = magicjs.pkcs7.signedData.create();
        var O = z(S);
        var Q;
        if (T === "originHash") {
            Q = {
                signingTime: undefined
            }
        } else {
            Q = {
                signingTime: N
            }
        }
        var L = {
            scheme: Y,
            md: U,
            cert: V
        };
        if (T === "originHash") {
            L.format = magicjs.pkcs7.signedData.format.noSignedAttributes
        }
        if (typeof(arguments[5]) != "undefined" && typeof(arguments[5]) == "object") {
            if (arguments[5].indexOf("OPT_HASHED_CONTENT") > 0) {
                Q.format = magicjs.pkcs7.signedData.format.hashedContent;
                L.format = magicjs.pkcs7.signedData.format.hashedContent;
                if (typeof(arguments[6]) != "undefined" && arguments[6] == 1) {
                    O = magicjs.base64.decode(O)
                } else {
                    O = magicjs.hex.decode(O)
                }
            } else {
                if (arguments[5].indexOf("TBS_ENCODE_BASE64") > -1 || arguments[5].indexOf("TBS_ENCODE_HEX") > -1) {
                    if (typeof(arguments[6]) != "undefined" && arguments[6] == 1) {
                        O = magicjs.base64.decode(O)
                    }
                }
            }
        }
        var W = X.makeTBSData(O, U, Q);
        X.compose(1, L, O, W, magicjs.base64.decode(P));
        return magicjs.base64.encode(X.toDer())
    }

    function z(N) {
        tbhdata = magicjs.utf8.encode(N);
        var L = d(tbhdata);
        return String.fromCharCode.apply(null, L)
    }

    function d(S) {
        var N, R, L = [],
            P = 0;
        for (var Q = 0; Q < S.length; Q++) {
            N = S.charCodeAt(Q);
            if (N < 127) {
                L[P++] = N & 255
            } else {
                R = [];
                do {
                    R.push(N & 255);
                    N = N >> 8
                } while (N);
                R = R.reverse();
                for (var O = 0; O < R.length; ++O) {
                    L[P++] = R[O]
                }
            }
        }
        return L
    }
    return {
        init: H,
        base64encode: w,
        base64decode: p,
        genHmac: t,
        verifyHmac: r,
        encrypt: J,
        decrypt: m,
        sign: l,
        autoSign: v,
        envelopedData: c,
        signedEnvelopedData: C,
        verifyVID: I,
        getVIDRandom: g,
        getVIDRandomHash: a,
        generateRandom: A,
        genKeypair: u,
        genHash: K,
        genHashCount: j,
        prikeyDecrypt: E,
        prikeyEncrypt: o,
        getVIDRandom: g,
        asymEncrypt: f,
        asymDecrypt: x,
        pfxImport: y,
        pfxImport_withOption: B,
        pfxExport: q,
        pfxChangePwExport: h,
        getcertInfo: k,
        prikeyChangePassword: n,
        certChangePassword: b,
        signature: s,
        signedAttributes: e,
        pkcs7: D
    }
});
var Resource_API = (function(d, t) {
    var q;
    var e = null;
    var a = d;

    function p(u, v) {
        ML4WebLog.log("Resource_API init() called...");
        this.csFlag = t;
        if (this.csFlag && e == null) {
            v(0, {
                msg: "csFlag true."
            })
        } else {
            v(0, {
                msg: "csFlag false."
            })
        }
    }

    function f(v, u, w) {
        ML4WebLog.log("Resource_API.callLocalServerAPI() called...");
        if (e == null) {
            e = ML4WebApi.getCsManager()
        }
        k(v, true, u, w)
    }

    function m(u, v) {
        k(u, true, {}, v)
    }

    function n() {
        return this.csFlag
    }

    function k(v, w, A, u) {
        try {
            var z;
            if (z == null) {
                try {
                    z = new XMLHttpRequest();
                    z.open("POST", v, w);
                    z.setRequestHeader("Content-Type", "application/x-www-form-urlencoded;text/html;utf-8");
                    z.send(A)
                } catch (y) {
                    try {
                        z = new ActiveXObject("Microsoft.XMLHTTP");
                        z.open("POST", v, w);
                        z.setRequestHeader("Content-Type", "application/x-www-form-urlencoded;text/html;utf-8");
                        z.send(A)
                    } catch (y) {
                        z = new ActiveXObject("Msxml2.XMLHTTP");
                        z.open("POST", v, w);
                        z.setRequestHeader("Content-Type", "application/x-www-form-urlencoded;text/html;utf-8");
                        z.send(A)
                    }
                }
            }
            var x = w || false;
            if (x) {
                z.onreadystatechange = function() {
                    if (z.readyState == 4) {
                        if (z.status == 200) {
                            u(0, z.responseText)
                        } else {
                            u(z.status, z.statusText)
                        }
                    }
                }
            } else {
                if (typeof(u) == "function") {
                    if (z.readyState == 4) {
                        if (z.status == 200) {
                            u(0, z.responseText)
                        } else {
                            u(z.readyState, z.statusText)
                        }
                    }
                }
            }
        } catch (y) {
            u(ML4WebLog.getErrCode("Resource_API_httpRequest"), {
                errCode: y.code,
                errMsg: y.message
            })
        }
    }

    function s(w) {
        var v = "";
        var u = arguments.length - 1;
        if (u < 0) {
            return
        }
        v += "{";
        v += '"Version":"' + a.Version + '",';
        v += '"ServiceID":"' + a.ServiceID + '",';
        v += '"AuthKey":"' + ConfigObject.MAGICJS_LIC + '",';
        if (a.SessionID == null || a.SessionID == "") {
            v += '"SessionID":"' + ML4WebApi.getProperty("SessionID") + '",'
        } else {
            v += '"SessionID":"' + a.SessionID + '",'
        }
        v += '"CrossServerURL":"' + a.CrossServerURL + '",';
        v += '"CrossServerCert":"' + a.CrossServerCert + '",';
        v += '"SessionTimeout":"' + a.SessionTimeout + '",';
        if (u == 0) {
            v += '"MessageID":"' + w + '"'
        } else {
            v += '"MessageID":"' + w + '",'
        }
        for (i = 0; i < u; i++) {
            if (i + 1 == (u)) {
                v += '"' + i + '":"' + arguments[i + 1] + '"'
            } else {
                v += '"' + i + '":"' + arguments[i + 1] + '",'
            }
        }
        v += "}";
        return v
    }

    function g(w) {
        var v = "";
        var u = arguments.length - 1;
        if (u < 0) {
            return
        }
        v += "{";
        v += '"Version":"' + a.Version + '",';
        v += '"ServiceID":"' + a.CsServiceID + '",';
        v += '"SessionTimeout":"' + a.SessionTimeout + '",';
        v += '"AuthKey":"' + ConfigObject.MAGICJS_LIC + '",';
        if (a.SessionID == null || a.SessionID == "") {
            v += '"SessionID":"' + ML4WebApi.getProperty("SessionID") + '",'
        } else {
            v += '"SessionID":"' + a.SessionID + '",'
        }
        if (u === 0) {
            v += '"MessageID":"' + w + '"'
        } else {
            v += '"MessageID":"' + w + '",'
        }
        for (i = 0; i < u; i++) {
            if (i + 1 == (u)) {
                v += '"' + i + '":"' + arguments[i + 1] + '"'
            } else {
                v += '"' + i + '":"' + arguments[i + 1] + '",'
            }
        }
        v += "}";
        return v
    }

    function r(v, x, A, u) {
        try {
            var z = new XMLHttpRequest();
            var w = !x;
            z.open("POST", v, w);
            z.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            z.send(A);
            if (x === false) {
                z.onreadystatechange = function() {
                    if (z.readyState == 4) {
                        if (z.status == 200) {
                            u(z.responseText, 0)
                        } else {
                            u(z.statusText, z.status)
                        }
                    }
                }
            } else {
                if (x === true) {
                    if (z.readyState == 4) {
                        if (z.status == 200) {
                            return z.responseText
                        } else {
                            ML4WebLog.log("ML4WebAjaxError", "AJAX Failed : [ xmlHttpRequest.statusText ][ " + z.statusText + " ][xmlHttpRequest.readyState][ " + z.readyState + " ]")
                        }
                    } else {
                        ML4WebLog.log("ML4WebAjaxError", "AJAX Failed : [ xmlHttpRequest.statusText ][ " + z.statusText + " ][xmlHttpRequest.readyState][ " + z.readyState + " ]")
                    }
                }
            }
        } catch (y) {
            u(ML4WebLog.getErrCode("Resource_API_httpRequest"), {
                errCode: y.code,
                errMsg: y.message
            })
        }
    }

    function o(u, v, x) {
        try {
            r(u, false, v, function(z, y) {
                try {
                    if (y === 0) {
                        var B = JSON.parse(z);
                        x(B)
                    } else {
                        x({
                            ResultCode: y,
                            ResultMessage: z
                        })
                    }
                } catch (A) {
                    ML4WebLog.log(JSON.parse(v).MessageID + " : [ " + A.name + " ][ " + A.code + " ]");
                    x({
                        ResultCode: A.code,
                        ResultMessage: A.name
                    })
                }
            })
        } catch (w) {
            ML4WebLog.log(JSON.parse(v).MessageID + ":  [ " + w.message + " ][" + w.code + " ]");
            x({
                ResultCode: w.code,
                ResultMessage: w.message
            })
        }
    }

    function b(x) {
        var w = "";
        var u = 0;
        var v = "";
        w += "{";
        for (u = 0; u < x.length; u++) {
            v = x[u].split("&&");
            w += '"' + v[0] + '":"' + v[1] + '"'
        }
        w += "}";
        return w
    }
    var h = function(u) {
        var v = u.getByte();
        if (v === 128) {
            return undefined
        }
        var x;
        var w = v & 128;
        if (!w) {
            x = v
        } else {
            x = u.getInt((v & 127) << 3)
        }
        return x
    };
    var l = function(u, v) {
        if (v.length() < 2) {
            throw new Error("Too few bytes to parse DER.")
        }
        if (v.getByte() != u) {
            throw new Error("Invalid format.")
        }
        var w = h(v);
        return v.getBytes(w)
    };

    function c(v) {
        try {
            var w = v;
            var A = magicjs.base64.decode(w);
            var C = magicjs.ByteStringBuffer.create(A);
            l(48, C);
            var B = A.slice(0, C.read);
            B = magicjs.base64.encode(B);
            var x = magicjs.utf8.decode(l(12, C));
            var y = dreamsecurity.asn1.utcTimeToDate(l(23, C));
            var u = l(4, C);
            return {
                signedData: B,
                pdf: u
            }
        } catch (z) {
            return {
                code: ML4WebLog.getErrCode("Resource_API_getSignedDataAndPdf"),
                msg: {
                    errCode: z.code,
                    errMsg: z.message
                }
            }
        }
    }

    function j(u, v, z) {
        try {
            var y;
            if (y == null) {
                try {
                    y = new XMLHttpRequest();
                    y.open("POST", u, v);
                    y.setRequestHeader("Content-Type", "application/x-www-form-urlencoded;text/html;utf-8");
                    y.send(z)
                } catch (x) {
                    try {
                        y = new ActiveXObject("Msxml2.HTTP");
                        y.open("POST", u, v);
                        y.setRequestHeader("Content-Type", "application/x-www-form-urlencoded;text/html;utf-8");
                        y.send(z)
                    } catch (x) {
                        y = new ActiveXObject("Microsoft.XMLHTTP");
                        y.open("POST", u, v);
                        y.setRequestHeader("Content-Type", "application/x-www-form-urlencoded;text/html;utf-8");
                        y.send(z)
                    }
                }
            }
            var w = v || false;
            if (w) {
                y.onreadystatechange = function() {
                    if (y.readyState == 4) {
                        if (y.status == 200) {
                            callbackFunction(0, y.responseText)
                        } else {
                            callbackFunction(y.status, y.statusText)
                        }
                    }
                }
            } else {
                if (y.readyState == 4) {
                    if (y.status == 200) {
                        return y.responseText
                    } else {
                        return {
                            code: "888",
                            data: " AJAX Failed : [ xmlHttpRequest.statusText ][ " + y.statusText + " ][xmlHttpRequest.readyState][ " + y.readyState + " ]"
                        }
                    }
                } else {
                    return {
                        code: "888",
                        data: " AJAX Failed : [ xmlHttpRequest.statusText ][ " + y.statusText + " ][xmlHttpRequest.readyState][ " + y.readyState + " ]"
                    }
                }
            }
        } catch (x) {
            return {
                code: ML4WebLog.getErrCode("Resource_API_csRequest"),
                data: {
                    errCode: x.code,
                    errMsg: x.message
                }
            }
        }
    }
    return {
        init: p,
        callLocalServerAPI: f,
        loadJSLibrary: m,
        checkCS: n,
        httpRequest: k,
        makeJsonMessage: s,
        makeIrosJson: b,
        irosRequset: j,
        getSignedDataAndPdf: c,
        makeCsJsonMessage: g,
        csRequest: r,
        csAsyncCall: o
    }
});
var Storage_API = (function() {
    function r(w) {
        ML4WebLog.log("Storage_API.init() called...");
        Storage_API_filter.init(function(x, y) {
            w(x, y)
        })
    }

    function c(w, x) {}

    function t(w) {}

    function h(w, z) {
        ML4WebLog.log("Storage_API.SelectStorageInfo() called...");
        if (w == null || w == "") {
            z(ML4WebLog.getErrCode("Storage_API_SelectStorageInfo"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof z != "function" || z == null || z == "") {
                z(ML4WebLog.getErrCode("Storage_API_SelectStorageInfo"), {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            }
        }
        try {
            var x = window["Storage_API_" + w]["SelectStorageInfo"];
            x(w, z)
        } catch (y) {
            z(ML4WebLog.getErrCode("Storage_API_SelectStorageInfo"), {
                errCode: 888,
                errMsg: y.message
            })
        }
    }

    function o(y, z) {
        ML4WebLog.log("Storage_API.GetCertList() called...");
        if (y == null || $.isEmptyObject(y)) {
            z(ML4WebLog.getErrCode("Storage_API_GetCertList"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof z != "function" || z == null || z == "") {
                z(ML4WebLog.getErrCode("Storage_API_GetCertList"), {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            }
        }
        try {
            var w = window["Storage_API_" + y.storageName]["GetCertList"];
            w(y, function(B, C) {
                if (B == 0) {
                    if (C.cert_list != null && C.cert_list.length > 0) {
                        for (var A = 0; A < C.cert_list.length; A++) {
                            if (typeof(C.cert_list[A].certpath) != "undefined") {
                                C.cert_list[A].certpath = magicjs.utf8.decode(magicjs.base64.decode(C.cert_list[A].certpath)).replace(/\\\\/, "\\")
                            }
                        }
                        Storage_API_filter.selectfilteredCertList(C.cert_list, function(D, E) {
                            if (D == 0) {
                                C.cert_list = E.filtered_list
                            } else {
                                C.cert_list = null
                            }
                        })
                    }
                    z(B, C)
                } else {
                    z(B, C)
                }
            })
        } catch (x) {
            z(ML4WebLog.getErrCode("Storage_API_GetCertList"), {
                errCode: 888,
                errMsg: x.message
            })
        }
    }

    function l(z, A) {
        ML4WebLog.log("Storage_API.GetCertString() called...");
        if (z == null || $.isEmptyObject(z)) {
            A(ML4WebLog.getErrCode("Storage_API_GetCertString"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof A != "function" || A == null || A == "") {
                A(ML4WebLog.getErrCode("Storage_API_GetCertString"), {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            }
        }
        var w = z.storageName;
        try {
            var x = window["Storage_API_" + w]["GetCertString"];
            x(z, A)
        } catch (y) {
            A(ML4WebLog.getErrCode("Storage_API_GetCertString"), {
                errCode: 888,
                errMsg: y.message
            })
        }
    }

    function u(B, w, C) {
        if (B == null || B == "") {
            C(ML4WebLog.getErrCode("Storage_API_GetDetailCert"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof C != "function" || C == null || C == "") {
                C(ML4WebLog.getErrCode("Storage_API_GetDetailCert"), {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            } else {}
        }
        var A = [];
        if (typeof(w) == "undefined" || w == null || w.length <= 0) {
            A.push(DS_CERT_INFO.VERSION);
            A.push(DS_CERT_INFO.SERIALNUM);
            A.push(DS_CERT_INFO.SIGNATUREALGORITHM);
            A.push(DS_CERT_INFO.ISSUERNAME);
            A.push(DS_CERT_INFO.STARTDATE);
            A.push(DS_CERT_INFO.ENDDATE);
            A.push(DS_CERT_INFO.STARTDATETIME);
            A.push(DS_CERT_INFO.ENDDATETIME);
            A.push(DS_CERT_INFO.SUBJECTNAME);
            A.push(DS_CERT_INFO.PUBKEY);
            A.push(DS_CERT_INFO.PUBKEYALGORITHM);
            A.push(DS_CERT_INFO.KEYUSAGE);
            A.push(DS_CERT_INFO.CERTPOLICY);
            A.push(DS_CERT_INFO.POLICYID);
            A.push(DS_CERT_INFO.POLICYNOTICE);
            A.push(DS_CERT_INFO.SUBJECTALTNAME);
            A.push(DS_CERT_INFO.AUTHKEYID);
            A.push(DS_CERT_INFO.SUBKEYID);
            A.push(DS_CERT_INFO.CRLDP);
            A.push(DS_CERT_INFO.AIA);
            A.push(DS_CERT_INFO.REALNAME)
        } else {
            A = w
        }
        var x = B.storageName;
        ML4WebLog.log("Storage_API.GetDetailCert() called...");
        try {
            var y = window["Storage_API_" + x]["GetDetailCert"];
            y(B, A, C)
        } catch (z) {
            C(ML4WebLog.getErrCode("Storage_API_GetDetailCert"), {
                errCode: 888,
                errMsg: z.message
            })
        }
    }

    function p(y, w, A, B) {
        if (y == null || $.isEmptyObject(y)) {
            B(ML4WebLog.getErrCode("Storage_API_SaveCert"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (w == null || w == "") {
                B(ML4WebLog.getErrCode("Storage_API_SaveCert"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (typeof B != "function" || B == null || B == "") {
                    B(ML4WebLog.getErrCode("Storage_API_SaveCert"), {
                        errCode: 103,
                        errMsg: $.i18n.prop("ER103")
                    });
                    return
                }
            }
        }
        try {
            var x = window["Storage_API_" + A.storageName]["SaveCert"];
            x(y, w, A, B)
        } catch (z) {
            B(ML4WebLog.getErrCode("Storage_API_SaveCert"), {
                errCode: 888,
                errMsg: z.message
            })
        }
    }

    function a(z, A) {
        if (z == null || $.isEmptyObject(z)) {
            A(ML4WebLog.getErrCode("Storage_API_DeleteCert"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof A != "function" || A == null || A == "") {
                A(ML4WebLog.getErrCode("Storage_API_DeleteCert"), {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            }
        }
        var w = z.storageName;
        try {
            var x = window["Storage_API_" + w]["DeleteCert"];
            x(z, A)
        } catch (y) {
            A(ML4WebLog.getErrCode("Storage_API_DeleteCert"), {
                errCode: 888,
                errMsg: y.message
            })
        }
    }

    function m(A, w, B) {
        if (A == null || $.isEmptyObject(A)) {
            B(ML4WebLog.getErrCode("Storage_API_DeleteCert_Token"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof B != "function" || B == null || B == "") {
                B(ML4WebLog.getErrCode("Storage_API_DeleteCert_Token"), {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            }
        }
        var x = A.storageName;
        try {
            var y = window["Storage_API_" + x]["DeleteCert_Token"];
            y(A, w, B)
        } catch (z) {
            B(ML4WebLog.getErrCode("Storage_API_DeleteCert_Token"), {
                errCode: 888,
                errMsg: z.message
            })
        }
    }

    function f(B, x, w, C) {
        if (B == null || $.isEmptyObject(B)) {
            C(ML4WebLog.getErrCode("Storage_API_ChangePassword"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (x == null || x == "") {
                C(ML4WebLog.getErrCode("Storage_API_ChangePassword"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (w == null || w == "") {
                    C(ML4WebLog.getErrCode("Storage_API_ChangePassword"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof C != "function" || C == null || C == "") {
                        C(ML4WebLog.getErrCode("Storage_API_ChangePassword"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
        }
        var y = B.storageName;
        try {
            var z = window["Storage_API_" + y]["ChangePassword"];
            z(B, x, w, C)
        } catch (A) {
            C(ML4WebLog.getErrCode("Storage_API_ChangePassword"), {
                errCode: 888,
                errMsg: A.message
            })
        }
    }

    function b(B, w, z, C) {
        if (B == null || $.isEmptyObject(B)) {
            C(ML4WebLog.getErrCode("Storage_API_verifyVID"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (w == null || w == "") {
                C(ML4WebLog.getErrCode("Storage_API_verifyVID"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (z == null || z == "") {
                    C(ML4WebLog.getErrCode("Storage_API_verifyVID"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof C != "function" || C == null || C == "") {
                        C(ML4WebLog.getErrCode("Storage_API_verifyVID"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
        }
        var x = B.storageName;
        try {
            var y = window["Storage_API_" + x]["verifyVID"];
            y(B, w, z, C)
        } catch (A) {
            C(ML4WebLog.getErrCode("Storage_API_verifyVID"), {
                errCode: 888,
                errMsg: A.message
            })
        }
    }

    function j(A, w, B) {
        if (A == null || $.isEmptyObject(A)) {
            B(ML4WebLog.getErrCode("Storage_API_getVIDRandom"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (w == null || w == "") {
                B(ML4WebLog.getErrCode("Storage_API_getVIDRandom"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (typeof B != "function" || B == null || B == "") {
                    B(ML4WebLog.getErrCode("Storage_API_getVIDRandom"), {
                        errCode: 103,
                        errMsg: $.i18n.prop("ER103")
                    });
                    return
                }
            }
        }
        var x = A.storageName;
        try {
            var y = window["Storage_API_" + x]["getVIDRandom"];
            y(A, w, B)
        } catch (z) {
            B(ML4WebLog.getErrCode("Storage_API_getVIDRandom"), {
                errCode: 888,
                errMsg: z.message
            })
        }
    }

    function s(B, w, z, C) {
        if (B == null || $.isEmptyObject(B)) {
            C(ML4WebLog.getErrCode("Storage_API_getVIDRandomHash"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (w == null || w == "") {
                C(ML4WebLog.getErrCode("Storage_API_getVIDRandomHash"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (z == null || z == "") {
                    C(ML4WebLog.getErrCode("Storage_API_getVIDRandomHash"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof C != "function" || C == null || C == "") {
                        C(ML4WebLog.getErrCode("Storage_API_getVIDRandomHash"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
        }
        var x = B.storageName;
        try {
            var y = window["Storage_API_" + x]["getVIDRandomHash"];
            y(B, w, z, C)
        } catch (A) {
            C(ML4WebLog.getErrCode("Storage_API_getVIDRandomHash"), {
                errCode: 888,
                errMsg: A.message
            })
        }
    }

    function e(C, y, w, B, D) {
        if (C == null || $.isEmptyObject(C)) {
            D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (y == null || $.isEmptyObject(y)) {
                D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (typeof D != "function" || D == null || D == "") {
                    D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                        errCode: 103,
                        errMsg: $.i18n.prop("ER103")
                    });
                    return
                } else {
                    if (C.storageName == "smartcert") {
                        w = "11111"
                    } else {
                        if (w == null || w == "") {
                            D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        }
                    }
                }
            }
        }
        var x = C.storageName;
        try {
            var z = window["Storage_API_" + x]["Sign"];
            z(C, y, w, B, D)
        } catch (A) {
            D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                errCode: 888,
                errMsg: A.message
            })
        }
    }

    function q(C, y, w, B, D) {
        if (C == null || $.isEmptyObject(C)) {
            D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (y == null || $.isEmptyObject(y)) {
                D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (typeof D != "function" || D == null || D == "") {
                    D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                        errCode: 103,
                        errMsg: $.i18n.prop("ER103")
                    });
                    return
                } else {
                    if (C.storageName == "smartcert") {
                        w = "11111"
                    } else {
                        if (w == null || w == "") {
                            D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        }
                    }
                }
            }
        }
        var x = C.storageName;
        try {
            var z = window["Storage_API_" + x]["Signature"];
            z(C, y, w, B, D)
        } catch (A) {
            D(ML4WebLog.getErrCode("Storage_API_Sign"), {
                errCode: 888,
                errMsg: A.message
            })
        }
    }

    function d(B, z, A, w, x, D) {
        if (B == null || $.isEmptyObject(B)) {
            D(ML4WebLog.getErrCode("Storage_API_SingedEnvelopedData"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (z == null || z == "") {
                D(ML4WebLog.getErrCode("Storage_API_SingedEnvelopedData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (A == null || $.isEmptyObject(A)) {
                    D(ML4WebLog.getErrCode("Storage_API_SingedEnvelopedData"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (w == null || w == "") {
                        D(ML4WebLog.getErrCode("Storage_API_SingedEnvelopedData"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (x == null || x == "") {
                            D(ML4WebLog.getErrCode("Storage_API_SingedEnvelopedData"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        } else {
                            if (typeof D != "function" || D == null || D == "") {
                                D(ML4WebLog.getErrCode("Storage_API_SingedEnvelopedData"), {
                                    errCode: 103,
                                    errMsg: $.i18n.prop("ER103")
                                });
                                return
                            }
                        }
                    }
                }
            }
        }
        var E = B.storageName;
        try {
            var y = window["Storage_API_" + E]["SingedEnvelopedData"];
            y(B, z, A, w, x, D)
        } catch (C) {
            D(ML4WebLog.getErrCode("Storage_API_SingedEnvelopedData"), {
                errCode: 888,
                errMsg: C.message
            })
        }
    }

    function g(C, y, w, B, D) {
        if (C == null || $.isEmptyObject(C)) {
            D(ML4WebLog.getErrCode("Storage_API_IrosSign"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (y == null || $.isEmptyObject(y)) {
                D(ML4WebLog.getErrCode("Storage_API_IrosSign"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (B == null || B == "") {
                    D(ML4WebLog.getErrCode("Storage_API_IrosSign"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof D != "function" || D == null || D == "") {
                        D(ML4WebLog.getErrCode("Storage_API_IrosSign"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    } else {
                        if (C.storageName == "smartcert") {
                            w = "11111"
                        } else {
                            if (w == null || w == "") {
                                D(ML4WebLog.getErrCode("Storage_API_IrosSign"), {
                                    errCode: 100,
                                    errMsg: $.i18n.prop("ER100")
                                });
                                return
                            }
                        }
                    }
                }
            }
        }
        var x = C.storageName;
        try {
            var z = window["Storage_API_" + x]["IrosSign"];
            z(C, y, w, B, D)
        } catch (A) {
            D(ML4WebLog.getErrCode("Storage_API_IrosSign"), {
                errCode: 888,
                errMsg: A.message
            })
        }
    }

    function n(C, y, w, B, D) {
        if (C == null || $.isEmptyObject(C)) {
            D(ML4WebLog.getErrCode("Storage_API_IrosAddSignData"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (y == null || $.isEmptyObject(y)) {
                D(ML4WebLog.getErrCode("Storage_API_IrosAddSignData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (B == null || B == "") {
                    D(ML4WebLog.getErrCode("Storage_API_IrosAddSignData"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof D != "function" || D == null || D == "") {
                        D(ML4WebLog.getErrCode("Storage_API_IrosAddSignData"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    } else {
                        if (C.storageName == "smartcert") {
                            w = "11111"
                        } else {
                            if (w == null || w == "") {
                                D(ML4WebLog.getErrCode("Storage_API_IrosAddSignData"), {
                                    errCode: 100,
                                    errMsg: $.i18n.prop("ER100")
                                });
                                return
                            }
                        }
                    }
                }
            }
        }
        var x = C.storageName;
        try {
            var z = window["Storage_API_" + x]["IrosAddSignData"];
            z(C, y, w, B, D)
        } catch (A) {
            D(ML4WebLog.getErrCode("Storage_API_IrosAddSignData"), {
                errCode: 888,
                errMsg: A.message
            })
        }
    }

    function k(C, y, w, B) {
        if (C == null || $.isEmptyObject(C)) {
            return {
                code: ML4WebLog.getErrCode("Storage_API_IrosMultiSign"),
                data: {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                }
            }
        } else {
            if (y == null || $.isEmptyObject(y)) {
                return {
                    code: ML4WebLog.getErrCode("Storage_API_IrosMultiSign"),
                    data: {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    }
                }
            } else {
                if (B == null || B == "") {
                    return {
                        code: ML4WebLog.getErrCode("Storage_API_IrosMultiSign"),
                        data: {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        }
                    }
                } else {
                    if (C.storageName == "smartcert") {
                        w = "11111"
                    } else {
                        if (w == null || w == "") {
                            return {
                                code: ML4WebLog.getErrCode("Storage_API_IrosMultiSign"),
                                data: {
                                    errCode: 100,
                                    errMsg: $.i18n.prop("ER100")
                                }
                            }
                        }
                    }
                }
            }
        }
        var x = C.storageName;
        try {
            var z = window["Storage_API_" + x]["IrosMultiSign"];
            return z(C, y, w, B)
        } catch (A) {
            return {
                code: ML4WebLog.getErrCode("Storage_API_IrosMultiSign"),
                data: {
                    errCode: 888,
                    errMsg: A.message
                }
            }
        }
    }

    function v(C, y, w, B) {
        if (C == null || $.isEmptyObject(C)) {
            return {
                code: ML4WebLog.getErrCode("Storage_API_IrosMultiAddSign"),
                data: {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                }
            }
        } else {
            if (y == null || $.isEmptyObject(y)) {
                return {
                    code: ML4WebLog.getErrCode("Storage_API_IrosMultiAddSign"),
                    data: {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    }
                }
            } else {
                if (B == null || B == "") {
                    return {
                        code: ML4WebLog.getErrCode("Storage_API_IrosMultiAddSign"),
                        data: {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        }
                    }
                } else {
                    if (C.storageName == "smartcert") {
                        w = "11111"
                    } else {
                        if (w == null || w == "") {
                            return {
                                code: ML4WebLog.getErrCode("Storage_API_IrosMultiAddSign"),
                                data: {
                                    errCode: 100,
                                    errMsg: $.i18n.prop("ER100")
                                }
                            }
                        }
                    }
                }
            }
        }
        var x = C.storageName;
        try {
            var z = window["Storage_API_" + x]["IrosMultiAddSign"];
            return z(C, y, w, B)
        } catch (A) {
            return {
                code: ML4WebLog.getErrCode("Storage_API_IrosMultiAddSign"),
                data: {
                    errCode: 888,
                    errMsg: A.message
                }
            }
        }
    }
    return {
        init: r,
        SetProperty: c,
        GetProperty: t,
        SelectStorageInfo: h,
        GetCertList: o,
        GetCertString: l,
        GetDetailCert: u,
        SaveCert: p,
        DeleteCert: a,
        DeleteCert_Token: m,
        ChangePassword: f,
        verifyVID: b,
        getVIDRandom: j,
        getVIDRandomHash: s,
        Sign: e,
        Signature: q,
        SingedEnvelopedData: d,
        IrosSign: g,
        IrosAddSignData: n,
        IrosMultiSign: k,
        IrosMultiAddSign: v
    }
});

function completeFunc(j, f, e) {
    var h = ML4WebApi.getCryptoApi();
    var d = JSON.parse(f);
    var k = j.option.ds_pki_sign_type;
    if (typeof(d.returnObj.returnCode) != "undefined" && d.returnObj.returnCode != "") {
        if (d.returnObj.returnCode === "E1000") {
            e(d.returnObj.returnCode, d.returnObj.returnMsg)
        }
    }
    if (typeof d.signResult.b64SignedData != "undefined" && d.signResult.b64SignedData != "") {
        var b = d.signResult.b64SignedData;
        var u = d.signResult.b64Signer;
        var a = d.signResult.R;
        var t = "";
        var g = new Object();
        g.userCert = u;
        if (k == "signeddata") {
            var n = b;
            var s = u;
            var m = j.msgType;
            var l = j.plainText;
            if (j.signTime.indexOf("T") < 0) {
                j.signTime = j.signTime.replace(" ", "T")
            }
            var p = j.signTime;
            var q = 0;
            var c = new Array();
            var o = new Array();
            if (n instanceof Array) {
                if (typeof(j.option.ds_msg_decode) != "undefined" && j.option.ds_msg_decode == "true") {
                    q = 1
                }
                for (var r = 0; r < n.length; r++) {
                    c = new Object();
                    if (l instanceof Array) {
                        c[r] = h.pkcs7(s, m, l[r], n[r], p, j.option.ds_pki_sign, q)
                    } else {
                        c[r] = h.pkcs7(s, m, l, n[r], p, j.option.ds_pki_sign, q)
                    }
                    o.push(c[r])
                }
            }
            if (l instanceof Array) {
                g.encMsg = o
            } else {
                g.encMsg = o[0]
            }
        } else {
            g.encMsg = b
        }
        h.getcertInfo(u, [], function(v, w) {
            if (v == 0) {
                g.certbag = {};
                g.certbag.signcert = u;
                g.certInfo = w.result;
                ML4WebApi.webConfig.getRandomfromPrivateKey = a[0];
                g.randonNum = a[0];
                g.serialnum = g.certInfo.serialnum;
                g.subjectname = g.certInfo.subjectname;
                e(v, g)
            } else {
                e(ML4WebLog.getErrCode("Storage_smartcertnx_Sign"), {
                    errCode: w.errCode,
                    errMsg: w.errMsg
                })
            }
        })
    }
}

function encodeUtf8Hex(a) {
    return unescape(encodeURIComponent(a))
}

function encodeUtf8andBase64(d) {
    var h = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    var a = "";
    var c = "";
    var g, e, b;
    var f = 0;
    d = unescape(encodeURIComponent(d));
    maxline = (d.length + 2 - ((d.length + 2) % 3)) / 3 * 4;
    while (f < d.length) {
        g = d.charCodeAt(f++);
        e = d.charCodeAt(f++);
        b = d.charCodeAt(f++);
        a += h.charAt(g >> 2);
        a += h.charAt(((g & 3) << 4) | (e >> 4));
        if (isNaN(e)) {
            a += "=="
        } else {
            a += h.charAt(((e & 15) << 2) | (b >> 6));
            a += isNaN(b) ? "=" : h.charAt(b & 63)
        }
        if (maxline && a.length > maxline) {
            c += a.substr(0, maxline) + "\r\n";
            a = a.substr(maxline)
        }
    }
    c += a;
    return c
}
var Storage_API_web = {
    selectCertString: "",
    selectCertIdx: "",
    getML4WebCert: function() {
        var b = {};
        var c = "[]";
        var d = ML4WebApi.getCryptoApi();
        if (typeof(localStorage) != "undefined") {
            var a = localStorage.getItem("ML4WebCert");
            if (a != null && typeof(a) != "undefined" && typeof(a) == "string") {
                a = d.getDecryptedCert(a);
                a = JSON.parse(a)
            }
            if (a != null && typeof(a) != "undefined" && typeof(a) == "object") {
                if (typeof(a.ver) != "undefined" && a.ver == "v1") {
                    c = a.certBaglist
                }
            }
        }
        return c
    },
    setML4WebCert: function(c) {
        var b = {};
        var a = [];
        var d = ML4WebApi.getCryptoApi();
        b.ver = "v1";
        b.time = new Date().getTime();
        b.certBaglist = a;
        if (c != null && typeof(c) != "undefined" && typeof(c) == "string") {
            b.certBaglist = c;
            a = d.getEncryptedCert(JSON.stringify(b))
        }
        if (typeof(localStorage) != "undefined") {
            localStorage.setItem("ML4WebCert", a)
        }
    },
    delML4WebCert: function() {
        if (typeof(localStorage) != "undefined") {
            localStorage.removeItem("ML4WebCert")
        }
    },
    getSelectCert: function(f) {
        ML4WebLog.log("Storage_API_web.getSelectCert() called...");
        var c = {
            code: 0,
            signcert: "",
            signpri: "",
            message: ""
        };
        try {
            if (Storage_API_web.selectCertString.length != 0 && Storage_API_web.selectCertString.storageCertIdx == f.storageCertIdx) {
                c.signcert = Storage_API_web.selectCertString.signcert;
                c.signpri = Storage_API_web.selectCertString.signpri
            } else {
                var a = Storage_API_web.getML4WebCert();
                var j = false;
                if (a != null) {
                    var b = JSON.parse(a);
                    var k = {};
                    var h = b.length;
                    for (var d = 0; d < h; d++) {
                        if (b[d].storageCertIdx == f.storageCertIdx) {
                            k = b[d];
                            j = true
                        }
                    }
                    if (j) {
                        c.signcert = k.signcert;
                        c.signpri = k.signpri
                    } else {
                        if (typeof(f.browserSaveYn) != "undefined") {
                            c.signcert = f.signcert;
                            c.signpri = f.signpri
                        } else {
                            if (f.browserSaveYn === true) {}
                        }
                    }
                } else {
                    c.signcert = f.signcert;
                    c.signpri = f.signpri
                }
            }
            return c
        } catch (g) {
            c.code = ML4WebLog.getErrCode("Storage_Web_getSelectCert");
            c.message = "certBaglist error message : " + g.message;
            return c
        }
    },
    SelectStorageInfo: function(a, c) {
        ML4WebLog.log("Storage_API_web.SelectStorageInfo() called...");
        var b = {};
        if (true) {
            c(0, b)
        } else {
            c(ML4WebLog.getErrCode("Storage_Web_SelectStorageInfo"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    GetCertList: function(j, g) {
        ML4WebLog.log("Storage_API_web.GetCertList() called...");
        var d = [];
        var l = Storage_API_web.getML4WebCert();
        var h = l != null ? JSON.parse(l) : [];
        if (l != null && h.length > 0) {
            var k = JSON.parse(l);
            if (typeof(k) == null || k == null) {
                g(ML4WebLog.getErrCode("Storage_Web_GetCertList"), {
                    errCode: 202,
                    errMsg: $.i18n.prop("ER202")
                })
            } else {
                var f = ML4WebApi.getCryptoApi();
                var e = k.length;
                for (var c = 0; c < e; c++) {
                    Storage_API_web.selectCertString = k[c];
                    var b = k[c].signcert;
                    var a = [];
                    f.getcertInfo(b, a, function(o, n) {
                        if (o == "0") {
                            if (ML4WebApi.getProperty("libType") == 0) {
                                n.result = n
                            }
                            var m = {
                                storageName: "web",
                                storageOpt: {}
                            };
                            m.storageCertIdx = n.result.subkeyid;
                            Storage_API_web.selectCertIdx = n.result.subkeyid;
                            n.result.storageRawCertIdx = m;
                            d[c] = n.result;
                            if (e == d.length) {
                                g(0, {
                                    cert_list: d
                                })
                            }
                        } else {
                            g(ML4WebLog.getErrCode("Storage_Web_GetCertList"), {
                                errCode: o,
                                errMsg: n
                            })
                        }
                    })
                }
            }
        } else {
            ML4WebLog.log("Storage_API_web.GetCertList() ML4WebCert null...");
            g(0, {
                cert_list: []
            })
        }
    },
    GetCertString: function(e, j) {
        ML4WebLog.log("Storage_API_web.GetCertString() called...");
        var a = "";
        var b = Storage_API_web.getML4WebCert();
        if (typeof(b) == null || b == null) {
            j(ML4WebLog.getErrCode("Storage_Web_GetCertString"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        } else {
            ML4WebLog.log("Storage_API_web.GetCertString certbag Text =" + b);
            var c = JSON.parse(b);
            ML4WebLog.log("Storage_API_web.GetCertString localStorageNum =" + c.length);
            ML4WebLog.log("Storage_API_web.GetCertString parameter =" + e.storageCertIdx + " " + c.storageCertIdx);
            var g = {};
            var f = c.length;
            for (var d = 0; d < f; d++) {
                ML4WebLog.log("Storage_API_web.GetCertString=" + c[d].storageCertIdx);
                if (c[d].storageCertIdx == e.storageCertIdx) {
                    g = c[d];
                    break
                }
            }
            var h = false;
            if (typeof(g.signcert) != null) {
                delete g.storageCertIdx;
                h = true
            }
            if (h) {
                j(0, {
                    cert: g
                })
            } else {
                j(ML4WebLog.getErrCode("Storage_Web_GetCertString"), {
                    errCode: 201,
                    errMsg: $.i18n.prop("ER201")
                })
            }
        }
    },
    GetDetailCert: function(g, f, l) {
        ML4WebLog.log("Storage_API_web.GetDetailCert() called... fields.length = " + f.length);
        var a = "";
        var b = Storage_API_web.getML4WebCert();
        var c = JSON.parse(b);
        var j = {};
        var k = ML4WebApi.getCryptoApi();
        var e = null;
        var h = c.length;
        if (c != null && c.length > 0) {
            for (var d = 0; d < h; d++) {
                if (c[d].storageCertIdx == g.storageCertIdx) {
                    j = c[d];
                    e = k.getcertInfo(j.signcert, f, function(n, o) {
                        if (o != null) {
                            var m = {};
                            l(0, o)
                        } else {
                            l(ML4WebLog.getErrCode("Storage_Web_GetDetailCert"), {
                                errCode: n,
                                errMsg: $.i18n.prop("ER201")
                            })
                        }
                    });
                    break
                }
            }
        } else {
            l(ML4WebLog.getErrCode("Storage_Web_GetDetailCert"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    SaveCert: function(j, a, g, l) {
        ML4WebLog.log("Storage_API_web.SaveCert() called...");
        var f = ["startdatetime", "enddatetime", "issuername", "subjectname", "policyid", "subkeyid", "serialnum"];
        var k = ML4WebApi.getCryptoApi();
        var b = j.signcert;
        var d = g;
        var c = "";
        if (typeof(j.accesstime) != "undefined") {
            c = j.accesstime
        } else {
            c = new Date().getTime()
        }
        try {
            k.prikeyDecrypt(j.signpri, a, function(e, m) {
                if (e == 0) {
                    k.getcertInfo(b, f, function(q, p) {
                        if (q == 0) {
                            var s = "";
                            var o = magicjs.base64.decode(j.signcert);
                            var r = k.genHash("sha1", o);
                            if (ML4WebApi.getProperty("libType") == 0) {
                                s = p.subkeyid
                            } else {
                                s = p.result.subkeyid
                            }
                            var n = new Object();
                            n.fingerprint = r.resulthex;
                            n.timestamp = c;
                            n.status = "SAVE";
                            n.notBefore = p.result.startdatetime;
                            n.notAfter = p.result.enddatetime;
                            n.issuer = encodeURIComponent(p.result.issuername);
                            n.subject = encodeURIComponent(p.result.subjectname);
                            n.policyOID = p.result.policyid;
                            n.serial = p.result.serialnum;
                            n.source = "LOCAL";
                            j.storageCertIdx = s;
                            j.kftc = n;
                            d.storageCertIdx = s;
                            Storage_API_web.DeleteCert(d, function(u, v) {
                                if (u == 0) {
                                    var x = [];
                                    var t = Storage_API_web.getML4WebCert();
                                    if (t != null && t != "") {
                                        x = JSON.parse(t)
                                    }
                                    x.push(j);
                                    var w = JSON.stringify(x);
                                    Storage_API_web.setML4WebCert(w);
                                    l(0, {
                                        result: true
                                    })
                                } else {
                                    l(ML4WebLog.getErrCode("Storage_Web_SaveCert"), {
                                        errCode: u,
                                        errMsg: $.i18n.prop("ER201")
                                    })
                                }
                            })
                        } else {
                            l(ML4WebLog.getErrCode("Storage_Web_SaveCert"), {
                                errCode: q,
                                errMsg: JSON.stringify(p)
                            })
                        }
                    })
                } else {
                    l(ML4WebLog.getErrCode("Storage_Web_SaveCert"), {
                        errCode: e,
                        errMsg: m.errMsg
                    })
                }
            })
        } catch (h) {
            l(ML4WebLog.getErrCode("Storage_Web_SaveCert"), {
                errCode: 888,
                errMsg: h.message
            })
        }
    },
    SaveCertBag: function(h, f, k) {
        ML4WebLog.log("Storage_API_web.SaveCertBag() called...");
        var d = ["startdatetime", "enddatetime", "issuername", "subjectname", "policyid", "subkeyid", "serialnum"];
        var j = ML4WebApi.getCryptoApi();
        var a = h.signcert;
        var c = f;
        var b = "";
        if (typeof(h.accesstime) != "undefined") {
            b = h.accesstime
        } else {
            b = new Date().getTime()
        }
        try {
            j.getcertInfo(a, d, function(n, m) {
                if (n == 0) {
                    var p = "";
                    var l = magicjs.base64.decode(h.signcert);
                    var o = j.genHash("sha1", l);
                    if (ML4WebApi.getProperty("libType") == 0) {
                        p = m.subkeyid
                    } else {
                        p = m.result.subkeyid
                    }
                    var e = new Object();
                    e.fingerprint = o.resulthex;
                    e.timestamp = b;
                    e.status = "SAVE";
                    e.notBefore = m.result.startdatetime;
                    e.notAfter = m.result.enddatetime;
                    e.issuer = encodeURIComponent(m.result.issuername);
                    e.subject = encodeURIComponent(m.result.subjectname);
                    e.policyOID = m.result.policyid;
                    e.serial = m.result.serialnum;
                    e.source = "LOCAL";
                    h.storageCertIdx = p;
                    h.kftc = e;
                    c.storageCertIdx = p;
                    Storage_API_web.DeleteCert(c, function(r, s) {
                        if (r == 0) {
                            var u = [];
                            var q = Storage_API_web.getML4WebCert();
                            if (q != null && q != "") {
                                u = JSON.parse(q)
                            }
                            u.push(h);
                            var t = JSON.stringify(u);
                            Storage_API_web.setML4WebCert(t);
                            k(0, {
                                result: true
                            })
                        } else {
                            k(ML4WebLog.getErrCode("Storage_Web_SaveCert"), {
                                errCode: r,
                                errMsg: $.i18n.prop("ER201")
                            })
                        }
                    })
                } else {
                    k(ML4WebLog.getErrCode("Storage_Web_SaveCert"), {
                        errCode: n,
                        errMsg: JSON.stringify(m)
                    })
                }
            })
        } catch (g) {
            k(ML4WebLog.getErrCode("Storage_Web_SaveCert"), {
                errCode: 888,
                errMsg: g.message
            })
        }
    },
    DeleteCert: function(g, n) {
        ML4WebLog.log("Storage_API_web.DeleteCert() called...");
        try {
            var a = Storage_API_web.getML4WebCert();
            var b = a != null ? JSON.parse(a) : [];
            var l = {};
            var m = ML4WebApi.getCryptoApi();
            var d = false;
            var f = [];
            var j = b.length;
            for (var c = j - 1; c >= 0; c--) {
                if (b[c].storageCertIdx == g.storageCertIdx) {
                    b.splice(c, 1)
                } else {
                    var k = f.length;
                    f[k] = b[c]
                }
            }
            Storage_API_web.delML4WebCert();
            if (f.length > 0) {
                Storage_API_web.setML4WebCert(JSON.stringify(f))
            } else {
                Storage_API_web.setML4WebCert("[]")
            }
            n(0, {
                result: true
            })
        } catch (h) {
            n(ML4WebLog.getErrCode("Storage_Web_DeleteCert"), {
                errCode: 888,
                errMsg: h.message
            })
        }
    },
    ChangePassword: function(h, k, c, p) {
        ML4WebLog.log("Storage_API_web.ChangePassword() called...");
        try {
            var a = Storage_API_web.getML4WebCert();
            var b = JSON.parse(a);
            var n = {};
            var o = ML4WebApi.getCryptoApi();
            var f = null;
            var m = b.length;
            if (b != null && m > 0) {
                for (var d = 0; d < m; d++) {
                    if (b[d].storageCertIdx == h.storageCertIdx) {
                        var l = b[d];
                        var g = c;
                        c = ML4WebApi.ml4web_crypto_api.SD_api(c);
                        o.prikeyDecrypt(l.signpri, k, function(e, q) {
                            if (e == 0) {
                                o.prikeyEncrypt(q.Base64String, c, null, function(s, t) {
                                    if (s == 0) {
                                        if (ML4WebApi.getProperty("libType") == 0) {
                                            l.signpri = t
                                        } else {
                                            l.signpri = t.Base64String
                                        }
                                        if (l.kmpri) {
                                            o.prikeyDecrypt(l.kmpri, k, function(u, v) {
                                                if (u == 0) {
                                                    o.prikeyEncrypt(v.Base64String, c, null, function(y, w) {
                                                        if (y == 0) {
                                                            if (ML4WebApi.getProperty("libType") == 0) {
                                                                l.kmpri = w
                                                            } else {
                                                                l.kmpri = w.Base64String
                                                            }
                                                            var x = Storage_API_web.SaveCert;
                                                            x(l, g, h, function(A, z) {
                                                                if (A == 0) {
                                                                    p(0, {
                                                                        result: true
                                                                    })
                                                                } else {
                                                                    p(ML4WebLog.getErrCode("Storage_Web_ChangePassword"), {
                                                                        errCode: A,
                                                                        errMsg: z.errMsg
                                                                    })
                                                                }
                                                            })
                                                        } else {
                                                            p(ML4WebLog.getErrCode("Storage_Web_ChangePassword"), {
                                                                errCode: y,
                                                                errMsg: $.i18n.prop("ER201")
                                                            })
                                                        }
                                                    })
                                                } else {
                                                    p(ML4WebLog.getErrCode("Storage_Web_ChangePassword"), {
                                                        errCode: u,
                                                        errMsg: $.i18n.prop("ER201")
                                                    })
                                                }
                                            })
                                        } else {
                                            var r = JSON.stringify(h);
                                            Storage_API_web.SaveCert(l, g, h, function(v, u) {
                                                if (v == 0) {
                                                    p(0, {
                                                        result: true
                                                    })
                                                } else {
                                                    p(ML4WebLog.getErrCode("Storage_Web_ChangePassword"), {
                                                        errCode: v,
                                                        errMsg: u.errMsg
                                                    })
                                                }
                                            })
                                        }
                                    } else {
                                        p(ML4WebLog.getErrCode("Storage_Web_ChangePassword"), {
                                            errCode: s,
                                            errMsg: $.i18n.prop("ER201")
                                        })
                                    }
                                })
                            } else {
                                p(ML4WebLog.getErrCode("Storage_Web_ChangePassword"), {
                                    errCode: e,
                                    errMsg: $.i18n.prop("ER201")
                                })
                            }
                        })
                    } else {}
                }
            } else {
                p(ML4WebLog.getErrCode("Storage_Web_ChangePassword"), {
                    errCode: 204,
                    errMsg: $.i18n.prop("ER204")
                })
            }
        } catch (j) {
            p(ML4WebLog.getErrCode("Storage_Web_ChangePassword"), {
                errCode: 888,
                errMsg: j.message
            })
        }
    },
    verifyVID: function(f, a, d, l) {
        ML4WebLog.log("Storage_API_web.verifyVID() called...");
        var h = false;
        var b = Storage_API_web.getML4WebCert();
        var c = b != null ? JSON.parse(b) : [];
        var j = {};
        var k = ML4WebApi.getCryptoApi();
        var g = c.length;
        for (var e = 0; e < g; e++) {
            if (c[e].storageCertIdx == f.storageCertIdx) {
                j = c[e];
                h = true
            }
        }
        if (h) {
            k.verifyVID(j.signcert, j.signpri, a, d, function(n, m) {
                if (n == 0) {
                    if (m.result == true) {
                        l(0, m)
                    } else {
                        l(ML4WebLog.getErrCode("Storage_web_verifyVID"), {
                            errCode: n,
                            errMsg: $.i18n.prop("ES022")
                        })
                    }
                } else {
                    l(ML4WebLog.getErrCode("Storage_web_verifyVID"), {
                        errCode: n,
                        errMsg: $.i18n.prop("ES022")
                    })
                }
            })
        } else {
            l(ML4WebLog.getErrCode("Storage_Web_verifyVID"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    getVIDRandom: function(f, a, l) {
        ML4WebLog.log("Storage_API_web.getVIDRandom() called...");
        var e = [];
        var h = false;
        var b = Storage_API_web.getML4WebCert();
        var c = JSON.parse(b);
        var j = {};
        var k = ML4WebApi.getCryptoApi();
        if (c != null) {
            var g = c.length;
            for (var d = 0; d < g; d++) {
                if (c[d].storageCertIdx == f.storageCertIdx) {
                    j = c[d];
                    h = true
                }
            }
            if (h) {
                k.getVIDRandom(j.signpri, a, function(n, m) {
                    if (n == 0) {
                        if (ML4WebApi.getProperty("libType") == 0) {
                            l(0, {
                                VIDRandom: m
                            })
                        } else {
                            l(0, {
                                VIDRandom: m.result
                            })
                        }
                    } else {
                        l(ML4WebLog.getErrCode("Storage_web_getVIDRandom"), {
                            errCode: n,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            } else {
                if (typeof(f.browserSaveYn) != "undefined") {
                    k.getVIDRandom(f.signpri, a, function(n, m) {
                        if (n == 0) {
                            if (ML4WebApi.getProperty("libType") == 0) {
                                l(0, {
                                    VIDRandom: m
                                })
                            } else {
                                l(0, {
                                    VIDRandom: m.result
                                })
                            }
                        } else {
                            l(ML4WebLog.getErrCode("Storage_web_getVIDRandom"), {
                                errCode: n,
                                errMsg: $.i18n.prop("ER201")
                            })
                        }
                    })
                } else {
                    l(ML4WebLog.getErrCode("Storage_Web_getVIDRandom"), {
                        errCode: 201,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            }
        } else {
            k.getVIDRandom(f.signpri, a, function(n, m) {
                if (n == 0) {
                    if (ML4WebApi.getProperty("libType") == 0) {
                        l(0, {
                            VIDRandom: m
                        })
                    } else {
                        l(0, {
                            VIDRandom: m.result
                        })
                    }
                } else {
                    l(ML4WebLog.getErrCode("Storage_web_getVIDRandom"), {
                        errCode: n,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        }
    },
    getVIDRandomHash: function(f, a, d, l) {
        ML4WebLog.log("Storage_API_web.getVIDRandomHash() called...");
        var h = false;
        var b = Storage_API_web.getML4WebCert();
        var c = b != null ? JSON.parse(b) : [];
        var j = {};
        var k = ML4WebApi.getCryptoApi();
        var g = c.length;
        for (var e = 0; e < g; e++) {
            ML4WebLog.log("Storage_API_web.getVIDRandomHash() called...certBaglistObj[i].storageCertIdx=" + c[e].storageCertIdx);
            if (c[e].storageCertIdx == f.storageCertIdx) {
                j = c[e];
                h = true
            }
        }
        if (h) {
            k.getVIDRandomHash(j.signcert, j.signpri, a, d, function(n, m) {
                if (n == 0) {
                    l(0, {
                        VIDRandomHash: m.result
                    })
                } else {
                    l(ML4WebLog.getErrCode("Storage_web_getVIDRandomHash"), {
                        errCode: n,
                        errMsg: $.i18n.prop("ES022")
                    })
                }
            })
        } else {
            l(ML4WebLog.getErrCode("Storage_Web_getVIDRandomHash"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    Sign: function(f, c, a, e, g) {
        ML4WebLog.log("Storage_API_web.Sign() called...");
        var d = ML4WebApi.getCryptoApi();
        e = encodeUtf8Hex(e);
        var b = Storage_API_web.getSelectCert(f);
        if (b.code === 0) {
            d.sign(b.signcert, b.signpri, a, e, c, function(j, h) {
                if (j == 0) {
                    if (ML4WebApi.getProperty("libType") == 0) {
                        g(0, {
                            storageCertIdx: f,
                            encMsg: h,
                            userCert: b.signcert
                        })
                    } else {
                        g(0, {
                            storageCertIdx: f,
                            encMsg: h.stringResult,
                            userCert: b.signcert
                        })
                    }
                } else {
                    if (ML4WebApi.getProperty("libType") == 0) {
                        g(ML4WebLog.getErrCode("Storage_Web_Sign"), {
                            errCode: h.errCode,
                            errMsg: h.errMsg
                        })
                    } else {
                        g(ML4WebLog.getErrCode("Storage_Web_Sign"), {
                            errCode: j,
                            errMsg: h
                        })
                    }
                }
            })
        } else {
            g(ML4WebLog.getErrCode("Storage_Web_Sign"), {
                errCode: b.code,
                errMsg: b.message
            })
        }
    },
    Signature: function(f, c, a, e, g) {
        ML4WebLog.log("Storage_API_web.Signature() called...");
        var d = ML4WebApi.getCryptoApi();
        e = encodeUtf8Hex(e);
        var b = Storage_API_web.getSelectCert(f);
        if (b.code === 0) {
            d.signature(b.signcert, b.signpri, a, e, c, function(j, h) {
                if (j === 0) {
                    g(0, {
                        storageCertIdx: f,
                        encMsg: h.stringResult,
                        userCert: b.signcert
                    })
                } else {
                    g(ML4WebLog.getErrCode("Storage_Web_Signature"), {
                        errCode: j,
                        errMsg: h.errMsg
                    })
                }
            })
        } else {
            g(ML4WebLog.getErrCode("Storage_Web_Signature"), {
                errCode: b.code,
                errMsg: b.message
            })
        }
    },
    IrosSign: function(f, c, a, e, g) {
        ML4WebLog.log("Storage_API_web.IrosSign() called...");
        var d = ML4WebApi.getCryptoApi();
        e = encodeUtf8Hex(e);
        var b = Storage_API_web.getSelectCert(f);
        if (b.code === 0) {
            d.sign(b.signcert, b.signpri, a, e, c, function(j, h) {
                if (j == 0) {
                    if (ML4WebApi.getProperty("libType") == 0) {
                        g(0, {
                            storageCertIdx: f,
                            encMsg: h
                        })
                    } else {
                        g(0, {
                            storageCertIdx: f,
                            encMsg: h.stringResult
                        })
                    }
                } else {
                    if (ML4WebApi.getProperty("libType") == 0) {
                        g(ML4WebLog.getErrCode("Storage_Web_IrosSign"), {
                            errCode: h.errCode,
                            errMsg: h.errMsg
                        })
                    } else {
                        g(ML4WebLog.getErrCode("Storage_Web_IrosSign"), {
                            errCode: j,
                            errMsg: h
                        })
                    }
                }
            })
        } else {
            g(ML4WebLog.getErrCode("Storage_Web_IrosSign"), {
                errCode: b.code,
                errMsg: b.message
            })
        }
    },
    IrosAddSignData: function(f, c, a, e, g) {
        ML4WebLog.log("Storage_API_web.IrosAddSign() called...");
        ML4WebLog.log("Storage_API_web.IrosAddSign() storageRawCertIdx = " + JSON.stringify(f));
        var d = ML4WebApi.getCryptoApi();
        e = encodeUtf8Hex(e);
        var b = Storage_API_web.getSelectCert(f);
        if (b.code === 0) {
            d.sign(b.signcert, b.signpri, a, e, c, function(j, h) {
                if (j == 0) {
                    if (ML4WebApi.getProperty("libType") == 0) {
                        g(0, {
                            storageCertIdx: f,
                            encMsg: h
                        })
                    } else {
                        g(0, {
                            storageCertIdx: f,
                            encMsg: h.stringResult
                        })
                    }
                } else {
                    if (ML4WebApi.getProperty("libType") == 0) {
                        g(ML4WebLog.getErrCode("Storage_Web_IrosAddSign"), {
                            errCode: h.errCode,
                            errMsg: h.errMsg
                        })
                    } else {
                        g(ML4WebLog.getErrCode("Storage_Web_IrosAddSign"), {
                            errCode: j,
                            errMsg: h
                        })
                    }
                }
            })
        } else {
            g(ML4WebLog.getErrCode("Storage_Web_IrosAddSign"), {
                errCode: b.code,
                errMsg: b.message
            })
        }
    },
    IrosMultiSign: function(h, f, a, d) {
        ML4WebLog.log("Storage_API_web.IrosMultiSign() called...");
        ML4WebLog.log("Storage_API_web.IrosMultiSign() storageRawCertIdx = " + JSON.stringify(h));
        var l = ML4WebApi.getCryptoApi();
        if (Storage_API_web.selectCertString.length != 0 && Storage_API_web.selectCertString.storageCertIdx == h.storageCertIdx) {
            var m = l.sign(Storage_API_web.selectCertString.signcert, Storage_API_web.selectCertString.signpri, a, d, f);
            return m
        } else {
            var g = [];
            var j = false;
            var c = Storage_API_web.getML4WebCert();
            if (c != null) {
                var b = JSON.parse(c);
                var k = {};
                for (var e = 0; e < b.length; e++) {
                    ML4WebLog.log("Storage_API_web.IrosMultiSign() called...certBaglistObj[i].storageCertIdx=" + b[e].storageCertIdx);
                    ML4WebLog.log("Storage_API_web.IrosMultiSign() called..." + h.storageCertIdx);
                    if (b[e].storageCertIdx == h.storageCertIdx) {
                        k = b[e];
                        j = true
                    }
                }
                if (j) {
                    var m = l.sign(k.signcert, k.signpri, a, d, f);
                    return m
                } else {
                    return {
                        code: ML4WebLog.getErrCode("Storage_Web_IrosMultiSign"),
                        data: {
                            errCode: 201111,
                            errMsg: $.i18n.prop("ER201")
                        }
                    }
                }
            }
        }
    },
    IrosMultiAddSign: function(h, f, a, d) {
        ML4WebLog.log("Storage_API_web.IrosMultiAddSign() called...");
        ML4WebLog.log("Storage_API_web.IrosMultiAddSign() storageRawCertIdx = " + JSON.stringify(h));
        var l = ML4WebApi.getCryptoApi();
        if (Storage_API_web.selectCertString.length != 0 && Storage_API_web.selectCertString.storageCertIdx == h.storageCertIdx) {
            var m = l.sign(Storage_API_web.selectCertString.signcert, Storage_API_web.selectCertString.signpri, a, d, f);
            return m
        } else {
            var g = [];
            var j = false;
            var c = Storage_API_web.getML4WebCert();
            if (c != null) {
                var b = JSON.parse(c);
                var k = {};
                for (var e = 0; e < b.length; e++) {
                    ML4WebLog.log("Storage_API_web.IrosMultiAddSign() called...certBaglistObj[i].storageCertIdx=" + b[e].storageCertIdx);
                    ML4WebLog.log("Storage_API_web.IrosMultiAddSign() called..." + h.storageCertIdx);
                    if (b[e].storageCertIdx == h.storageCertIdx) {
                        k = b[e];
                        j = true
                    }
                }
                if (j) {
                    var m = l.sign(k.signcert, k.signpri, a, d, f);
                    return m
                } else {
                    return {
                        code: ML4WebLog.getErrCode("Storage_Web_IrosMultiAddSign"),
                        data: {
                            errCode: 201111,
                            errMsg: $.i18n.prop("ER201")
                        }
                    }
                }
            }
        }
    },
    SingedEnvelopedData: function(j, f, g, a, d, o) {
        ML4WebLog.log("Storage_API_web.SingedEnvelopedData() called...");
        var n = ML4WebApi.getCryptoApi();
        d = encodeUtf8Hex(d);
        var h = [];
        var l = false;
        var c = Storage_API_web.getML4WebCert();
        var b = c != null ? JSON.parse(c) : [];
        var m = {};
        var k = b.length;
        for (var e = 0; e < k; e++) {
            if (b[e].storageCertIdx == j.storageCertIdx) {
                m = b[e];
                l = true
            }
        }
        if (l) {
            n.signedEnvelopedData(f, Storage_API_web.selectCertString.signcert, Storage_API_web.selectCertString.signpri, a, d, null, null, function(q, p) {
                if (q == 0) {
                    o(0, {
                        storageCertIdx: j,
                        encMsg: p.stringResult
                    })
                } else {
                    o(ML4WebLog.getErrCode("Storage_Web_Sign"), {
                        errCode: 201,
                        errMsg: p
                    })
                }
            })
        } else {
            o(ML4WebLog.getErrCode("Storage_Web_SingedEnvelopedData"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    }
};
var Storage_API_pfx = {
    selectCertString: "",
    selectStorageRawCertIdx: "",
    selectCertPasswd: "",
    SelectStorageInfo: function(a, c) {
        var b = {};
        if (window.FileReader && ML4WebApi.getProperty("libType") == 1) {
            b.pfxOpt = [{
                libType: "javascript"
            }]
        } else {
            b.pfxOpt = [{
                libType: "c"
            }]
        }
        if (true) {
            c(0, b)
        } else {
            c(ML4WebLog.getErrCode("Storage_pfx_SelectStorageInfo"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    GetCertList: function(k, j) {
        ML4WebLog.log("Storage_API_pfx.GetCertList() called...");
        var c = [];
        if (k.pfxOpt.libType == "c") {
            var h = ML4WebApi.getResourceApi();
            var d = ML4WebApi.getProperty("CsUrl");
            k.pfxOpt.downloadUrl = ML4WebApi.getProperty("PfxExportDownloadUrl");
            var l = h.makeJsonMessage("GetCertList", encodeURIComponent(JSON.stringify(k)));
            var a = ML4WebApi.getCsManager();
            try {
                a.callLocalServerAPI(d, l, function(m, o) {
                    if (m == 0) {
                        var e = JSON.parse(o);
                        if (e.ResultCode == 0) {
                            var n = JSON.parse(e.ResultMessage);
                            j(0, n);
                            return
                        } else {
                            j(ML4WebLog.getErrCode("Storage_pfx_GetCertList"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    }
                })
            } catch (f) {
                j(ML4WebLog.getErrCode("Storage_pfx_GetCertList"), {
                    errCode: 888,
                    errMsg: f.message
                });
                return
            }
        } else {
            var g = ML4WebApi.getCryptoApi();
            var b = k.pfxOpt.b64CertString;
            g.pfxImport(b, k.pfxOpt.pfxPasswd, function(o, n) {
                var m = n.result;
                selectCertString = m;
                selectCertPasswd = k.pfxOpt.pfxPasswd;
                if (n.result) {
                    var e = [];
                    g.getcertInfo(n.result.signcert, e, function(s, r) {
                        if (s == "0") {
                            var p = {
                                storageName: "pfx",
                                storageOpt: {}
                            };
                            p.storageOpt.pfxOpt = k.pfxOpt;
                            p.storageCertIdx = r.result.subkeyid;
                            selectStorageRawCertIdx = p;
                            var q = JSON.stringify(p);
                            r.result.storageRawCertIdx = p;
                            c.push(r.result);
                            j(0, {
                                cert_list: c
                            })
                        } else {
                            j(ML4WebLog.getErrCode("Storage_pfx_GetCertList"), {
                                errCode: s,
                                errMsg: JSON.stringify(r)
                            })
                        }
                    })
                } else {
                    j(ML4WebLog.getErrCode("Storage_pfx_GetCertList"), {
                        errCode: o,
                        errMsg: n.errMsg
                    })
                }
            })
        }
    },
    GetCertString: function(g, j) {
        ML4WebLog.log("Storage_API_pfx.GetCertString() called...");
        if (g.storageOpt.pfxOpt.libType == "c") {
            var h = ML4WebApi.getResourceApi();
            var c = ML4WebApi.getProperty("CsUrl");
            var b = h.makeJsonMessage("GetCertString", encodeURIComponent(JSON.stringify(g)));
            var a = ML4WebApi.getCsManager();
            try {
                a.callLocalServerAPI(c, b, function(k, m) {
                    if (k == 0) {
                        var e = JSON.parse(m);
                        if (e.ResultCode == 0) {
                            var l = JSON.parse(e.ResultMessage);
                            j(0, {
                                cert: l.cert_string
                            });
                            return
                        } else {
                            j(ML4WebLog.getErrCode("Storage_pfx_GetCertString"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    }
                })
            } catch (f) {
                j(ML4WebLog.getErrCode("Storage_pfx_GetCertString"), {
                    errCode: 888,
                    errMsg: f.message
                });
                return
            }
        } else {
            if (g.storageOpt.pfxOpt.b64CertString != "") {
                var d = ML4WebApi.getCryptoApi();
                d.pfxImport(g.storageOpt.pfxOpt.b64CertString, g.storageOpt.pfxOpt.pfxPasswd, function(l, k) {
                    if (l == 0) {
                        var e = k.result;
                        selectCertString = e;
                        selectCertPasswd = g.storageOpt.pfxOpt.pfxPasswd;
                        j(0, {
                            cert: selectCertString
                        })
                    } else {
                        j(ML4WebLog.getErrCode("Storage_pfx_GetCertString"), {
                            errCode: l,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            } else {
                j(ML4WebLog.getErrCode("Storage_pfx_GetCertString"), {
                    errCode: 201,
                    errMsg: $.i18n.prop("ER201")
                })
            }
        }
    },
    GetDetailCert: function(f, d, k) {
        ML4WebLog.log("Storage_API_pfx.GetDetailCert() called...");
        var a = "";
        if (f.storageOpt.pfxOpt.libType == "c") {
            var j = ML4WebApi.getResourceApi();
            var c = ML4WebApi.getProperty("CsUrl");
            var l = j.makeJsonMessage("GetDetailCert", encodeURIComponent(JSON.stringify(f)), encodeURIComponent(JSON.stringify(d)));
            var b = ML4WebApi.getCsManager();
            try {
                b.callLocalServerAPI(c, l, function(m, n) {
                    if (m == 0) {
                        var e = JSON.parse(n);
                        if (e.ResultCode == 0) {
                            k(0, {
                                result: JSON.parse(e.ResultMessage)
                            });
                            return
                        } else {
                            k(ML4WebLog.getErrCode("Storage_pfx_GetDetailCert"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    } else {
                        k(ML4WebLog.getErrCode("Storage_pfx_GetDetailCert"), {
                            errCode: m,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            } catch (g) {
                k(ML4WebLog.getErrCode("Storage_pfx_GetDetailCert"), {
                    errCode: 888,
                    errMsg: g.message
                });
                return
            }
        } else {
            var h = ML4WebApi.getCryptoApi();
            try {
                Storage_API_pfx.GetCertString(f, function(n, m) {
                    if (n == 0) {
                        var e = m.cert;
                        h.getcertInfo(e.signcert, d, function(p, r) {
                            if (p == 0) {
                                var o = {};
                                var q = d.length;
                                for (i = 0; i < q; i++) {
                                    var s = d[i];
                                    o[s] = r.result[s]
                                }
                                k(0, {
                                    result: o
                                })
                            } else {
                                k(ML4WebLog.getErrCode("Storage_pfx_GetDetailCert"), {
                                    errCode: p,
                                    errMsg: r
                                })
                            }
                        })
                    } else {
                        k(ML4WebLog.getErrCode("Storage_pfx_GetDetailCert"), {
                            errCode: n,
                            errMsg: m
                        })
                    }
                })
            } catch (g) {
                k(ML4WebLog.getErrCode("Storage_pfx_GetDetailCert"), {
                    errCode: 888,
                    errMsg: g.message
                })
            }
        }
    },
    SaveCert: function(f, a, k, j) {
        ML4WebLog.log("Storage_API_pfx.SaveCert() called...");
        if (!window.FileReader) {
            var h = ML4WebApi.getResourceApi();
            var c = ML4WebApi.getProperty("CsUrl");
            var l = h.makeJsonMessage("SaveCert", encodeURIComponent(JSON.stringify(f)), a, encodeURIComponent(JSON.stringify(k)));
            var b = ML4WebApi.getCsManager();
            try {
                b.callLocalServerAPI(c, l, function(m, n) {
                    if (m == 0) {
                        var e = JSON.parse(n);
                        if (e.ResultCode == 0) {
                            j(0, {
                                result: $.i18n.prop("ER105")
                            });
                            return
                        } else {
                            j(ML4WebLog.getErrCode("Storage_pfx_SaveCert"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    } else {
                        j(ML4WebLog.getErrCode("Storage_pfx_SaveCert"), {
                            errCode: m,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            } catch (d) {
                j(ML4WebLog.getErrCode("Storage_pfx_SaveCert"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        } else {
            var g = ML4WebApi.getCryptoApi();
            g.pfxExport(f, a, function(n, m) {
                if (n == 0) {
                    var e = "test.pfx";
                    var o = ["subjectname", "realname"];
                    var p;
                    g.getcertInfo(f.signcert, o, function(r, A) {
                        if (r == 0) {
                            if (ML4WebApi.getProperty("libType") == 0) {
                                if (typeof(A.realname) == "undefined") {
                                    var t = A.subjectname;
                                    t = t.substring(3, t.indexOf("[,]"));
                                    e = t + ".pfx"
                                } else {
                                    e = A.realname + ".pfx"
                                }
                                p = m
                            } else {
                                if (typeof(A.result.realname) == "undefined") {
                                    var t = A.result.subjectname;
                                    t = t.substring(3, t.indexOf("[,]"));
                                    e = t + ".pfx"
                                } else {
                                    e = A.result.realname + ".pfx"
                                }
                                p = m.result
                            }
                        }
                        var y = window.atob(p);
                        var z = y.length;
                        var u = new Uint8Array(new ArrayBuffer(z));
                        for (i = 0; i < z; i++) {
                            u[i] = y.charCodeAt(i)
                        }
                        var w = "application/octet-stream";
                        var q = new Blob([u], {
                            type: w
                        });
                        if (typeof window.navigator.msSaveBlob !== "undefined") {
                            window.navigator.msSaveBlob(q, e)
                        } else {
                            var v = window.URL || window.webkitURL;
                            var s = v.createObjectURL(q);
                            if (e) {
                                var x = document.createElement("a");
                                if (typeof x.download === "undefined") {
                                    window.location = s
                                } else {
                                    x.href = s;
                                    x.download = e;
                                    document.body.appendChild(x);
                                    x.click()
                                }
                            } else {
                                window.location = s
                            }
                            setTimeout(function() {
                                v.revokeObjectURL(s)
                            }, 100)
                        }
                        j(0, {
                            result: true
                        })
                    })
                } else {
                    j(ML4WebLog.getErrCode("Storage_pfx_SaveCert"), {
                        errCode: n,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        }
    },
    DeleteCert: function(a, b) {
        ML4WebLog.log("Storage_API_pfx.DeleteCert() called.");
        b(ML4WebLog.getErrCode("Storage_pfx_DeleteCert"), {
            errCode: 105,
            errMsg: $.i18n.prop("ER105")
        })
    },
    ChangePassword: function(c, b, a, d) {
        ML4WebLog.log("Storage_API_pfx.ChangePassword() called...");
        d(ML4WebLog.getErrCode("Storage_pfx_ChangePassword"), {
            errCode: 105,
            errMsg: $.i18n.prop("ER105")
        })
    },
    verifyVID: function(f, a, c, k) {
        ML4WebLog.log("Storage_API_pfx.verifyVID() called...");
        if (f.storageOpt.pfxOpt.libType == "c") {
            var j = ML4WebApi.getResourceApi();
            var d = ML4WebApi.getProperty("CsUrl");
            var l = j.makeJsonMessage("VerifyVID", encodeURIComponent(JSON.stringify(f)), a, c);
            var b = ML4WebApi.getCsManager();
            try {
                b.callLocalServerAPI(d, l, function(m, n) {
                    if (m == 0) {
                        var e = JSON.parse(n);
                        if (e.ResultCode == 0) {
                            k(0, {
                                result: true
                            });
                            return
                        } else {
                            k(ML4WebLog.getErrCode("Storage_pfx_verifyVID"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    }
                })
            } catch (g) {
                k(ML4WebLog.getErrCode("Storage_pfx_verifyVID"), {
                    errCode: 888,
                    errMsg: g.message
                });
                return
            }
        } else {
            var h = ML4WebApi.getCryptoApi();
            if (selectCertString.length != 0) {
                h.verifyVID(selectCertString.signcert, selectCertString.signpri, a, c, function(m, e) {
                    if (m == 0) {
                        if (e.result == true) {
                            k(0, e);
                            return
                        } else {
                            k(ML4WebLog.getErrCode("Storage_pfx_verifyVID"), {
                                errCode: 18,
                                errMsg: $.i18n.prop("ES022")
                            });
                            return
                        }
                    } else {
                        k(ML4WebLog.getErrCode("Storage_pfx_verifyVID"), {
                            errCode: m,
                            errMsg: $.i18n.prop("ES022")
                        });
                        return
                    }
                })
            } else {
                f.storageOpt.pfxOpt.pfxPasswd = a;
                Storage_API_pfx.GetCertString(f, function(n, m) {
                    if (n == 0) {
                        var e = m.cert;
                        h.verifyVID(e.signcert, e.signpri, a, c, function(o, p) {
                            if (o == 0) {
                                k(0, p)
                            } else {
                                k(ML4WebLog.getErrCode("Storage_pfx_verifyVID"), {
                                    errCode: o,
                                    errMsg: p
                                })
                            }
                        })
                    } else {
                        k(ML4WebLog.getErrCode("Storage_pfx_verifyVID"), {
                            errCode: n,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            }
        }
    },
    getVIDRandom: function(d, a, j) {
        ML4WebLog.log("Storage_API_pfx.getVIDRandom() called...");
        if (d.storageOpt.pfxOpt.libType == "c") {
            var h = ML4WebApi.getResourceApi();
            var c = ML4WebApi.getProperty("CsUrl");
            var k = h.makeJsonMessage("GetVIDRandom", encodeURIComponent(JSON.stringify(d)), a);
            var b = ML4WebApi.getCsManager();
            try {
                b.callLocalServerAPI(c, k, function(l, m) {
                    if (l == 0) {
                        var e = JSON.parse(m);
                        if (e.ResultCode == 0) {
                            j(0, {
                                VIDRandom: e.ResultMessage
                            });
                            return
                        } else {
                            j(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    } else {
                        j(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                            errCode: l,
                            errMsg: m.ResultMessage
                        })
                    }
                })
            } catch (f) {
                j(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                    errCode: 888,
                    errMsg: f.message
                });
                return
            }
        } else {
            var g = ML4WebApi.getCryptoApi();
            if (selectCertString.length != 0) {
                g.getVIDRandom(selectCertString.signpri, a, function(l, e) {
                    if (l == 0) {
                        j(0, {
                            VIDRandom: e.result
                        })
                    } else {
                        j(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                            errCode: l,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            } else {
                d.storageOpt.pfxOpt.pfxPasswd = a;
                Storage_API_pfx.GetCertString(d, function(m, l) {
                    if (m == 0) {
                        var e = l.cert;
                        g.getVIDRandom(e.signpri, a, function(n, o) {
                            if (n == 0) {
                                j(0, {
                                    VIDRandom: o
                                })
                            } else {
                                j(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                                    errCode: n,
                                    errMsg: o
                                })
                            }
                        })
                    } else {
                        j(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                            errCode: m,
                            errMsg: $.i18n.prop("ER207")
                        })
                    }
                })
            }
        }
    },
    getVIDRandomHash: function(f, a, c, k) {
        ML4WebLog.log("Storage_API_pfx.getVIDRandom() called...");
        if (f.storageOpt.pfxOpt.libType == "c") {
            var j = ML4WebApi.getResourceApi();
            var d = ML4WebApi.getProperty("CsUrl");
            var l = j.makeJsonMessage("GetVIDRandomHash", encodeURIComponent(JSON.stringify(f)), a);
            var b = ML4WebApi.getCsManager();
            try {
                b.callLocalServerAPI(d, l, function(m, n) {
                    if (m == 0) {
                        var e = JSON.parse(n);
                        if (e.ResultCode == 0) {
                            k(0, {
                                VIDRandomHash: e.ResultMessage
                            });
                            return
                        } else {
                            k(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    } else {
                        k(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                            errCode: m,
                            errMsg: n.ResultMessage
                        })
                    }
                })
            } catch (g) {
                k(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                    errCode: 888,
                    errMsg: g.message
                });
                return
            }
        } else {
            var h = ML4WebApi.getCryptoApi();
            if (selectCertString.length != 0) {
                h.getVIDRandomHash(selectCertString.signcert, selectCertString.signpri, a, c, function(m, e) {
                    if (m == 0) {
                        k(0, {
                            VIDRandomHash: e
                        })
                    } else {
                        k(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                            errCode: m,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            } else {
                f.storageOpt.pfxOpt.pfxPasswd = a;
                Storage_API_pfx.GetCertString(f, function(n, m) {
                    if (n == 0) {
                        var e = m.cert;
                        h.getVIDRandomHash(selectCertString.signcert, e.signpri, a, c, function(o, p) {
                            if (o == 0) {
                                k(0, {
                                    VIDRandomHash: p
                                })
                            } else {
                                k(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                                    errCode: o,
                                    errMsg: p
                                })
                            }
                        })
                    } else {
                        k(ML4WebLog.getErrCode("Storage_pfx_getVIDRandom"), {
                            errCode: n,
                            errMsg: $.i18n.prop("ER207")
                        })
                    }
                })
            }
        }
    },
    Sign: function(g, d, a, c, l) {
        ML4WebLog.log("Storage_API_pfx.Sign() called...");
        if (g.storageOpt.pfxOpt.libType == "c") {
            var k = ML4WebApi.getResourceApi();
            var f = ML4WebApi.getProperty("CsUrl");
            c = encodeUtf8andBase64(c);
            var m = k.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(d)), a, c);
            var b = ML4WebApi.getCsManager();
            try {
                b.callLocalServerAPI(f, m, function(n, o) {
                    if (n == 0) {
                        var e = JSON.parse(o);
                        if (e.ResultCode == 0) {
                            Storage_API_pfx.GetCertString(g, function(p, r) {
                                if (p == 0) {
                                    var q = JSON.parse(e.ResultMessage);
                                    l(0, {
                                        storageCertIdx: g,
                                        encMsg: q.encMsg,
                                        userCert: r.cert.signcert
                                    })
                                } else {
                                    l(ML4WebLog.getErrCode("Storage_pfx_Sign"), {
                                        errCode: r.errCode,
                                        errMsg: r.errMsg
                                    })
                                }
                            })
                        } else {
                            l(ML4WebLog.getErrCode("Storage_pfx_Sign"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            })
                        }
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_Sign"), {
                            errCode: n,
                            errMsg: o.ResultMessage
                        })
                    }
                })
            } catch (h) {
                l(ML4WebLog.getErrCode("Storage_pfx_Sign"), {
                    errCode: 888,
                    errMsg: h.message
                });
                return
            }
        } else {
            var j = ML4WebApi.getCryptoApi();
            c = encodeUtf8Hex(c);
            if (selectCertString.length != 0) {
                j.sign(selectCertString.signcert, selectCertString.signpri, a, c, d, function(n, e) {
                    if (n == 0) {
                        l(0, {
                            storageCertIdx: g,
                            encMsg: e.stringResult,
                            userCert: selectCertString.signcert
                        });
                        return
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_Sign"), {
                            errCode: n,
                            errMsg: e.errMsg
                        });
                        return
                    }
                })
            } else {
                g.storageOpt.pfxOpt.pfxPasswd = a;
                Storage_API_pfx.GetCertString(g, function(o, n) {
                    if (o == 0) {
                        var e = n.cert;
                        c = encodeUtf8Hex(c);
                        j.sign(e.signcert, e.signpri, a, c, d, function(p, q) {
                            if (p == 0) {
                                l(0, q)
                            } else {
                                l(ML4WebLog.getErrCode("Storage_pfx_Sign"), {
                                    errCode: o,
                                    errMsg: n.errMsg
                                })
                            }
                        })
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_Sign"), {
                            errCode: o,
                            errMsg: n.errMsg
                        })
                    }
                })
            }
        }
    },
    Signature: function(d, b, a, c, e) {
        Storage_API_hdd.Sign(d, b, a, c, e)
    },
    IrosSign: function(g, d, a, c, l) {
        ML4WebLog.log("Storage_API_pfx.IrosSign() called... storageRawCertIdx === " + JSON.stringify(g));
        ML4WebLog.log("Storage_API_pfx.IrosSign() called... libType === " + g.storageOpt.pfxOpt.libType);
        if (g.storageOpt.pfxOpt.libType == "c") {
            var k = ML4WebApi.getResourceApi();
            var f = ML4WebApi.getProperty("CsUrl");
            c = encodeUtf8andBase64(c);
            var m = k.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(d)), a, c);
            var b = ML4WebApi.getCsManager();
            try {
                b.callLocalServerAPI(f, m, function(n, p) {
                    ML4WebLog.log("Storage_API_pfx.IrosSign() httpRequest callback code ===" + n);
                    if (n == 0) {
                        var e = JSON.parse(p);
                        if (e.ResultCode == 0) {
                            ML4WebLog.log("sign result === " + e.ResultMessage);
                            var o = JSON.parse(e.ResultMessage);
                            l(0, {
                                storageCertIdx: g,
                                encMsg: o.encMsg
                            });
                            return
                        } else {
                            l(ML4WebLog.getErrCode("Storage_pfx_IrosSign"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_IrosSign"), {
                            errCode: n,
                            errMsg: p.ResultMessage
                        })
                    }
                })
            } catch (h) {
                l(ML4WebLog.getErrCode("Storage_pfx_IrosSign"), {
                    errCode: 888,
                    errMsg: h.message
                });
                return
            }
        } else {
            var j = ML4WebApi.getCryptoApi();
            if (selectCertString.length != 0) {
                j.sign(selectCertString.signcert, selectCertString.signpri, a, c, d, function(n, e) {
                    if (n == 0) {
                        l(0, {
                            storageCertIdx: g,
                            encMsg: e.stringResult
                        });
                        return
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_IrosSign"), {
                            errCode: n,
                            errMsg: e.errMsg
                        });
                        return
                    }
                })
            } else {
                g.storageOpt.pfxOpt.pfxPasswd = a;
                Storage_API_pfx.GetCertString(g, function(o, n) {
                    if (o == 0) {
                        var e = n.cert;
                        c = encodeUtf8Hex(c);
                        j.sign(e.signcert, e.signpri, a, c, d, function(p, q) {
                            if (p == 0) {
                                l(0, q)
                            } else {
                                l(ML4WebLog.getErrCode("Storage_pfx_IrosSign"), {
                                    errCode: o,
                                    errMsg: n.errMsg
                                })
                            }
                        })
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_IrosSign"), {
                            errCode: o,
                            errMsg: n.errMsg
                        })
                    }
                })
            }
        }
    },
    IrosAddSignData: function(g, d, a, c, l) {
        ML4WebLog.log("Storage_API_pfx.IrosAddSign() called... storageRawCertIdx === " + JSON.stringify(g));
        ML4WebLog.log("Storage_API_pfx.IrosAddSign() called... libType === " + g.storageOpt.pfxOpt.libType);
        if (g.storageOpt.pfxOpt.libType == "c") {
            var k = ML4WebApi.getResourceApi();
            var f = ML4WebApi.getProperty("CsUrl");
            c = encodeUtf8andBase64(c);
            var m = k.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(d)), a, c);
            var b = ML4WebApi.getCsManager();
            try {
                b.callLocalServerAPI(f, m, function(n, p) {
                    ML4WebLog.log("Storage_API_pfx.IrosAddSign() httpRequest callback code ===" + n);
                    if (n == 0) {
                        var e = JSON.parse(p);
                        if (e.ResultCode == 0) {
                            ML4WebLog.log("IrosAddSign result === " + e.ResultMessage);
                            var o = JSON.parse(e.ResultMessage);
                            l(0, {
                                storageCertIdx: g,
                                encMsg: o.encMsg
                            });
                            return
                        } else {
                            l(ML4WebLog.getErrCode("Storage_pfx_IrosAddSign"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_IrosAddSign"), {
                            errCode: n,
                            errMsg: p.ResultMessage
                        })
                    }
                })
            } catch (h) {
                l(ML4WebLog.getErrCode("Storage_pfx_IrosAddSign"), {
                    errCode: 888,
                    errMsg: h.message
                });
                return
            }
        } else {
            var j = ML4WebApi.getCryptoApi();
            if (selectCertString.length != 0) {
                j.sign(selectCertString.signcert, selectCertString.signpri, a, c, d, function(n, e) {
                    if (n == 0) {
                        l(0, {
                            storageCertIdx: g,
                            encMsg: e.stringResult
                        });
                        return
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_IrosAddSign"), {
                            errCode: n,
                            errMsg: e.errMsg
                        });
                        return
                    }
                })
            } else {
                g.storageOpt.pfxOpt.pfxPasswd = a;
                Storage_API_pfx.GetCertString(g, function(o, n) {
                    if (o == 0) {
                        var e = n.cert;
                        c = encodeUtf8Hex(c);
                        j.sign(e.signcert, e.signpri, a, c, d, function(p, q) {
                            if (p == 0) {
                                l(0, q)
                            } else {
                                l(ML4WebLog.getErrCode("Storage_pfx_IrosAddSign"), {
                                    errCode: o,
                                    errMsg: n.errMsg
                                })
                            }
                        })
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_IrosAddSign"), {
                            errCode: o,
                            errMsg: n.errMsg
                        })
                    }
                })
            }
        }
    },
    IrosMultiSign: function(g, d, a, b) {
        ML4WebLog.log("Storage_API_pfx.IrosMultiSign() called... storageRawCertIdx === " + JSON.stringify(g));
        ML4WebLog.log("Storage_API_pfx.IrosMultiSign() called... libType === " + g.storageOpt.pfxOpt.libType);
        if (g.storageOpt.pfxOpt.libType == "c") {
            var k = ML4WebApi.getResourceApi();
            var f = ML4WebApi.getProperty("CsUrl");
            b = encodeUtf8andBase64(b);
            var m = k.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(d)), a, b);
            var c = ML4WebApi.getCsManager();
            try {
                c.callLocalServerAPI(f, m, function(n, p) {
                    ML4WebLog.log("Storage_API_pfx.IrosSign() httpRequest callback code ===" + n);
                    if (n == 0) {
                        var e = JSON.parse(p);
                        if (e.ResultCode == 0) {
                            ML4WebLog.log("sign result === " + e.ResultMessage);
                            var o = JSON.parse(e.ResultMessage);
                            return {
                                code: 0,
                                data: o.encMsg
                            }
                        } else {
                            return {
                                code: ML4WebLog.getErrCode("Storage_pfx_IrosSign"),
                                data: {
                                    errCode: e.ResultCode,
                                    errMsg: e.ResultMessage
                                }
                            }
                        }
                    } else {
                        return {
                            code: ML4WebLog.getErrCode("Storage_pfx_IrosSign"),
                            data: {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            }
                        }
                    }
                })
            } catch (h) {
                return {
                    code: ML4WebLog.getErrCode("Storage_pfx_IrosSign"),
                    data: {
                        errCode: 888,
                        errMsg: h.message
                    }
                }
            }
        } else {
            var j = ML4WebApi.getCryptoApi();
            if (selectCertString.length != 0) {
                var l = j.sign(selectCertString.signcert, selectCertString.signpri, a, b, d);
                return l
            } else {
                g.storageOpt.pfxOpt.pfxPasswd = a;
                Storage_API_pfx.GetCertString(g, function(p, o) {
                    if (p == 0) {
                        var n = o.cert;
                        var e = j.sign(n.signcert, n.signpri, a, b, d);
                        return e
                    } else {
                        return {
                            code: ML4WebLog.getErrCode("Storage_pfx_IrosSign"),
                            data: {
                                errCode: p,
                                errMsg: o.errMsg
                            }
                        }
                    }
                })
            }
        }
    },
    IrosMultiAddSign: function(g, d, a, b) {
        ML4WebLog.log("Storage_API_pfx.IrosMultiAddSign() called... storageRawCertIdx === " + JSON.stringify(g));
        ML4WebLog.log("Storage_API_pfx.IrosMultiAddSign() called... libType === " + g.storageOpt.pfxOpt.libType);
        if (g.storageOpt.pfxOpt.libType == "c") {
            var k = ML4WebApi.getResourceApi();
            var f = ML4WebApi.getProperty("CsUrl");
            b = encodeUtf8andBase64(b);
            var m = k.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(d)), a, b);
            var c = ML4WebApi.getCsManager();
            try {
                c.callLocalServerAPI(f, m, function(n, p) {
                    ML4WebLog.log("Storage_API_pfx.IrosAddSign() httpRequest callback code ===" + n);
                    if (n == 0) {
                        var e = JSON.parse(p);
                        if (e.ResultCode == 0) {
                            ML4WebLog.log("IrosAddSign result === " + e.ResultMessage);
                            var o = JSON.parse(e.ResultMessage);
                            callback(0, {
                                storageCertIdx: g,
                                encMsg: o.encMsg
                            });
                            return
                        } else {
                            callback(ML4WebLog.getErrCode("Storage_pfx_IrosAddSign"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    } else {
                        callback(ML4WebLog.getErrCode("Storage_pfx_IrosAddSign"), {
                            errCode: n,
                            errMsg: p.ResultMessage
                        })
                    }
                })
            } catch (h) {
                callback(ML4WebLog.getErrCode("Storage_pfx_IrosAddSign"), {
                    errCode: 888,
                    errMsg: h.message
                });
                return
            }
        } else {
            var j = ML4WebApi.getCryptoApi();
            if (selectCertString.length != 0) {
                var l = j.sign(selectCertString.signcert, selectCertString.signpri, a, b, d);
                return l
            } else {
                g.storageOpt.pfxOpt.pfxPasswd = a;
                Storage_API_pfx.GetCertString(g, function(p, o) {
                    var n = o.cert;
                    var e = j.sign(n.signcert, n.signpri, a, b, d);
                    return e
                })
            }
        }
    },
    SingedEnvelopedData: function(h, d, f, a, c, l) {
        ML4WebLog.log("Storage_API_pfx.SingedEnvelopedData() called...");
        if (h.storageOpt.pfxOpt.libType == "c") {
            var k = ML4WebApi.getResourceApi();
            var g = ML4WebApi.getProperty("CsUrl");
            c = encodeUtf8andBase64(c);
            var m = k.makeJsonMessage("SingedEnvelopedData", encodeURIComponent(JSON.stringify(h)), d, encodeURIComponent(JSON.stringify(f)), a, c);
            var b = ML4WebApi.getCsManager();
            try {
                b.callLocalServerAPI(g, m, function(n, p) {
                    if (n == 0) {
                        var e = JSON.parse(p);
                        if (e.ResultCode == 0) {
                            var o = JSON.parse(e.ResultMessage);
                            l(0, {
                                storageCertIdx: h,
                                encData: o.encMsg
                            });
                            return
                        } else {
                            l(ML4WebLog.getErrCode("Storage_pfx_SingedEnvelopedData"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    } else {
                        l(ML4WebLog.getErrCode("Storage_pfx_SingedEnvelopedData"), {
                            errCode: n,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            } catch (j) {
                l(ML4WebLog.getErrCode("Storage_pfx_SingedEnvelopedData"), {
                    errCode: 888,
                    errMsg: j.message
                });
                return
            }
        } else {
            if (true) {
                l(0, {
                    "sign message": "[some value...]"
                })
            } else {
                l(ML4WebLog.getErrCode("Storage_pfx_SingedEnvelopedData"), {
                    errCode: 201,
                    errMsg: $.i18n.prop("ER201")
                })
            }
        }
    }
};
var Storage_API_hdd = {
    SelectStorageInfo: function(b, j) {
        var h = ML4WebApi.getResourceApi();
        var f = ML4WebApi.getProperty("cs_timeout");
        var d = ML4WebApi.getProperty("CsUrl");
        var c = h.makeJsonMessage("SelectStorageInfo", b);
        var a = ML4WebApi.getCsManager();
        try {
            a.callLocalServerAPI(d, c, function(k, m) {
                if (k == 0) {
                    var e = JSON.parse(m);
                    if (e.ResultCode == 0) {
                        var l = JSON.parse(e.ResultMessage);
                        j(0, l);
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_hdd_SelectStorageInfo"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(k, m)
                }
            })
        } catch (g) {
            j(ML4WebLog.getErrCode("Storage_hdd_SelectStorageInfo"), {
                errCode: 888,
                errMsg: g.message
            });
            return
        }
    },
    GetCertList: function(f, h) {
        ML4WebLog.log("Storage_API_hdd.GetCertList() called...");
        var g = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var b = g.makeJsonMessage("GetCertList", encodeURIComponent(JSON.stringify(f)));
        var a = ML4WebApi.getCsManager();
        try {
            a.callLocalServerAPI(c, b, function(j, l) {
                if (j == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        var k = JSON.parse(e.ResultMessage);
                        h(0, k);
                        return
                    } else {
                        h(ML4WebLog.getErrCode("Storage_hdd_GetCertList"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    h(ML4WebLog.getErrCode("Storage_hdd_GetCertList"), {
                        errCode: j,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (d) {
            h(ML4WebLog.getErrCode("Storage_hdd_GetCertList"), {
                errCode: 888,
                errMsg: d.message
            });
            return
        }
    },
    GetCertString: function(f, h) {
        ML4WebLog.log("Storage_API_hdd.GetCertString() called...");
        var g = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var b = g.makeJsonMessage("GetCertString", encodeURIComponent(JSON.stringify(f)));
        var a = ML4WebApi.getCsManager();
        try {
            a.callLocalServerAPI(c, b, function(j, l) {
                if (j == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        var k = JSON.parse(e.ResultMessage);
                        h(0, {
                            cert: k.cert_string
                        });
                        return
                    } else {
                        h(ML4WebLog.getErrCode("Storage_hdd_GetCertString"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    h(ML4WebLog.getErrCode("Storage_hdd_GetCertString"), {
                        errCode: j,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (d) {
            h(ML4WebLog.getErrCode("Storage_hdd_GetCertString"), {
                errCode: 888,
                errMsg: d.message
            });
            return
        }
    },
    GetDetailCert: function(g, a, j) {
        ML4WebLog.log("Storage_API_hdd.GetDetailCert() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var c = h.makeJsonMessage("GetDetailCert", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(a)));
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(d, c, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, {
                            result: JSON.parse(e.ResultMessage)
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_hdd_GetDetailCert"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_hdd_GetDetailCert"), {
                        errCode: k,
                        errMsg: l.ResultMessage
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_hdd_GetDetailCert"), {
                errCode: 888,
                errMsg: f.message
            });
            return
        }
    },
    SaveCert: function(f, a, j, h) {
        ML4WebLog.log("Storage_API_hdd.SaveCert() called");
        var g = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var k = g.makeJsonMessage("SaveCert", encodeURIComponent(JSON.stringify(f)), encodeURIComponent(a), encodeURIComponent(JSON.stringify(j)));
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(c, k, function(l, m) {
                if (l == 0) {
                    var e = JSON.parse(m);
                    if (e.ResultCode == 0) {
                        h(0, {
                            result: true
                        })
                    } else {
                        h(ML4WebLog.getErrCode("Storage_hdd_SaveCert"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        })
                    }
                } else {
                    h(ML4WebLog.getErrCode("Storage_hdd_SaveCert"), {
                        errCode: l,
                        errMsg: $.i18n.prop("ES023")
                    })
                }
            })
        } catch (d) {
            h(ML4WebLog.getErrCode("Storage_hdd_SaveCert"), {
                errCode: 888,
                errMsg: d.message
            })
        }
    },
    DeleteCert: function(f, h) {
        ML4WebLog.log("Storage_API_hdd.DeleteCert() called...");
        var g = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var b = g.makeJsonMessage("DeleteCert", encodeURIComponent(JSON.stringify(f)));
        var a = ML4WebApi.getCsManager();
        try {
            a.callLocalServerAPI(c, b, function(j, k) {
                if (j == 0) {
                    var e = JSON.parse(k);
                    if (e.ResultCode == 0) {
                        h(0, {
                            result: true
                        });
                        return
                    } else {
                        h(ML4WebLog.getErrCode("Storage_hdd_DeleteCert"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    h(ML4WebLog.getErrCode("Storage_hdd_DeleteCert"), {
                        errCode: j,
                        errMsg: $.i18n.prop("ES017")
                    })
                }
            })
        } catch (d) {
            h(ML4WebLog.getErrCode("Storage_hdd_DeleteCert"), {
                errCode: 888,
                errMsg: d.message
            });
            return
        }
    },
    ChangePassword: function(d, g, b, j) {
        ML4WebLog.log("Storage_API_hdd.ChangePassword() called...");
        var h = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var k = h.makeJsonMessage("ChangePassword", encodeURIComponent(JSON.stringify(d)), encodeURIComponent(g), encodeURIComponent(b));
        var a = ML4WebApi.getCsManager();
        try {
            a.callLocalServerAPI(c, k, function(l, m) {
                if (l == 0) {
                    var e = JSON.parse(m);
                    if (e.ResultCode == 0) {
                        j(0, {
                            result: true
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_hdd_ChangePassword"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_hdd_ChangePassword"), {
                        errCode: l,
                        errMsg: $.i18n.prop("TS021")
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_hdd_ChangePassword"), {
                errCode: 888,
                errMsg: f.message
            });
            return
        }
    },
    verifyVID: function(f, a, c, j) {
        ML4WebLog.log("Storage_API_hdd.verifyVID() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var k = h.makeJsonMessage("VerifyVID", encodeURIComponent(JSON.stringify(f)), encodeURIComponent(a), c, ML4WebApi.HDSDOption.kOption, "");
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(d, k, function(l, m) {
                if (l == 0) {
                    var e = JSON.parse(m);
                    if (e.ResultCode == 0) {
                        j(0, {
                            result: true
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_hdd_verifyVID"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_hdd_verifyVID"), {
                        errCode: l,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (g) {
            j(ML4WebLog.getErrCode("Storage_hdd_verifyVID"), {
                errCode: 888,
                errMsg: g.message
            });
            return
        }
    },
    getVIDRandom: function(g, b, j) {
        ML4WebLog.log("Storage_API_hdd.getVIDRandom() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var c = h.makeJsonMessage("GetVIDRandom", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(b), ML4WebApi.HDSDOption.kOption, "");
        var a = ML4WebApi.getCsManager();
        try {
            a.callLocalServerAPI(d, c, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, {
                            VIDRandom: e.ResultMessage
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_hdd_getVIDRandom"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_hdd_getVIDRandom"), {
                        errCode: k,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_hdd_getVIDRandom"), {
                errCode: 888,
                errMsg: f.message
            });
            return
        }
    },
    getVIDRandomHash: function(f, a, d, k) {
        ML4WebLog.log("Storage_API_hdd.getVIDRandomHash() called...");
        var g = false;
        var b = Storage_API_web.getML4WebCert();
        var c = b != null ? JSON.parse(b) : [];
        var h = {};
        var j = ML4WebApi.getCryptoApi();
        for (var e = 0; e < c.length; e++) {
            if (c[e].storageCertIdx == f.storageCertIdx) {
                h = c[e];
                g = true
            }
        }
        if (g) {
            j.getVIDRandomHash(h.signcert, h.signpri, encodeURIComponent(a), d, function(m, l) {
                if (m == 0) {
                    k(0, {
                        VIDRandomHash: l.result
                    })
                } else {
                    k(ML4WebLog.getErrCode("Storage_hdd_getVIDRandomHash"), {
                        errCode: m,
                        errMsg: $.i18n.prop("ES022")
                    })
                }
            })
        } else {
            k(ML4WebLog.getErrCode("Storage_hdd_getVIDRandomHash"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    Sign: function(g, d, a, c, k) {
        ML4WebLog.log("Storage_API_hdd.Sign() called...");
        ML4WebLog.log("callback === " + typeof k);
        c = encodeUtf8andBase64(c);
        var j = ML4WebApi.getResourceApi();
        var f = ML4WebApi.getProperty("CsUrl");
        var l = j.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(d)), encodeURIComponent(a), c, ML4WebApi.HDSDOption.kOption, ML4WebApi.HDSDOption.eOption);
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(f, l, function(m, n) {
                if (m == 0) {
                    var e = JSON.parse(n);
                    if (e.ResultCode == 0) {
                        Storage_API_hdd.GetCertString(g, function(o, q) {
                            if (o == 0) {
                                var p = JSON.parse(e.ResultMessage);
                                k(0, {
                                    storageCertIdx: g,
                                    encMsg: p.encMsg,
                                    userCert: q.cert.signcert
                                })
                            } else {
                                k(ML4WebLog.getErrCode("Storage_hdd_Sign"), {
                                    errCode: q.errCode,
                                    errMsg: q.errMsg
                                })
                            }
                        })
                    } else {
                        k(ML4WebLog.getErrCode("Storage_hdd_Sign"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        })
                    }
                } else {
                    k(ML4WebLog.getErrCode("Storage_hdd_Sign"), {
                        errCode: m,
                        errMsg: $.i18n.prop("ES024")
                    })
                }
            })
        } catch (h) {
            k(ML4WebLog.getErrCode("Storage_hdd_Sign"), {
                errCode: 888,
                errMsg: h.message
            });
            return
        }
    },
    Signature: function(d, b, a, c, e) {
        Storage_API_hdd.Sign(d, b, a, c, e)
    },
    IrosSign: function(g, d, a, c, k) {
        ML4WebLog.log("Storage_API_hdd.Sign() called...");
        ML4WebLog.log("callback === " + typeof k);
        c = magicjs.base64.encode(c);
        d.ds_pki_sign_type = "";
        var j = ML4WebApi.getResourceApi();
        var f = ML4WebApi.getProperty("CsUrl");
        var l = j.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(d)), encodeURIComponent(a), c, ML4WebApi.HDSDOption.kOption, ML4WebApi.HDSDOption.eOption);
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(f, l, function(m, o) {
                ML4WebLog.log("Storage_API_hdd.Sign() callback resultCode=" + m);
                ML4WebLog.log("Storage_API_hdd.Sign() callback obj =" + o);
                if (m == 0) {
                    var e = JSON.parse(o);
                    if (e.ResultCode == 0) {
                        ML4WebLog.log("sign result === " + e.ResultMessage);
                        var n = JSON.parse(e.ResultMessage);
                        k(0, {
                            storageCertIdx: g,
                            encMsg: n.encMsg
                        });
                        return
                    } else {
                        ML4WebLog.log("callback errCode =" + e.ResultCode);
                        k(ML4WebLog.getErrCode("Storage_hdd_Sign"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    k(ML4WebLog.getErrCode("Storage_hdd_Sign"), {
                        errCode: m,
                        errMsg: $.i18n.prop("ES024")
                    })
                }
            })
        } catch (h) {
            k(ML4WebLog.getErrCode("Storage_hdd_Sign"), {
                errCode: 888,
                errMsg: h.message
            });
            return
        }
    },
    IrosAddSignData: function(g, d, a, c, k) {
        ML4WebLog.log("Storage_API_hdd.IrosAddSign() called...");
        ML4WebLog.log("callback === " + typeof k);
        c = magicjs.base64.encode(c);
        d.ds_pki_sign_type = "";
        var j = ML4WebApi.getResourceApi();
        var f = ML4WebApi.getProperty("CsUrl");
        var l = j.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(d)), encodeURIComponent(a), c, ML4WebApi.HDSDOption.kOption, ML4WebApi.HDSDOption.eOption);
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(f, l, function(m, o) {
                ML4WebLog.log("Storage_API_hdd.IrosAddSign() callback resultCode=" + m);
                ML4WebLog.log("Storage_API_hdd.IrosAddSign() callback obj =" + o);
                if (m == 0) {
                    var e = JSON.parse(o);
                    if (e.ResultCode == 0) {
                        ML4WebLog.log("IrosAddSign result === " + e.ResultMessage);
                        var n = JSON.parse(e.ResultMessage);
                        k(0, {
                            storageCertIdx: g,
                            encMsg: n.encMsg
                        });
                        return
                    } else {
                        ML4WebLog.log("callback errCode =" + e.ResultCode);
                        k(ML4WebLog.getErrCode("Storage_hdd_IrosAddSign"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    k(ML4WebLog.getErrCode("Storage_hdd_IrosAddSign"), {
                        errCode: m,
                        errMsg: $.i18n.prop("ES024")
                    })
                }
            })
        } catch (h) {
            k(ML4WebLog.getErrCode("Storage_hdd_IrosAddSign"), {
                errCode: 888,
                errMsg: h.message
            });
            return
        }
    },
    IrosMultiSign: function(h, f, a, b) {
        ML4WebLog.log("Storage_API_hdd.IrosMultiSign() called...");
        b = magicjs.base64.encode(b);
        f.ds_pki_sign_type = "";
        var k = ML4WebApi.getResourceApi();
        var g = ML4WebApi.getProperty("CsUrl");
        var n = k.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(h)), encodeURIComponent(JSON.stringify(f)), encodeURIComponent(a), b, ML4WebApi.HDSDOption.kOption, ML4WebApi.HDSDOption.eOption);
        var c = ML4WebApi.getCsManager();
        try {
            var l = k.irosRequset(g, false, n);
            var m = JSON.parse(l);
            var d = JSON.parse(m.ResultMessage);
            if (m.ResultCode == 0) {
                return {
                    code: 0,
                    data: d.encMsg
                }
            } else {
                return {
                    code: ML4WebLog.getErrCode("Storage_hdd_IrosMultiSign"),
                    data: {
                        errCode: m.ResultCode,
                        errMsg: d.encMsg
                    }
                }
            }
        } catch (j) {
            return {
                code: ML4WebLog.getErrCode("Storage_hdd_IrosMultiSign"),
                data: {
                    errCode: 888,
                    errMsg: j.message
                }
            }
        }
    },
    IrosMultiAddSign: function(h, f, a, b) {
        ML4WebLog.log("Storage_API_hdd.IrosMultiAddSign() called...");
        b = magicjs.base64.encode(b);
        f.ds_pki_sign_type = "";
        var k = ML4WebApi.getResourceApi();
        var g = ML4WebApi.getProperty("CsUrl");
        var n = k.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(h)), encodeURIComponent(JSON.stringify(f)), encodeURIComponent(a), b, ML4WebApi.HDSDOption.kOption, ML4WebApi.HDSDOption.eOption);
        var c = ML4WebApi.getCsManager();
        try {
            var l = k.irosRequset(g, false, n);
            var m = JSON.parse(l);
            var d = JSON.parse(m.ResultMessage);
            if (m.ResultCode == 0) {
                return {
                    code: 0,
                    data: d.encMsg
                }
            } else {
                return {
                    code: ML4WebLog.getErrCode("Storage_hdd_IrosMultiAddSign"),
                    data: {
                        errCode: m.ResultCode,
                        errMsg: d.encMsg
                    }
                }
            }
        } catch (j) {
            callback(ML4WebLog.getErrCode("Storage_hdd_IrosMultiAddSign"), {
                errCode: 888,
                errMsg: j.message
            });
            return
        }
    },
    SingedEnvelopedData: function(h, d, f, a, c, l) {
        ML4WebLog.log("Storage_API_hdd.SingedEnvelopedData() called...");
        var k = ML4WebApi.getResourceApi();
        var g = ML4WebApi.getProperty("CsUrl");
        c = encodeUtf8andBase64(c);
        var m = k.makeJsonMessage("SingedEnvelopedData", encodeURIComponent(JSON.stringify(h)), d, encodeURIComponent(JSON.stringify(f)), a, c, ML4WebApi.HDSDOption.kOption, "");
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(g, m, function(n, p) {
                if (n == 0) {
                    var e = JSON.parse(p);
                    if (e.ResultCode == 0) {
                        var o = JSON.parse(e.ResultMessage);
                        l(0, {
                            storageCertIdx: h,
                            encData: o.encMsg
                        });
                        return
                    } else {
                        l(ML4WebLog.getErrCode("Storage_hdd_SingedEnvelopedData"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    l(ML4WebLog.getErrCode("Storage_hdd_SingedEnvelopedData"), {
                        errCode: n,
                        errMsg: $.i18n.prop("ES024")
                    })
                }
            })
        } catch (j) {
            l(ML4WebLog.getErrCode("Storage_hdd_SingedEnvelopedData"), {
                errCode: 888,
                errMsg: j.message
            });
            return
        }
    }
};
var Storage_API_token = {
    SelectStorageInfo: function(b, h) {
        ML4WebLog.log("Storage_API_token.SelectStorageInfo() called...");
        var g = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var c = g.makeJsonMessage("SelectStorageInfo", b);
        var a = ML4WebApi.getCsManager();
        try {
            a.callLocalServerAPI(d, c, function(s, o) {
                if (s == 0) {
                    var t = JSON.parse(o);
                    if (t.ResultCode == 0) {
                        var l = JSON.parse(t.ResultMessage);
                        var r = {};
                        if (t.ResultMessage.indexOf("USIM_0002") < 0) {
                            var e = {};
                            e.tokenname = "Mobile_SmartCert";
                            e.driver = "USIM_0002";
                            e.driverPath = "";
                            r.tokenOpt = [];
                            r.tokenOpt.push(e)
                        }
                        if (l.tokenOpt.length > 0) {
                            if (r.tokenOpt == null) {
                                r = l
                            } else {
                                for (var p = 0; p < l.tokenOpt.length; p++) {
                                    r.tokenOpt.push(l.tokenOpt[p])
                                }
                            }
                            var q = ML4WebApi.getProperty("token_filter").length;
                            if (q > 0) {
                                for (var n = 0; n < r.tokenOpt.length; n++) {
                                    for (var m = 0; m < q; m++) {
                                        if (r.tokenOpt[n].tokenname == ML4WebApi.getProperty("token_filter")[m]) {
                                            r.tokenOpt.splice(n, 1);
                                            break
                                        }
                                    }
                                }
                            }
                        }
                        h(0, r);
                        return
                    } else {
                        h(ML4WebLog.getErrCode("Storage_token_SelectStorageInfo"), {
                            errCode: t.ResultCode,
                            errMsg: t.ResultMessage
                        });
                        return
                    }
                } else {
                    h(s, {
                        errCode: s,
                        errMsg: JSON.stringify(o)
                    })
                }
            })
        } catch (f) {
            h(ML4WebLog.getErrCode("Storage_token_SelectStorageInfo"), {
                errCode: 201,
                errMsg: f.message
            });
            return
        }
    },
    GetCertList: function(f, h) {
        ML4WebLog.log("Storage_API_token.GetCertList() called...");
        var g = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var b = g.makeJsonMessage("GetCertList", encodeURIComponent(JSON.stringify(f)));
        try {
            var a = ML4WebApi.getCsManager();
            a.callLocalServerAPI(c, b, function(j, l) {
                if (j == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        var k = JSON.parse(e.ResultMessage);
                        h(0, k);
                        return
                    } else {
                        h(ML4WebLog.getErrCode("Storage_token_GetCertList"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    h(ML4WebLog.getErrCode("Storage_token_GetCertList"), {
                        errCode: j,
                        errMsg: $.i18n.prop("ES025")
                    })
                }
            })
        } catch (d) {
            h(ML4WebLog.getErrCode("Storage_token_GetCertList"), {
                errCode: 888,
                errMsg: d.message
            });
            return
        }
    },
    GetCertString: function(f, h) {
        ML4WebLog.log("Storage_API_token.GetCertString() called...");
        var g = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var b = g.makeJsonMessage("GetCertString", encodeURIComponent(JSON.stringify(f)));
        try {
            var a = ML4WebApi.getCsManager();
            a.callLocalServerAPI(c, b, function(j, l) {
                if (j == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        var k = JSON.parse(e.ResultMessage);
                        h(0, {
                            cert: k.cert_string
                        })
                    } else {
                        h(ML4WebLog.getErrCode("Storage_token_GetCertString"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        })
                    }
                } else {
                    h(ML4WebLog.getErrCode("Storage_token_GetCertString"), {
                        errCode: j,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (d) {
            h(ML4WebLog.getErrCode("Storage_token_GetCertString"), {
                errCode: 888,
                errMsg: d.message
            })
        }
    },
    GetDetailCert: function(g, a, j) {
        ML4WebLog.log("Storage_API_token.GetDetailCert() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var c = h.makeJsonMessage("GetDetailCert", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(a)));
        try {
            var b = ML4WebApi.getCsManager();
            b.callLocalServerAPI(d, c, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, {
                            result: JSON.parse(e.ResultMessage)
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_token_GetDetailCert"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_token_GetDetailCert"), {
                        errCode: k,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_token_GetDetailCert"), {
                errCode: 888,
                errMsg: f.message
            });
            return
        }
    },
    SaveCert: function(f, a, j, h) {
        ML4WebLog.log("Storage_API_token.SaveCert() called");
        var g = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var k = g.makeJsonMessage("SaveCert", encodeURIComponent(JSON.stringify(f)), a, encodeURIComponent(JSON.stringify(j)));
        try {
            var b = ML4WebApi.getCsManager();
            b.callLocalServerAPI(c, k, function(l, m) {
                if (l == 0) {
                    var e = JSON.parse(m);
                    if (e.ResultCode == 0) {
                        h(0, e.ResultMessage);
                        return
                    } else {
                        h(ML4WebLog.getErrCode("Storage_API_token_SaveCert"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    h(ML4WebLog.getErrCode("Storage_token_GetDetailCert"), {
                        errCode: l,
                        errMsg: $.i18n.prop("ES023")
                    })
                }
            })
        } catch (d) {
            h(ML4WebLog.getErrCode("Storage_token_SaveCert"), {
                errCode: 888,
                errMsg: d.message
            });
            return
        }
    },
    DeleteCert_Token: function(g, b, j) {
        ML4WebLog.log("Storage_API_token.DeleteCert_Token() called");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var c = h.makeJsonMessage("DeleteCert", encodeURIComponent(JSON.stringify(g)), b);
        try {
            var a = ML4WebApi.getCsManager();
            a.callLocalServerAPI(d, c, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, {
                            result: true
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_token_DeleteCert_Token"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_token_DeleteCert_Token"), {
                        errCode: k,
                        errMsg: $.i18n.prop("ES017")
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_token_DeleteCert"), {
                errCode: 888,
                errMsg: f.message
            });
            return
        }
    },
    ChangePassword: function(d, g, b, j) {
        ML4WebLog.log("Storage_API_token.ChangePassword() called...");
        var h = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var k = h.makeJsonMessage("ChangePassword", encodeURIComponent(JSON.stringify(d)), g, b);
        try {
            var a = ML4WebApi.getCsManager();
            a.callLocalServerAPI(c, k, function(l, m) {
                if (l == 0) {
                    var e = JSON.parse(m);
                    if (e.ResultCode == 0) {
                        j(0, {
                            result: true
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_token_ChangePassword"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_token_ChangePassword"), {
                        errCode: l,
                        errMsg: $.i18n.prop("TS021")
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_token_ChangePassword"), {
                errCode: 888,
                errMsg: f.message
            });
            return
        }
    },
    verifyVID: function(f, a, c, j) {
        ML4WebLog.log("Storage_API_token.verifyVID() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var k = h.makeJsonMessage("VerifyVID", encodeURIComponent(JSON.stringify(f)), a, c);
        try {
            var b = ML4WebApi.getCsManager();
            b.callLocalServerAPI(d, k, function(l, m) {
                if (l == 0) {
                    var e = JSON.parse(m);
                    if (e.ResultCode == 0) {
                        j(0, {
                            result: true
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_token_verifyVID"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_token_verifyVID"), {
                        errCode: l,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (g) {
            j(ML4WebLog.getErrCode("Storage_token_verifyVID"), {
                errCode: 888,
                errMsg: g.message
            });
            return
        }
    },
    getVIDRandom: function(g, b, j) {
        ML4WebLog.log("Storage_API_token.getVIDRandom() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var c = h.makeJsonMessage("GetVIDRandom", encodeURIComponent(JSON.stringify(g)), b, ML4WebApi.HDSDOption.kOption, "");
        try {
            var a = ML4WebApi.getCsManager();
            a.callLocalServerAPI(d, c, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, {
                            VIDRandom: e.ResultMessage
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_token_getVIDRandom"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_token_getVIDRandom"), {
                        errCode: k,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_token_getVIDRandom"), {
                errCode: 888,
                errMsg: f.message
            });
            return
        }
    },
    getVIDRandomHash: function(f, a, d, l) {
        ML4WebLog.log("Storage_API_token.getVIDRandomHash() called...");
        var h = false;
        var b = Storage_API_web.getML4WebCert();
        var c = b != null ? JSON.parse(b) : [];
        var j = {};
        var k = ML4WebApi.getCryptoApi();
        var g = c.length;
        for (var e = 0; e < g; e++) {
            if (c[e].storageCertIdx == f.storageCertIdx) {
                j = c[e];
                h = true
            }
        }
        if (h) {
            k.getVIDRandomHash(j.signcert, j.signpri, a, d, function(n, m) {
                if (n == 0) {
                    l(0, {
                        VIDRandomHash: result.ResultMessage
                    })
                } else {
                    l(ML4WebLog.getErrCode("Storage_token_getVIDRandomHash"), {
                        errCode: n,
                        errMsg: $.i18n.prop("ES022")
                    })
                }
            })
        } else {
            l(ML4WebLog.getErrCode("Storage_token_getVIDRandomHash"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    Sign: function(l, h, b, d, p) {
        ML4WebLog.log("Storage_API_token.Sign() called...");
        var o = ML4WebApi.getResourceApi();
        var j = ML4WebApi.getProperty("CsUrl");
        var a = "";
        if (typeof(d) == "object" && typeof(d.length) != "undefined") {
            var g = new Array();
            for (var f = 0; f < d.length; f++) {
                g.push(encodeUtf8andBase64(d[f]))
            }
            a = encodeURIComponent(JSON.stringify(g))
        } else {
            if (typeof(d) == "object" && typeof(d.length) == "undefined") {
                var g = new Object();
                g = d.constructor();
                for (var n in d) {
                    if (d.hasOwnProperty(n)) {
                        g[n] = d[n]
                    }
                }
                for (var f = 0; f < Object.keys(g).length; f++) {
                    var k = Object.keys(g)[f];
                    g[k] = encodeUtf8andBase64(g[k])
                }
                a = encodeURIComponent(JSON.stringify(g))
            } else {
                a = encodeUtf8andBase64(d)
            }
        }
        var q = o.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(l)), encodeURIComponent(JSON.stringify(h)), b, a, ML4WebApi.HDSDOption.kOption, "");
        try {
            var c = ML4WebApi.getCsManager();
            c.callLocalServerAPI(j, q, function(r, s) {
                if (r == 0) {
                    var e = JSON.parse(s);
                    if (e.ResultCode == 0) {
                        Storage_API_token.GetCertString(l, function(t, v) {
                            if (t == 0) {
                                var u = {
                                    storageName: l.storageName,
                                    tokenOpt: l.storageOpt.tokenOpt
                                };
                                Storage_API_token.GetCertList(u, function(w, z) {
                                    var y = l.storageCertIdx;
                                    if (w == 0) {
                                        magiclineUtil.StartClickEvt();
                                        var x = JSON.parse(e.ResultMessage);
                                        p(0, {
                                            storageCertIdx: l,
                                            certInfo: z.cert_list[y],
                                            certbag: v.cert,
                                            encMsg: x.encMsg,
                                            userCert: v.cert.signcert,
                                            serialnum: z.cert_list[y].serialnum,
                                            subjectname: z.cert_list[y].subjectname
                                        })
                                    } else {
                                        magiclineUtil.StartClickEvt();
                                        p(ML4WebLog.getErrCode("Storage_token_Sign"), {
                                            errCode: z.errCode,
                                            errMsg: z.errMsg
                                        })
                                    }
                                })
                            } else {
                                magiclineUtil.StartClickEvt();
                                p(ML4WebLog.getErrCode("Storage_token_Sign"), {
                                    errCode: v.errCode,
                                    errMsg: v.errMsg
                                })
                            }
                        })
                    } else {
                        magiclineUtil.StartClickEvt();
                        p(ML4WebLog.getErrCode("Storage_token_Sign"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        })
                    }
                } else {
                    magiclineUtil.StartClickEvt();
                    p(ML4WebLog.getErrCode("Storage_token_Sign"), {
                        errCode: r,
                        errMsg: $.i18n.prop("ES024")
                    })
                }
            })
        } catch (m) {
            magiclineUtil.StartClickEvt();
            p(ML4WebLog.getErrCode("Storage_token_Sign"), {
                errCode: 888,
                errMsg: m.message
            });
            return
        }
    },
    Signature: function(d, b, a, c, e) {
        Storage_API_token.Sign(d, b, a, c, e)
    },
    SingedEnvelopedData: function(h, d, f, a, c, l) {
        ML4WebLog.log("Storage_API_token.SingedEnvelopedData() called...");
        var k = ML4WebApi.getResourceApi();
        var g = ML4WebApi.getProperty("CsUrl");
        c = encodeUtf8andBase64(c);
        var m = k.makeJsonMessage("SingedEnvelopedData", encodeURIComponent(JSON.stringify(h)), d, encodeURIComponent(JSON.stringify(f)), a, c);
        try {
            var b = ML4WebApi.getCsManager();
            b.callLocalServerAPI(g, m, function(n, p) {
                if (n == 0) {
                    var e = JSON.parse(p);
                    if (e.ResultCode == 0) {
                        var o = JSON.parse(e.ResultMessage);
                        l(0, {
                            "envelop message": o.encMsg
                        });
                        return
                    } else {
                        l(ML4WebLog.getErrCode("Storage_token_SingedEnvelopedData"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    l(ML4WebLog.getErrCode("Storage_token_SingedEnvelopedData"), {
                        errCode: n,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (j) {
            l(ML4WebLog.getErrCode("Storage_token_SingedEnvelopedData"), {
                errCode: 888,
                errMsg: j.message
            });
            return
        }
    }
};
var Storage_API_mobile = {
    ubiCert: "",
    ubiPri: "",
    SelectStorageInfo: function(b, g) {
        ML4WebLog.log("Storage_API_mobile.SelectStorageInfo() called...");
        var e = {};
        if (true) {
            var f = ML4WebApi.getResourceApi();
            var d = ML4WebApi.getProperty("CsUrl");
            var c = f.makeJsonMessage("SelectStorageInfo", b);
            var a = ML4WebApi.getCsManager();
            a.callLocalServerAPI(d, c, function(j, l) {
                if (j == 0) {
                    if (l != "" && l != null) {
                        var h = JSON.parse(l);
                        if (h.ResultCode == 0) {
                            var k = {
                                phoneOpt: [{
                                    serviceOpt: {
                                        UbikeyWParam: "DREAMSECURITY|NULL",
                                        UbikeylParam: "DREAMSECURITY|NULL",
                                        popupURL: "http://www.ubikey.co.kr/infovine/download.html",
                                        version: "1.4.0.2"
                                    },
                                    servicename: "ubikey"
                                }, {
                                    serviceOpt: {
                                        popupURL: "https://ni.ubikey.co.kr",
                                    },
                                    servicename: "ubikeynx"
                                }, {
                                    serviceOpt: {
                                        popupURL: "https://mobi.yessign.or.kr/mobisignInstall.htm",
                                        siteCode: "6070059",
                                        version: "5.0.4.9"
                                    },
                                    servicename: "mobisign"
                                }, {
                                    serviceOpt: {
                                        USIMRaonSiteCode: "609100003",
                                        USIMServerIP: "center.smartcert.kr",
                                        USIMServerPort: 443,
                                        USIMSiteDomain: "www.dreamsecurity.com"
                                    },
                                    servicename: "dreamCS"
                                }]
                            };
                            g(0, k);
                            return
                        } else {
                            g(ML4WebLog.getErrCode("Storage_API_mobile_SelectStorageInfo"), {
                                errCode: h.ResultCode,
                                errMsg: h.ResultMessage
                            });
                            return
                        }
                    } else {
                        var k = {
                            phoneOpt: [{
                                serviceOpt: {
                                    UbikeyWParam: "DREAMSECURITY|NULL",
                                    UbikeylParam: "DREAMSECURITY|NULL",
                                    popupURL: "http://www.ubikey.co.kr/infovine/download.html",
                                    version: "1.4.0.2"
                                },
                                servicename: "ubikey"
                            }, {
                                serviceOpt: {
                                    popupURL: "https://ni.ubikey.co.kr",
                                },
                                servicename: "ubikeynx"
                            }, {
                                serviceOpt: {
                                    popupURL: "https://mobi.yessign.or.kr/mobisignInstall.htm",
                                    siteCode: "6070059",
                                    version: "5.0.4.9"
                                },
                                servicename: "mobisign"
                            }, {
                                serviceOpt: {
                                    USIMRaonSiteCode: "609100003",
                                    USIMServerIP: "center.smartcert.kr",
                                    USIMServerPort: 443,
                                    USIMSiteDomain: "www.dreamsecurity.com"
                                },
                                servicename: "dreamCS"
                            }]
                        };
                        g(0, k);
                        return
                    }
                } else {
                    g(j, l)
                }
            })
        } else {
            g(ML4WebLog.getErrCode("Storage_mobile_SelectStorageInfo"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    GetCertList: function(k, j) {
        ML4WebLog.log("Storage_API_mobile.GetCertList() called...");
        var c = [];
        var b;
        var f;
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        if (k.phoneOpt.servicename.indexOf("ubikeynx") > -1) {
            Tranx2pc(function(m, n) {
                var e = [];
                var o = ML4WebApi.getCryptoApi();
                o.getcertInfo(m, e, function(r, q) {
                    if (r == "0") {
                        if (ML4WebApi.getProperty("libType") == 0) {
                            q.result = q
                        }
                        var p = {
                            storageName: "mobile",
                            storageOpt: {}
                        };
                        p.storageCertIdx = q.result.subkeyid;
                        Storage_API_web.selectCertIdx = q.result.subkeyid;
                        Storage_API_mobile.ubiCert = m;
                        Storage_API_mobile.ubiPri = n;
                        q.result.storageRawCertIdx = p;
                        c[0] = q.result;
                        if (c.length > 0) {
                            j(0, {
                                cert_list: c
                            })
                        }
                    } else {
                        j(ML4WebLog.getErrCode("Storage_Web_GetCertList"), {
                            errCode: r,
                            errMsg: q
                        })
                    }
                })
            })
        } else {
            if (typeof(k.phoneOpt.serviceOpt.UbikeyWParam) != "undefined") {
                k.phoneOpt.servicename = "ubikey";
                b = {
                    CS_UBIKEY_wParam: k.phoneOpt.serviceOpt.UbikeyWParam
                };
                f = h.makeJsonMessage("SetProperty", encodeURIComponent(JSON.stringify(b)))
            } else {
                b = {
                    CS_UBIKEY_wParam: "DREAMSECURITY|NULL"
                };
                f = h.makeJsonMessage("SetProperty", encodeURIComponent(JSON.stringify(b)))
            }
        }
        var l = h.makeJsonMessage("GetCertList", encodeURIComponent(JSON.stringify(k)));
        var a = ML4WebApi.getCsManager();
        try {
            a.callLocalServerAPI(d, f, function(m, e) {
                a.callLocalServerAPI(d, l, function(o, q) {
                    if (o == 0) {
                        var n = JSON.parse(q);
                        if (n.ResultCode == 0) {
                            var p = JSON.parse(n.ResultMessage);
                            j(0, p);
                            return
                        } else {
                            j(ML4WebLog.getErrCode("Storage_mobile_GetCertList"), {
                                errCode: n.ResultCode,
                                errMsg: n.ResultMessage
                            });
                            return
                        }
                    } else {
                        j(ML4WebLog.getErrCode("Storage_mobile_GetCertList"), {
                            errCode: 201,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            })
        } catch (g) {
            j(ML4WebLog.getErrCode("Storage_mobile_GetCertList"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    },
    GetCertString: function(g, j) {
        ML4WebLog.log("Storage_API_mobile.GetCertString() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var c = h.makeJsonMessage("GetCertString", encodeURIComponent(JSON.stringify(g)));
        var b = ML4WebApi.getCsManager();
        if (Storage_API_mobile.ubiCert !== "" && Storage_API_mobile.ubiPri !== "") {
            var a = {
                signcert: Storage_API_mobile.ubiCert,
                signpri: Storage_API_mobile.ubiPri
            };
            j(0, {
                cert: a
            })
        }
        try {
            b.callLocalServerAPI(d, c, function(k, m) {
                if (k == 0) {
                    var e = JSON.parse(m);
                    if (e.ResultCode == 0) {
                        var l = JSON.parse(e.ResultMessage);
                        j(0, {
                            cert: l.cert_string
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_mobile_GetCertString"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_mobile_GetCertString"), {
                        errCode: k,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_mobile_GetCertString"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    },
    GetDetailCert: function(g, a, j) {
        ML4WebLog.log("Storage_API_mobile.GetDetailCert() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var c = h.makeJsonMessage("GetDetailCert", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(a)));
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(d, c, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, {
                            result: JSON.parse(e.ResultMessage)
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_mobile_GetDetailCert"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_mobile_GetDetailCert"), {
                        errCode: k,
                        errMsg: l.ResultMessage
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_mobile_GetDetailCert"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    },
    SaveCert: function(d, a, g, j) {
        ML4WebLog.log("Storage_API_mobile.SaveCert() called");
        var h = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var b = h.makeJsonMessage("SaveCert", encodeURIComponent(JSON.stringify(d)), a, encodeURIComponent(JSON.stringify(g)));
        try {
            h.httpRequest(c, false, b, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, e.ResultMessage);
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_mobile_SaveCert"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_mobile_SaveCert"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    },
    DeleteCert: function(a, b) {
        ML4WebLog.log("Storage_API_mobile.DeleteCert() called");
        b(ML4WebLog.getErrCode("Storage_mobile_DeleteCert"), {
            errCode: 101,
            errMsg: $.i18n.prop("ER101")
        })
    },
    ChangePassword: function(c, b, a, d) {
        ML4WebLog.log("Storage_API_mobile.ChangePassword() called...");
        if (true) {
            d(0, {
                result: true
            })
        } else {
            d(ML4WebLog.getErrCode("Storage_mobile_ChangePassword"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    verifyVID: function(f, a, c, j) {
        ML4WebLog.log("Storage_API_mobile.verifyVID() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        var k = h.makeJsonMessage("VerifyVID", encodeURIComponent(JSON.stringify(f)), a, c);
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(d, k, function(l, m) {
                if (l == 0) {
                    var e = JSON.parse(m);
                    if (e.ResultCode == 0) {
                        j(0, {
                            result: true
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_mobile_verifyVID"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_mobile_verifyVID"), {
                        errCode: l,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (g) {
            j(ML4WebLog.getErrCode("Storage_mobile_verifyVID"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    },
    getVIDRandom: function(g, b, j) {
        ML4WebLog.log("Storage_API_mobile.getVIDRandom() called...");
        var h = ML4WebApi.getResourceApi();
        var d = ML4WebApi.getProperty("CsUrl");
        if (b == "mobisign") {
            var c = h.makeJsonMessage("GetVIDRandom", encodeURIComponent(JSON.stringify(g)), b, "", "")
        } else {
            var c = h.makeJsonMessage("GetVIDRandom", encodeURIComponent(JSON.stringify(g)), b, ML4WebApi.HDSDOption.kOption, "")
        }
        var a = ML4WebApi.getCsManager();
        try {
            a.callLocalServerAPI(d, c, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, {
                            VIDRandom: e.ResultMessage
                        });
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_API_mobile_getVIDRandom"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    j(ML4WebLog.getErrCode("Storage_API_mobile_getVIDRandom"), {
                        errCode: k,
                        errMsg: $.i18n.prop("ER201")
                    })
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_mobile_getVIDRandom"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    },
    getVIDRandomHash: function(c, a, b, d) {
        ML4WebLog.log("Storage_API_mobile.getVIDRandomHash() called...");
        if (true) {
            d(0, {
                VIDRandom: "[some value...]"
            })
        } else {
            d(ML4WebLog.getErrCode("Storage_mobile_getVIDRandomHash"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    Sign: function(l, h, b, d, p) {
        ML4WebLog.log("Storage_API_mobile.Sign() called...");
        var o = ML4WebApi.getResourceApi();
        var j = ML4WebApi.getProperty("CsUrl");
        var a = "";
        if (typeof(d) == "object" && typeof(d.length) != "undefined") {
            var g = new Array();
            for (var f = 0; f < d.length; f++) {
                g.push(encodeUtf8andBase64(d[f]))
            }
            a = encodeURIComponent(JSON.stringify(g))
        } else {
            if (typeof(d) == "object" && typeof(d.length) == "undefined") {
                var g = new Object();
                g = d.constructor();
                for (var n in d) {
                    if (d.hasOwnProperty(n)) {
                        g[n] = d[n]
                    }
                }
                for (var f = 0; f < Object.keys(g).length; f++) {
                    var k = Object.keys(g)[f];
                    g[k] = encodeUtf8andBase64(g[k])
                }
                a = encodeURIComponent(JSON.stringify(g))
            } else {
                a = encodeUtf8andBase64(d)
            }
        }
        if (b == "mobisign") {
            var q = o.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(l)), encodeURIComponent(JSON.stringify(h)), b, a, "", "")
        } else {
            var q = o.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(l)), encodeURIComponent(JSON.stringify(h)), b, a, ML4WebApi.HDSDOption.kOption, "")
        }
        var c = ML4WebApi.getCsManager();
        try {
            c.callLocalServerAPI(j, q, function(r, s) {
                if (r == 0) {
                    var e = JSON.parse(s);
                    if (e.ResultCode == 0) {
                        Storage_API_mobile.GetCertString(l, function(t, v) {
                            if (t == 0) {
                                if (b == "mobisign") {
                                    l = l.storageOpt;
                                    l.storageOpt = null;
                                    Storage_API_mobile.GetCertList(l, function(w, y) {
                                        if (w == 0) {
                                            var x = JSON.parse(e.ResultMessage);
                                            p(0, {
                                                storageCertIdx: l,
                                                certInfo: y.cert_list[0],
                                                certbag: v.cert,
                                                encMsg: x.encMsg,
                                                userCert: v.cert.signcert,
                                                serialnum: y.cert_list[0].serialnum,
                                                subjectname: y.cert_list[0].subjectname
                                            })
                                        } else {
                                            p(ML4WebLog.getErrCode("Storage_mobile_Sign"), {
                                                errCode: y.errCode,
                                                errMsg: y.errMsg
                                            })
                                        }
                                    })
                                } else {
                                    if (t == 0) {
                                        var u = JSON.parse(e.ResultMessage);
                                        p(0, {
                                            storageCertIdx: l,
                                            encMsg: u.encMsg,
                                            userCert: v.cert.signcert
                                        })
                                    } else {
                                        p(ML4WebLog.getErrCode("Storage_mobile_Sign"), {
                                            errCode: v.errCode,
                                            errMsg: v.errMsg
                                        })
                                    }
                                }
                            } else {
                                p(ML4WebLog.getErrCode("Storage_mobile_Sign"), {
                                    errCode: v.errCode,
                                    errMsg: v.errMsg
                                })
                            }
                        })
                    } else {
                        p(ML4WebLog.getErrCode("Storage_API_mobile_Sign"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        })
                    }
                } else {
                    p(ML4WebLog.getErrCode("Storage_API_mobile_Sign"), {
                        errCode: r,
                        errMsg: $.i18n.prop("ES024")
                    })
                }
            })
        } catch (m) {
            p(ML4WebLog.getErrCode("Storage_mobile_Sign"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    },
    Signature: function(d, b, a, c, e) {
        Storage_API_mobile.Sign(d, b, a, c, e)
    },
    SingedEnvelopedData: function(h, d, f, a, c, l) {
        ML4WebLog.log("Storage_API_mobile.SingedEnvelopedData() called...");
        var k = ML4WebApi.getResourceApi();
        var g = ML4WebApi.getProperty("CsUrl");
        c = encodeUtf8andBase64(c);
        var m = k.makeJsonMessage("SingedEnvelopedData", encodeURIComponent(JSON.stringify(h)), d, encodeURIComponent(JSON.stringify(f)), a, c);
        var b = ML4WebApi.getCsManager();
        try {
            b.callLocalServerAPI(g, m, function(n, p) {
                if (n == 0) {
                    var e = JSON.parse(p);
                    if (e.ResultCode == 0) {
                        var o = JSON.parse(e.ResultMessage);
                        l(0, {
                            storageCertIdx: h,
                            encData: o.encMsg
                        });
                        return
                    } else {
                        l(ML4WebLog.getErrCode("Storage_mobile_SingedEnvelopedData"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                } else {
                    l(ML4WebLog.getErrCode("Storage_mobile_SingedEnvelopedData"), {
                        errCode: n,
                        errMsg: $.i18n.prop("ES024")
                    })
                }
            })
        } catch (j) {
            l(ML4WebLog.getErrCode("Storage_mobile_SingedEnvelopedData"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    }
};
var Storage_API_smartcert = {
    SelectStorageInfo: function(k, j) {
        ML4WebLog.log("Storage_API_smartcert.SelectStorageInfo() called...");
        var a = {};
        var b = {
            USIMServerIP: "",
            USIMServerPort: "",
            USIMSiteDomain: "",
            USIMRaonSiteCode: "",
            USIMInstallURL: "",
            USIMTokenInstallURL: ""
        };
        var d = {
            mobileConnURL: "",
            cryptoAPI: "",
            signScheme: "",
            encScheme: "",
            mdAlg: ""
        };
        a = {
            smartCertOpt: {
                servicename: "dreamWeb",
                serviceOpt: d
            }
        };
        try {
            if (ML4WebApi.getProperty("smartcert_type") == "C") {
                var h = ML4WebApi.getResourceApi();
                var f = ML4WebApi.getProperty("CsUrl");
                var l = h.makeJsonMessage("SelectStorageInfo", k);
                var c = ML4WebApi.getCsManager();
                c.callLocalServerAPI(f, l, function(m, o) {
                    if (m == 0) {
                        var e = JSON.parse(o);
                        if (e.ResultCode == 0) {
                            var n = JSON.parse(e.ResultMessage);
                            j(0, n);
                            return
                        } else {
                            j(ML4WebLog.getErrCode("Storage_smartcert_SelectStorageInfo"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    } else {
                        j(m, o)
                    }
                })
            } else {
                var d = {
                    mobileConnURL: "",
                    cryptoAPI: "",
                    signScheme: "",
                    encScheme: "",
                    mdAlg: ""
                };
                a = {
                    servicename: "dreamWeb",
                    serviceOpt: d
                };
                j(0, a)
            }
        } catch (g) {
            j(ML4WebLog.getErrCode("Storage_smartcert_SelectStorageInfo"), {
                errCode: result.ResultCode,
                errMsg: result.ResultMessage
            });
            return
        }
    },
    GetCertList: function(d, g) {
        ML4WebLog.log("Storage_API_smartcert.GetCertList() called...");
        if (true) {
            var f = ML4WebApi.getResourceApi();
            var b = ML4WebApi.getProperty("CsUrl");
            var a = f.makeJsonMessage("GetCertList", encodeURIComponent(JSON.stringify(d)));
            try {
                f.httpRequest(b, false, a, function(h, k) {
                    if (h == 0) {
                        var e = JSON.parse(k);
                        if (e.ResultCode == 0) {
                            var j = JSON.parse(e.ResultMessage);
                            g(0, j);
                            return
                        } else {
                            g(ML4WebLog.getErrCode("Storage_smartcert_GetCertList"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    }
                })
            } catch (c) {
                g(ML4WebLog.getErrCode("Storage_smartcert_GetCertList"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        } else {
            g(ML4WebLog.getErrCode("Storage_smartcert_GetCertList"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    GetCertString: function(d, g) {
        ML4WebLog.log("Storage_API_smartcert.GetCertString() called...");
        if (true) {
            var f = ML4WebApi.getResourceApi();
            var b = ML4WebApi.getProperty("CsUrl");
            var a = f.makeJsonMessage("GetCertString", encodeURIComponent(JSON.stringify(d)));
            try {
                f.httpRequest(b, false, a, function(h, k) {
                    if (h == 0) {
                        var e = JSON.parse(k);
                        if (e.ResultCode == 0) {
                            var j = JSON.parse(e.ResultMessage);
                            g(0, {
                                cert: j.cert_string
                            });
                            return
                        } else {
                            g(ML4WebLog.getErrCode("Storage_smartcert_GetCertString"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    }
                })
            } catch (c) {
                g(ML4WebLog.getErrCode("Storage_smartcert_GetCertString"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        } else {
            g(ML4WebLog.getErrCode("Storage_smartcert_GetCertString"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    GetDetailCert: function(g, a, j) {
        ML4WebLog.log("Storage_API_smartcert.GetDetailCert() called...");
        if (true) {
            var h = ML4WebApi.getResourceApi();
            var c = ML4WebApi.getProperty("CsUrl");
            if (typeof(g.storageCertIdx) == "undefined") {
                g.storageCertIdx = ""
            }
            if (g.storageOpt.servicename == "smartcertWEB") {
                var f = ML4WebApi.getCryptoApi();
                certInfo = f.getcertInfo(g.storageCertIdx, a, function(k, l) {
                    if (l != null) {
                        var e = {};
                        j(0, l)
                    } else {
                        j(ML4WebLog.getErrCode("Storage_Web_GetDetailCert"), {
                            errCode: 201,
                            errMsg: $.i18n.prop("ER201")
                        })
                    }
                })
            } else {
                var b = h.makeJsonMessage("GetDetailCert", encodeURIComponent(JSON.stringify(g)), encodeURIComponent(JSON.stringify(a)));
                try {
                    h.httpRequest(c, false, b, function(k, l) {
                        if (k == 0) {
                            var e = JSON.parse(l);
                            if (e.ResultCode == 0) {
                                j(0, {
                                    result: JSON.parse(e.ResultMessage)
                                });
                                return
                            } else {
                                j(ML4WebLog.getErrCode("Storage_smartcert_GetDetailCert"), {
                                    errCode: e.ResultCode,
                                    errMsg: e.ResultMessage
                                });
                                return
                            }
                        }
                    })
                } catch (d) {
                    j(ML4WebLog.getErrCode("Storage_smartcert_GetDetailCert"), {
                        errCode: 888,
                        errMsg: d.message
                    });
                    return
                }
            }
        } else {
            j(ML4WebLog.getErrCode("Storage_smartcert_GetDetailCert"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    SaveCert: function(d, a, g, j) {
        ML4WebLog.log("Storage_API_smartcert.SaveCert() called");
        var h = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var b = h.makeJsonMessage("SaveCert", encodeURIComponent(JSON.stringify(d)), a, encodeURIComponent(JSON.stringify(g)));
        try {
            h.httpRequest(c, false, b, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, e.ResultMessage);
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_smartcert_SaveCert"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_smartcert_SaveCert"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    },
    DeleteCert: function(d, g) {
        ML4WebLog.log("Storage_API_smartcert.DeleteCert() called");
        if (true) {
            var f = ML4WebApi.getResourceApi();
            var b = ML4WebApi.getProperty("CsUrl");
            var a = f.makeJsonMessage("DeleteCert", encodeURIComponent(JSON.stringify(d)), passwd);
            try {
                f.httpRequest(b, false, a, function(h, j) {
                    if (h == 0) {
                        var e = JSON.parse(j);
                        if (e.ResultCode == 0) {
                            g(0, {
                                result: true
                            });
                            return
                        } else {
                            g(ML4WebLog.getErrCode("Storage_smartcert_DeleteCert"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    }
                })
            } catch (c) {
                g(ML4WebLog.getErrCode("Storage_smartcert_DeleteCert"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        } else {
            g(ML4WebLog.getErrCode("Storage_smartcert_DeleteCert"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    ChangePassword: function(g, b, a, j) {
        ML4WebLog.log("Storage_API_smartcert.ChangePassword() called...");
        if (true) {
            var h = ML4WebApi.getResourceApi();
            var d = ML4WebApi.getProperty("CsUrl");
            var c = h.makeJsonMessage("ChangePassword", encodeURIComponent(JSON.stringify(g)), b, a);
            try {
                h.httpRequest(d, false, c, function(k, l) {
                    if (k == 0) {
                        var e = JSON.parse(l);
                        if (e.ResultCode == 0) {
                            j(0, {
                                result: true
                            });
                            return
                        } else {
                            j(ML4WebLog.getErrCode("Storage_smartcert_ChangePassword"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    }
                })
            } catch (f) {
                j(ML4WebLog.getErrCode("Storage_smartcert_ChangePassword"), {
                    errCode: 888,
                    errMsg: f.message
                });
                return
            }
        } else {
            j(ML4WebLog.getErrCode("Storage_smartcert_ChangePassword"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    verifyVID: function(g, a, d, j) {
        ML4WebLog.log("Storage_API_smartcert.verifyVID() called...");
        if (true) {
            var h = ML4WebApi.getResourceApi();
            var c = ML4WebApi.getProperty("CsUrl");
            var b = h.makeJsonMessage("VerifyVID", encodeURIComponent(JSON.stringify(g)), a, d);
            try {
                h.httpRequest(c, false, b, function(k, l) {
                    if (k == 0) {
                        var e = JSON.parse(l);
                        if (e.ResultCode == 0) {
                            j(0, {
                                result: true
                            });
                            return
                        } else {
                            j(ML4WebLog.getErrCode("Storage_smartcert_verifyVID"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    }
                })
            } catch (f) {
                j(ML4WebLog.getErrCode("Storage_smartcert_verifyVID"), {
                    errCode: 888,
                    errMsg: f.message
                });
                return
            }
        } else {
            j(ML4WebLog.getErrCode("Storage_smartcert_verifyVID"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    getVIDRandom: function(f, a, h) {
        ML4WebLog.log("Storage_API_smartcert.getVIDRandom() called...");
        if (true) {
            var g = ML4WebApi.getResourceApi();
            var c = ML4WebApi.getProperty("CsUrl");
            var b = g.makeJsonMessage("GetVIDRandom", encodeURIComponent(JSON.stringify(f)), a);
            try {
                g.httpRequest(c, false, b, function(j, k) {
                    if (j == 0) {
                        var e = JSON.parse(k);
                        if (e.ResultCode == 0) {
                            h(0, {
                                VIDRandom: e.ResultMessage
                            });
                            return
                        } else {
                            h(ML4WebLog.getErrCode("Storage_smartcert_getVIDRandom"), {
                                errCode: e.ResultCode,
                                errMsg: e.ResultMessage
                            });
                            return
                        }
                    }
                })
            } catch (d) {
                h(ML4WebLog.getErrCode("Storage_smartcert_getVIDRandom"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        } else {
            h(ML4WebLog.getErrCode("Storage_smartcert_getVIDRandom"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    getVIDRandomHash: function(f, a, d, k) {
        ML4WebLog.log("Storage_API_smartcert.getVIDRandomHash() called...");
        var g = false;
        var b = Storage_API_web.getML4WebCert();
        var c = b != null ? JSON.parse(b) : [];
        var h = {};
        var j = ML4WebApi.getCryptoApi();
        for (var e = 0; e < c.length; e++) {
            if (c[e].storageCertIdx == f.storageCertIdx) {
                h = c[e];
                g = true
            }
        }
        if (g) {
            j.getVIDRandomHash(h.signcert, h.signpri, a, d, function(m, l) {
                if (m == 0) {
                    k(0, l.result)
                } else {
                    k(ML4WebLog.getErrCode("Storage_smartcert_getVIDRandomHash"), {
                        errCode: m,
                        errMsg: $.i18n.prop("ES022")
                    })
                }
            })
        } else {
            k(ML4WebLog.getErrCode("Storage_smartcert_getVIDRandomHash"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    Sign: function(k, g, b, c, o) {
        ML4WebLog.log("Storage_API_smartcert.Sign() called...");
        var n = ML4WebApi.getResourceApi();
        var h = ML4WebApi.getProperty("CsUrl");
        var a = "";
        if (typeof(c) == "object" && typeof(c.length) != "undefined") {
            var f = new Array();
            for (var d = 0; d < c.length; d++) {
                f.push(encodeUtf8andBase64(c[d]))
            }
            a = encodeURIComponent(JSON.stringify(f))
        } else {
            if (typeof(c) == "object" && typeof(c.length) == "undefined") {
                var f = new Object();
                f = c.constructor();
                for (var m in c) {
                    if (c.hasOwnProperty(m)) {
                        f[m] = c[m]
                    }
                }
                for (var d = 0; d < Object.keys(f).length; d++) {
                    var j = Object.keys(f)[d];
                    f[j] = encodeUtf8andBase64(f[j])
                }
                a = encodeURIComponent(JSON.stringify(f))
            } else {
                a = encodeUtf8andBase64(c)
            }
        }
        if (g.errCode == 30055) {
            k.storageOpt.smartCertOpt.VerifySignature = false;
            var p = n.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(k)), encodeURIComponent(JSON.stringify(g)), b, a)
        } else {
            k.storageOpt.smartCertOpt.VerifySignature = true;
            var p = n.makeJsonMessage("Sign", encodeURIComponent(JSON.stringify(k)), encodeURIComponent(JSON.stringify(g)), b, a)
        }
        try {
            n.httpRequest(h, false, p, function(q, r) {
                if (q == 0) {
                    var e = JSON.parse(r);
                    if (e.ResultCode == 0) {
                        Storage_API_smartcert.GetCertString(k, function(s, t) {
                            if (s == 0) {
                                Storage_API_smartcert.GetCertList(k, function(u, w) {
                                    if (u == 0) {
                                        var v = JSON.parse(e.ResultMessage);
                                        if (typeof(v.randomNum) == "undefined") {
                                            o(0, {
                                                storageCertIdx: k,
                                                certInfo: w.cert_list[0],
                                                certbag: t.cert,
                                                encMsg: v.encMsg,
                                                userCert: t.cert.signcert,
                                                serialnum: w.cert_list[0].serialnum,
                                                subjectname: w.cert_list[0].subjectname
                                            })
                                        } else {
                                            o(0, {
                                                storageCertIdx: k,
                                                certInfo: w.cert_list[0],
                                                certbag: t.cert,
                                                randomNum: v.randomNum,
                                                encMsg: v.encMsg,
                                                userCert: t.cert.signcert,
                                                serialnum: w.cert_list[0].serialnum,
                                                subjectname: w.cert_list[0].subjectname
                                            })
                                        }
                                    } else {
                                        o(ML4WebLog.getErrCode("Storage_smartcert_Sign"), {
                                            errCode: t.errCode,
                                            errMsg: t.errMsg
                                        })
                                    }
                                })
                            } else {
                                o(ML4WebLog.getErrCode("Storage_smartcert_Sign"), {
                                    errCode: t.errCode,
                                    errMsg: t.errMsg
                                })
                            }
                        })
                    } else {
                        o(ML4WebLog.getErrCode("Storage_smartcert_Sign"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        })
                    }
                }
            })
        } catch (l) {
            o(ML4WebLog.getErrCode("Storage_smartcert_Sign"), {
                errCode: result.ResultCode,
                errMsg: result.ResultMessage
            });
            return
        }
    },
    Signature: function(d, b, a, c, e) {
        Storage_API_smartcert.Sign(d, b, a, c, e)
    },
    SingedEnvelopedData: function(g, c, d, a, b, k) {
        ML4WebLog.log("Storage_API_smartcert.SingedEnvelopedData() called...");
        var j = ML4WebApi.getResourceApi();
        var f = ML4WebApi.getProperty("CsUrl");
        b = encodeUtf8andBase64(b);
        var l = j.makeJsonMessage("SingedEnvelopedData", encodeURIComponent(JSON.stringify(g)), c, encodeURIComponent(JSON.stringify(d)), a, b);
        try {
            j.httpRequest(f, false, l, function(m, o) {
                if (m == 0) {
                    var e = JSON.parse(o);
                    if (e.ResultCode == 0) {
                        var n = JSON.parse(e.ResultMessage);
                        k(0, {
                            storageCertIdx: g,
                            encData: n.encMsg
                        });
                        return
                    } else {
                        k(ML4WebLog.getErrCode("Storage_smartcert_SingedEnvelopedData"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                }
            })
        } catch (h) {
            k(ML4WebLog.getErrCode("Storage_smartcert_SingedEnvelopedData"), {
                errCode: result.ResultCode,
                errMsg: result.ResultMessage
            });
            return
        }
    }
};
var Storage_API_smartcertnx = {
    pkcs7: function pkcs7(e, g, f, b) {
        var o = "RSASSA-PKCS1-V1_5";
        var h = "SHA256";
        var m = "";
        var j = magicjs.x509Cert.create(e);
        var n = magicjs.pkcs7.signedData.create();
        var d = {};
        var l = {};
        var a = null;
        if (typeof(f) == "undefined" || f == null) {
            m = magicjs.pkcs7.signedData.format.useContentInfo
        } else {
            if (typeof(f.sign) == "object") {
                m = magicjs.pkcs7.signedData.format.none;
                for (var c = 0; c < f.sign.length; c++) {
                    if (f.sign[c].toUpperCase() === "OPT_NONE") {
                        m = m | magicjs.pkcs7.signedData.format.none
                    } else {
                        if (f.sign[c].toUpperCase() === "OPT_USE_CONTNET_INFO") {
                            m = m | magicjs.pkcs7.signedData.format.useContentInfo
                        } else {
                            if (f.sign[c].toUpperCase() === "OPT_NO_CONTENT") {
                                m = m | magicjs.pkcs7.signedData.format.noContent
                            } else {
                                if (f.sign[c].toUpperCase() === "OPT_SIGNKOREA_FORMAT") {
                                    m = m | magicjs.pkcs7.signedData.format.signGateFormat
                                } else {
                                    if (f.sign[c].toUpperCase() === "OPT_HASHED_CONTENT") {
                                        m = m | magicjs.pkcs7.signedData.format.hashedContent
                                    } else {
                                        if (f.sign[c].toUpperCase() === "OPT_NO_SIGNEDATTRIBUTES") {
                                            m = m | magicjs.pkcs7.signedData.format.noSignedAttributes
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (m & magicjs.pkcs7.signedData.format.hashedContent) {
            g = magicjs.hex.decode(g)
        } else {
            if (f != null && typeof(f) != "undefined" && typeof(f.sign) != "undefined" && f.sign.indexOf("TBS_ENCODE_HEX") > -1) {
                g = magicjs.hex.decode(g)
            } else {
                if (f != null && typeof(f) != "undefined" && typeof(f.sign) != "undefined" && f.sign.indexOf("TBS_ENCODE_BASE64") > -1) {
                    g = magicjs.base64.decode(g)
                } else {
                    g = g
                }
            }
            m = m | magicjs.pkcs7.signedData.format.noSignedAttributes
        }
        d.signingTime = a;
        d.format = m;
        var k = n.makeTBSData(g, h, d);
        l.scheme = o;
        l.md = h;
        l.cert = j;
        l.format = m;
        n.compose(1, l, g, k, magicjs.base64.decode(b));
        var p = magicjs.base64.encode(n.toDer());
        return p
    },
    makePKCS1: function(m, c, e, k) {
        var j = new JS_Crypto_API();
        var d = [];
        var g = {};
        var l = {};
        var h = new Array();
        var f = new Array();
        if (typeof(m) == "string") {
            d.push(magicjs.utf8.encode(m))
        } else {
            if (typeof(m) == "object" && m instanceof Array) {
                for (var b = 0; b < m.length; b++) {
                    d.push(magicjs.utf8.encode(m[b]))
                }
            }
        }
        for (var b = 0; b < d.length; b++) {
            h[b] = "3031300d060960864801650304020105000420" + j.genHash("sha256", d[b]).resulthex;
            f[b] = {};
            f[b].msg = magicjs.base64.encode(h[b]);
            l[b] = {};
            l[b].signOrgView = false;
            l[b].plainText = d[b]
        }
        g = f;
        var a = jSmartCertNP.Sign({
            siteDomain: ConfigObject.CS_SMARTCERT_SiteDomain,
            msgType: "originHash",
            msg: JSON.stringify(g),
            msgIntegrity: JSON.stringify(l),
            signedDataType: "signature",
            multisignYn: "N",
            serial: e,
            randomChk: true,
            complete: function(p) {
                try {
                    var n = JSON.parse(p);
                    if (n.returnObj.returnCode == "0") {
                        k(n.signResult.b64SignedData)
                    } else {
                        k(false, n.returnObj.returnMsg + "(" + n.returnObj.returnCode + ")")
                    }
                } catch (o) {
                    k(false, o.message)
                }
            }
        });
        a.Open()
    },
    makePKCS7: function(n, d, f, l) {
        var k = new JS_Crypto_API();
        var a = 0;
        var e = [];
        var h = {};
        var m = {};
        var j = new Array();
        var g = new Array();
        if (typeof(n) == "string") {
            e.push(magicjs.utf8.encode(n))
        } else {
            if (typeof(n) == "object" && n instanceof Array) {
                a = 1;
                for (var c = 0; c < n.length; c++) {
                    e.push(magicjs.utf8.encode(n[c]))
                }
            }
        }
        for (var c = 0; c < e.length; c++) {
            if (d != null && typeof(d) != "undefined" && typeof(d.sign) != "undefined" && d.sign.indexOf("OPT_HASHED_CONTENT") > -1) {
                j[c] = "3031300d060960864801650304020105000420" + e[c]
            } else {
                if (d != null && typeof(d) != "undefined" && typeof(d.sign) != "undefined" && d.sign.indexOf("TBS_ENCODE_HEX") > -1) {
                    j[c] = "3031300d060960864801650304020105000420" + k.genHash("sha256", magicjs.hex.decode(e[c])).resulthex
                } else {
                    if (d != null && typeof(d) != "undefined" && typeof(d.sign) != "undefined" && d.sign.indexOf("TBS_ENCODE_BASE64") > -1) {
                        j[c] = "3031300d060960864801650304020105000420" + k.genHash("sha256", magicjs.base64.decode(e[c])).resulthex
                    } else {
                        j[c] = "3031300d060960864801650304020105000420" + k.genHash("sha256", e[c]).resulthex
                    }
                }
            }
            g[c] = {};
            g[c].msg = magicjs.base64.encode(j[c]);
            m[c] = {};
            m[c].signOrgView = false;
            m[c].plainText = e[c]
        }
        h = g;
        var b = jSmartCertNP.Sign({
            siteDomain: ConfigObject.CS_SMARTCERT_SiteDomain,
            msgType: "originHash",
            msg: JSON.stringify(h),
            msgIntegrity: JSON.stringify(m),
            signedDataType: "signature",
            multisignYn: "N",
            serial: f,
            randomChk: true,
            complete: function(t) {
                try {
                    var o = JSON.parse(t);
                    if (o.returnObj.returnCode == "0") {
                        var s = o.signResult.b64Signer;
                        var p = [];
                        for (var r = 0; r < o.signResult.b64SignedData.length; r++) {
                            p[r] = Storage_API_smartcertnx.pkcs7(s, e[r], d, o.signResult.b64SignedData[r])
                        }
                        if (a == 0) {
                            l(p[0])
                        } else {
                            l(p)
                        }
                    } else {
                        l(false, o.returnObj.returnMsg + "(" + o.returnObj.returnCode + ")")
                    }
                } catch (q) {
                    l(false, q.message)
                }
            }
        });
        b.Open()
    },
    SelectStorageInfo: function(a, f) {
        ML4WebLog.log("Storage_API_smartcertnx.SelectStorageInfo() called...");
        var d = {};
        var b = {
            mobileConnURL: "",
            cryptoAPI: "",
            signScheme: "",
            encScheme: "",
            mdAlg: ""
        };
        d = {
            smartCertOpt: {
                servicename: "dreamWeb",
                serviceOpt: b
            }
        };
        try {
            var b = {
                mobileConnURL: "",
                cryptoAPI: "",
                signScheme: "",
                encScheme: "",
                mdAlg: ""
            };
            d = {
                servicename: "dreamWeb",
                serviceOpt: b
            };
            f(0, d)
        } catch (c) {
            f(ML4WebLog.getErrCode("Storage_smartcertnx_SelectStorageInfo"), {
                errCode: result.ResultCode,
                errMsg: result.ResultMessage
            });
            return
        }
    },
    getVIDRandom: function(d, b, f) {
        ML4WebLog.log("Storage_API_smartcertnx.getVIDRandom() called...");
        try {
            if (ML4WebApi.webConfig.getRandomfromPrivateKey != null && ML4WebApi.webConfig.getRandomfromPrivateKey != "") {
                var a = {};
                a.VIDRandom = ML4WebApi.webConfig.getRandomfromPrivateKey;
                f(0, a)
            } else {
                f(ML4WebLog.getErrCode("Storage_smartcertnx_getVIDRandom"), "")
            }
            return
        } catch (c) {
            f(33333, "");
            return
        }
    },
    Sign: function(g, l, r, h, f) {
        ML4WebLog.log("Storage_API_smartcertnx.Sign() called...");
        var k = new JS_Crypto_API();
        var t = "signature";
        var n = "originHash";
        var o = magiclineUtil.getTimeStamp();
        var m;
        if (typeof(h) == "string") {
            m = h
        } else {
            m = [];
            for (var s = 0; s < h.length; s++) {
                m.push(h[s])
            }
        }
        var p = l.cert_filter_oid;
        p = p.replace(/\,/g, "|");
        var v = new Object();
        v.signOrgView = ML4WebApi.getProperty("cs_smartcert_signorgview");
        if (typeof m != "undefined" && m != "") {
            if (typeof(m) == "string") {
                v.plainText = m
            } else {
                v.plainText = []
            }
            if (n == "signedAttribute") {
                if (typeof o != "undefined" && o != "") {
                    v.signTime = o
                }
            }
        }
        var a = "";
        var j = new Array();
        var q = new Array();
        var c = new Array();
        var b = new Array();
        var u = 0;
        if (m instanceof Array) {
            if (l != null && typeof(l.ds_pki_sign) != "undefined" && typeof(l.ds_pki_sign) == "object") {
                for (var s = 0; s < m.length; s++) {
                    if (l.ds_pki_sign.indexOf("OPT_HASHED_CONTENT") > -1) {
                        u = 1;
                        v.plainText.push(magicjs.hex.encode(magicjs.base64.decode(m[s])))
                    } else {
                        if (l.ds_pki_sign.indexOf("TBS_ENCODE_BASE64") > -1 || l.ds_pki_sign.indexOf("TBS_ENCODE_HEX") > -1) {
                            v.plainText.push(magicjs.hex.encode(magicjs.base64.decode(m[s])))
                        } else {
                            v.plainText.push(magicjs.hex.encode(m[s]))
                        }
                    }
                }
            }
            var e = v.plainText;
            for (var s = 0; s < e.length; s++) {
                j[s] = new Object();
                v.plainText = e[s];
                j[s].msg = k.signedAttributes(n, v, u);
                q.push(j[s]);
                c[s] = new Object();
                c[s].signOrgView = v.signOrgView;
                c[s].plainText = v.plainText;
                if (typeof(v.signTime) != "undefined") {
                    c[s].signTime = v.signTime
                }
                b.push(c[s])
            }
            a = JSON.stringify(q);
            msgIntegrity = JSON.stringify(b)
        } else {
            j = new Object();
            if (l != null && typeof(l.ds_pki_sign) != "undefined" && typeof(l.ds_pki_sign) == "object") {
                if (l.ds_pki_sign.indexOf("OPT_HASHED_CONTENT") > -1) {
                    u = 1;
                    v.plainText = magicjs.hex.encode(magicjs.base64.decode(v.plainText))
                } else {
                    if (l.ds_pki_sign.indexOf("TBS_ENCODE_BASE64") > -1 || l.ds_pki_sign.indexOf("TBS_ENCODE_HEX") > -1) {
                        v.plainText = magicjs.hex.encode(magicjs.base64.decode(v.plainText))
                    }
                }
            }
            j.msg = k.signedAttributes(n, v, u);
            a = JSON.stringify(j);
            msgIntegrity = JSON.stringify(v)
        }
        var h = "";
        var d = jSmartCertNP.Sign({
            msgType: n,
            msgIntegrity: msgIntegrity,
            msg: a,
            signedDataType: t,
            subject: ML4WebApi.getProperty("web_smartcert_subject"),
            issuer: ML4WebApi.getProperty("web_smartcert_issuer"),
            serial: ML4WebApi.getProperty("web_smartcert_serial"),
            oid: p,
            randomChk: true,
            siteDomain: ML4WebApi.getProperty("cs_smartcert_sitedomain"),
            multisignYn: ML4WebApi.getProperty("web_smartcert_multisign_yn"),
            validate: ML4WebApi.getProperty("web_smartcert_validate"),
            complete: function(x) {
                var w = {};
                w.option = l;
                w.plainText = m;
                w.msgType = n;
                w.signTime = o;
                completeFunc(w, x, f)
            }
        });
        d.Open()
    },
    Signature: function(d, b, a, c, e) {
        Storage_API_smartcertnx.Sign(d, b, a, c, e)
    }
};
var Storage_API_cloud = {
    SelectStorageInfo: function(a, c) {
        var b = {};
        b = {
            cloudOpt: [{
                servicename: "Dropbox",
                id: "dreamuser",
                passwd: "dreampw"
            }, {
                servicename: "google",
                id: "dreamuser",
                passwd: "dreampw"
            }]
        };
        if (true) {
            c(0, b)
        } else {
            c(ML4WebLog.getErrCode("Storage_cloud_SelectStorageInfo"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    GetCertList: function(b, c) {
        ML4WebLog.log("Storage_API_cloud.GetCertString() called...");
        var a = [];
        if (true) {
            c(0, {
                cert: a
            })
        } else {
            c(ML4WebLog.getErrCode("Storage_cloud_GetCertList"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    GetCertString: function(b, c) {
        ML4WebLog.log("Storage_API_cloud.GetCertString() called...");
        var a = "";
        a = "MIIGAQIBAzCCBccGCSqGSIb3DQEHAaCCBbgEggW0MIIFsDCCAoIGCSqGSIb3DQEHAaCCAnMEggJvMIICazCCAmcGCyqGSIb3DQEMCgEDoIICLzCCAisGCiqGSIb3DQEJFgGgggIbBIICFzCCAhMwggF8oAMCAQICAQIwDQYJKoZIhvcNAQEFBQAwODELMAkGA1UEBhMCS1IxDjAMBgNVBAoMBWRyZWFtMQwwCgYDVQQLDANkZXYxCzAJBgNVBAMMAmNhMB4XDTE0MDIxNjE0MzgyOFoXDTE1MDIxNjE0MzgyOFowRDELMAkGA1UEBhMCS1IxFjAUBgNVBAoMDWRyZWFtc2VjdXJpdHkxDDAKBgNVBAsMA2RldjEPMA0GA1UEAwwGdG9tYXRvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK2fNuhSTz4BbfCEjMhL/OLmlZCDnWTDKc/k35hGf2AkQH7Glt6HGPI+oyevhq9qpcxWYa4pFIYpMvsu4Zru+V6IOhD/Wzrkqiw999PX6gax2GlcOCS/sb0yRbeNv0dj1yyHy/jMrwap336idObUEdMut3Pg1/imx37cS6QbMOVQIDAQABoyEwHzAdBgNVHQ4EFgQUoDfOSwWXopD3thx6iHwMzN17l3MwDQYJKoZIhvcNAQEFBQADgYEAW55K0CAXJrLg+cGROSZMkFAD+kTSdMODNeYljnVliKY36LNGlW2tbG4FTxLOUt8HPtFkH1Tr+bfC1YIXohWyqdNWXcluj8+fyWOqViRkWnOR6ZmwxdObjg8pg07w77Xc/rKAKhANVFN6kpyuFIODFh2sM/4XbONpl6E/8kA9UlcxJTAjBgkqhkiG9w0BCRUxFgQU2LoxaGDuOVCozIgQmPyWZBAatHgwggMmBgkqhkiG9w0BBwGgggMXBIIDEzCCAw8wggMLBgsqhkiG9w0BDAoBAqCCAtMwggLPMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAiX69cei0p8aQICCAAwHQYJYIZIAWUDBAECBBCDaD4fnGWb92voxGNt4vWbBIICgHB9kW7AXf/n8w1JVvboxnDLoX5GLx8YQKIYe3ZbWpEdtp6aUNLyx7UqmZn5+UfCyLOolM+Yj7HkafUdZT5U04ipUS5Bf1+QGhc0qP1OEEms7IhqzOz+oHnBchcxc+JbOzKYpFxEd9QVN2n6+iCNJlrMuznyOzQV9/9mPgPNr/JOYEoIlsOmI2pgAhnCMIgZ11mmAdcsZ/1sx3ozsYehRPQcIDVhkcKDI6L2rlUi33thqxFagjv412LoAM4AQoUvzHF1GRzoEsote3lW3wWWXz7hudSqGU+7Adn/JsmWEkEjlH8NdoWEz2ufdaq+/4vbGWK0feRXZjMGaE0eqbSr0y0OK2V/2lXAJ8L140Jbfl6SUXEnAcYd9zDUljlkkUR7qtqPQB7kmPaRgZepYGtLjturruzCN9Z9Fhyh49kVA45fl1qC2OFQJ9hXCDphAslt2nusRuKLoFQCmL4mDOta5U3NSPreghpwCkge0GllR9UBdMn3oAjs2Fxu3PyGjNvyoy2oqQSJZ8iNsIP/uf2CjqEQPgu8LdI+gcUmd5nnGgWeko9PN+cN0KUP0pwFRkliF1Pxj43z1uhs3uld0sivFNeKJS1ZLjU3vWr7rD0xIHeMw9v6BJCCqcN1S7cNcnYBlHeDfBiN1oWmXZuHWHfkcmmrwz+rqYwg4gJq4z2sTArABzvVIuLSdWnLzHpsR4HCEsZzPXxNGMA2MY6u7ptPY6mawzfHj3iG/LtP1tk2JUMEPrLm3EVeue6sEhMnO9fzT5nWkIfg0bl4t1UlD7Xtpbl1hydawiVDH2GT0WzmZ+XQWbYKUeUG8g8nyXeawvN34V74xXOy/9q/73oiuQBhZIkxJTAjBgkqhkiG9w0BCRUxFgQU2LoxaGDuOVCozIgQmPyWZBAatHgwMTAhMAkGBSsOAwIaBQAEFFi/W5xKKycM4KgJenQu78AenuTzBAgVIdBaWLvOTwICCAA=";
        if (true) {
            c(0, {
                cert: a
            })
        } else {
            c(ML4WebLog.getErrCode("Storage_cloud_GetCertString"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    GetDetailCert: function(d, b, e) {
        ML4WebLog.log("Storage_API_cloud.GetDetailCert() called... fields.length = " + b.length);
        var c = "";
        c = "[sum value...]";
        if (true) {
            var a = {};
            e(0, a)
        } else {
            e(ML4WebLog.getErrCode("Storage_cloud_GetDetailCert"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    SaveCert: function(d, a, g, j) {
        ML4WebLog.log("Storage_API_cloud.SaveCert() called");
        var h = ML4WebApi.getResourceApi();
        var c = ML4WebApi.getProperty("CsUrl");
        var b = h.makeJsonMessage("SaveCert", encodeURIComponent(JSON.stringify(d)), a, encodeURIComponent(JSON.stringify(g)));
        try {
            h.httpRequest(c, false, b, function(k, l) {
                if (k == 0) {
                    var e = JSON.parse(l);
                    if (e.ResultCode == 0) {
                        j(0, e.ResultMessage);
                        return
                    } else {
                        j(ML4WebLog.getErrCode("Storage_cloud_SaveCert"), {
                            errCode: e.ResultCode,
                            errMsg: e.ResultMessage
                        });
                        return
                    }
                }
            })
        } catch (f) {
            j(ML4WebLog.getErrCode("Storage_cloud_SaveCert"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            });
            return
        }
    },
    DeleteCert: function(a, b) {
        ML4WebLog.log("Storage_API_cloud.DeleteCert() called");
        b(ML4WebLog.getErrCode("Storage_cloud_DeleteCert"), {
            errCode: 101,
            errMsg: $.i18n.prop("ER101")
        })
    },
    ChangePassword: function(c, b, a, d) {
        ML4WebLog.log("Storage_API_cloud.ChangePassword() called...");
        if (true) {
            d(0, {
                result: true
            })
        } else {
            d(ML4WebLog.getErrCode("Storage_cloud_ChangePassword"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    verifyVID: function(c, a, b, d) {
        ML4WebLog.log("Storage_API_cloud.verifyVID() called...");
        if (true) {
            d(0, {
                result: true
            })
        } else {
            d(ML4WebLog.getErrCode("Storage_cloud_verifyVID"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    getVIDRandom: function(b, a, c) {
        ML4WebLog.log("Storage_API_cloud.getVIDRandom() called...");
        if (true) {
            c(0, {
                VIDRandom: "[some value...]"
            })
        } else {
            c(ML4WebLog.getErrCode("Storage_cloud_getVIDRandom"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    getVIDRandomHash: function(c, a, b, d) {
        ML4WebLog.log("Storage_API_cloud.getVIDRandomHash() called...");
        if (true) {
            d(0, {
                VIDRandom: "[some value...]"
            })
        } else {
            d(ML4WebLog.getErrCode("Storage_cloud_getVIDRandomHash"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    Sign: function(d, b, a, c, e) {
        ML4WebLog.log("Storage_API_cloud.Sign() called...");
        if (true) {
            e(0, {
                "sign message": "[some value...]"
            })
        } else {
            e(ML4WebLog.getErrCode("Storage_cloud_Sign"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    },
    Signature: function(d, b, a, c, e) {
        Storage_API_cloud.Sign(d, b, a, c, e)
    },
    SingedEnvelopedData: function(e, c, b, a, d, f) {
        ML4WebLog.log("Storage_API_cloud.SingedEnvelopedData() called...");
        if (true) {
            f(0, {
                "SingedEnvelopedData message": "[some value...]"
            })
        } else {
            f(ML4WebLog.getErrCode("Storage_cloud_SingedEnvelopedData"), {
                errCode: 201,
                errMsg: $.i18n.prop("ER201")
            })
        }
    }
};
var Storage_API_easyauth = {
    SelectStorageInfo: function(a, d) {
        ML4WebLog.log("Storage_API_easyauth.SelectStorageInfo() called");
        try {
            var b = {
                mobileConnURL: "",
                cryptoAPI: "",
                signScheme: "",
                encScheme: "",
                mdAlg: ""
            };
            storageInfo = {
                servicename: "dreamWeb",
                serviceOpt: b
            };
            d(0, null)
        } catch (c) {
            d(ML4WebLog.getErrCode("Storage_easyauth_SelectStorageInfo"), {
                errCode: result.ResultCode,
                errMsg: result.ResultMessage
            });
            return
        }
    },
    GetCertList: function(a, b) {
        ML4WebLog.log("Storage_API_easyauth.GetCertList() called")
    },
    GetCertString: function(a, b) {
        ML4WebLog.log("Storage_API_easyauth.GetCertString() called")
    },
    GetDetailCert: function(d, a, f) {
        ML4WebLog.log("Storage_API_easyauth.GetDetailCert() called...");
        var e = ML4WebApi.getResourceApi();
        var b = ML4WebApi.getProperty("CsUrl");
        if (typeof(d.storageCertIdx) == "undefined") {
            d.storageCertIdx = ""
        }
        var c = ML4WebApi.getCryptoApi();
        certInfo = c.getcertInfo(d.storageCertIdx, a, function(h, j) {
            if (j != null) {
                var g = {};
                f(0, j)
            } else {
                f(ML4WebLog.getErrCode("Storage_Web_GetDetailCert"), {
                    errCode: 201,
                    errMsg: $.i18n.prop("ER201")
                })
            }
        })
    },
    SaveCert: function(b, a, c, d) {
        ML4WebLog.log("Storage_API_easyauth.SaveCert() called")
    },
    DeleteCert: function(a, b) {
        ML4WebLog.log("Storage_API_easyauth.DeleteCert() called")
    },
    ChangePassword: function(c, b, a, d) {
        ML4WebLog.log("Storage_API_easyauth.ChangePassword() called...")
    },
    verifyVID: function(c, a, b, d) {
        ML4WebLog.log("Storage_API_easyauth.verifyVID() called...")
    },
    getVIDRandom: function(b, a, c) {
        ML4WebLog.log("Storage_API_easyauth.getVIDRandom() called...")
    },
    getVIDRandomHash: function(c, a, b, d) {
        ML4WebLog.log("Storage_API_easyauth.getVIDRandomHash() called...")
    },
    Sign: function(d, b, a, c, e) {
        ML4WebLog.log("Storage_API_easyauth.Sign() called...")
    },
    Signature: function(d, b, a, c, e) {
        Sign(d, b, a, c, e)
    },
    SingedEnvelopedData: function(e, c, b, a, d, f) {
        Storage_API_easyauth.ML4WebLog.log("Storage_API_easyauth.SingedEnvelopedData() called...")
    }
};
var Storage_API_kftc = {
    initflag: 0,
    opencert: null,
    localCertInfos: [],
    newCertInfos: [],
    serverNonce: "",
    base64UrlToArrayBuffer: function(f) {
        var j = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        var k = f.replace(/-/g, "+").replace(/_/g, "/");
        var h = String(k).replace(/[=]+$/, "");
        for (var g = 0, m, d, l = 0, c = ""; d = h.charAt(l++); ~d && (m = g % 4 ? m * 64 + d : d, g++ % 4) ? c += String.fromCharCode(255 & m >> (-2 * g & 6)) : 0) {
            d = j.indexOf(d)
        }
        var b = new Array(c.length);
        for (var e = 0, a = c.length; e < a; e++) {
            b[e] = c.charCodeAt(e)
        }
        return b
    },
    createOpencertPassword: function(a, c, e) {
        ML4WebLog.log("Storage_API_kftc.createOpencertPassword() called...");
        var d = ML4WebApi.getCryptoApi();
        var b = "";
        c = d.SD_api(c);
        b = a + c;
        d.genHashCount("sha256", b, 2048, function(f, g) {
            e(f, g)
        })
    },
    getEncryptedPKCS12: function(b, c, h, n) {
        ML4WebLog.log("Storage_API_kftc.getEncryptedPKCS12() called...");
        var d, a, m;
        var f, j, l = "";
        var k = ML4WebApi.getCryptoApi();
        if (b == null || b == "") {
            ML4WebLog.log("invalid param : encryptedData");
            n(100, {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (c == null || c == "") {
                ML4WebLog.log("invalid param : clientNonce");
                n(100, {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (h == null || h == "") {
                    ML4WebLog.log("invalid param : serverNonce");
                    n(100, {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof n != "function" || n == null || n == "") {
                        ML4WebLog.log("invalid param : callback");
                        n(103, {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
        }
        try {
            b = Storage_API_kftc.base64UrlToArrayBuffer(b);
            d = b.slice(0, 16);
            d = String.fromCharCode.apply(String, d);
            a = b.slice(16, b.length);
            a = String.fromCharCode.apply(String, a);
            c = Storage_API_kftc.base64UrlToArrayBuffer(c);
            h = Storage_API_kftc.base64UrlToArrayBuffer(h);
            f = c.slice();
            f = f.concat(h);
            f = String.fromCharCode.apply(String, f);
            k.genHashCount("sha256", f, 2048, function(e, o) {
                if (e == 0) {
                    j = o.hash;
                    d = magicjs.base64.encode(d);
                    a = magicjs.base64.encode(a);
                    k.decrypt("AES256-CBC", j, d, a, function(p, q) {
                        if (p == 0) {
                            n(0, q.stringResult)
                        } else {
                            ML4WebLog.log("crypto_api.decrypt error =====> code : " + q.errCode + " message : " + q.errMsg);
                            n(q.errCode, q.errMsg)
                        }
                    })
                } else {
                    ML4WebLog.log("getEncryptedPKCS12 error =====> code : " + o.errCode + " message : " + o.errMsg);
                    n(o.errCode, o.errMsg)
                }
            })
        } catch (g) {
            n(g.code, g.message)
        }
    },
    getCertInfo: function(b, h) {
        ML4WebLog.log("Storage_API_kftc.getCertInfo() called...");
        var a = {};
        var e = ["startdatetime", "enddatetime", "issuername", "subjectname", "policyid"];
        var d = "";
        var c = "";
        var f = ML4WebApi.getCryptoApi();
        var g = "";
        if (typeof(b.accesstime) != "undefined") {
            g = b.accesstime
        } else {
            g = new Date().getTime()
        }
        if (b == null || $.isEmptyObject(b)) {
            ML4WebLog.log("invalid param : certBag");
            h(100, {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof h != "function" || h == null || h == "") {
                ML4WebLog.log("invalid param : callback");
                h(103, {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            }
        }
        d = magicjs.base64.decode(b.signcert);
        f.genHash("sha1", d, function(j, k) {
            if (j == 0) {
                c = k.resulthex;
                f.getcertInfo(b.signcert, e, function(l, m) {
                    if (l == 0) {
                        a.fingerprint = c;
                        a.timestamp = g;
                        a.status = "SAVE";
                        a.subject = m.result.subjectname;
                        a.notAfter = m.result.enddatetime;
                        a.notBefore = m.result.startdatetime;
                        a.issuer = m.result.issuername;
                        a.policyOID = m.result.policyid;
                        a.source = "LOCAL";
                        h(0, a)
                    } else {
                        ML4WebLog.log("Storage_API_kftc_getCertInfo()", {
                            errCode: m.errCode,
                            errMsg: m.message
                        });
                        h(m.errCode, {
                            errCode: m.errCode,
                            errMsg: m.message
                        })
                    }
                })
            } else {
                ML4WebLog.log("Storage_API_kftc_getCertInfo()", {
                    errCode: k.errCode,
                    errMsg: k.message
                });
                h(k.errCode, {
                    errCode: k.errCode,
                    errMsg: k.message
                })
            }
        })
    },
    SelectStorageInfo: function(b, c) {
        ML4WebLog.log("Storage_API_kftc.SelectStorageInfo() called...");
        if (b == null || $.isEmptyObject(b)) {
            ML4WebLog.log("invalid param : storageName");
            c(100, $.i18n.prop("ER100") + "[storageName]");
            return
        } else {
            if (typeof c != "function" || c == null || c == "") {
                ML4WebLog.log("invalid param : callback");
                c(103, $.i18n.prop("ER103"));
                return
            }
        }
        ML4WebLog.log("opencert.init :: flag = " + Storage_API_kftc.initflag);
        if (Storage_API_kftc.initflag == 0) {
            var a = ML4WebApi.getProperty("kftc_apikey");
            if (a == null || a == "") {
                ML4WebLog.log("kftcApikey is null !!");
                c(100, $.i18n.prop("ER100") + "[kftcApikey]");
                return
            }
            window.OpenCertApiKey = ML4WebApi.ml4web_crypto_api.getDecryptedCert(a);
            Storage_API_kftc.opencert = OpenCert.getInstance();
            Storage_API_kftc.initflag = 1;
            Storage_API_kftc.opencert.init(window.OpenCertApiKey, function(d) {
                if (d.error) {
                    ML4WebLog.log("opencert.init() error =====> code : " + d.error.code + " message : " + d.error.message);
                    c(0, {})
                } else {
                    Storage_API_kftc.serverNonce = d.serverNonce;
                    ML4WebLog.log("serverNonce <BASE64URL> : [" + Storage_API_kftc.serverNonce + "]");
                    c(0, {})
                }
            });
            Storage_API_kftc.opencert.setEventListener("changeCertInfos", function(d) {
                if (d == "connect" || d == "disconnect" || d == "removeCertFromTray") {
                    $("#stg_web_kftc").trigger("click")
                }
            })
        } else {
            c(0, {})
        }
    },
    SaveCert: function(c, b, g, h) {
        ML4WebLog.log("Storage_API_kftc.SaveCert() called...");
        var a = {};
        var f = "";
        var d = "";
        var e = ML4WebApi.getCryptoApi();
        if (c == null || $.isEmptyObject(c)) {
            ML4WebLog.log("invalid param : certBag");
            h(100, $.i18n.prop("ER100") + "[certBag]");
            return
        } else {
            if (b == null || b == "") {
                ML4WebLog.log("invalid param : passwd");
                h(100, $.i18n.prop("ER100") + "[passwd]");
                return
            } else {
                if (g == null || $.isEmptyObject(g)) {
                    ML4WebLog.log("invalid param : storageRawCertIdx");
                    h(100, $.i18n.prop("ER100") + "[storageRawCertIdx]");
                    return
                } else {
                    if (Storage_API_kftc.opencert == null) {
                        ML4WebLog.log("invalid param : opencert");
                        h(100, $.i18n.prop("ER100") + "[opencert] => " + $.i18n.prop("ES080"));
                        return
                    } else {
                        if (typeof h != "function" || h == null || h == "") {
                            ML4WebLog.log("invalid param : callback");
                            h(100, $.i18n.prop("ER103"));
                            return
                        }
                    }
                }
            }
        }
        e.prikeyDecrypt(c.signpri, b, function(j, k) {
            if (j == 0) {
                ML4WebLog.log("step 1. Storage_API_kftc.getCertInfo");
                Storage_API_kftc.getCertInfo(c, function(l, m) {
                    if (l == 0) {
                        a = m;
                        ML4WebLog.log("step 2. crypto_api.pfxExport");
                        e.pfxExport(c, b, function(n, o) {
                            if (n == 0) {
                                f = o.result;
                                ML4WebLog.log("step 3. Storage_API_kftc.createOpencertPassword");
                                Storage_API_kftc.createOpencertPassword(a.fingerprint, b, function(p, q) {
                                    if (p == 0) {
                                        d = q.resulthex;
                                        ML4WebLog.log("step 4. Storage_API_kftc.opencert.setPKCS12");
                                        Storage_API_kftc.opencert.setPKCS12(f, a, d, function(r) {
                                            if (r.error) {
                                                ML4WebLog.log("opencert.setPKCS12 error =====> code : " + r.error.code + " message : " + r.error.message);
                                                h(r.error.code, r.error.message)
                                            } else {
                                                h(0, "opencert.setPKCS12 success...")
                                            }
                                        }, {
                                            mode: "window"
                                        })
                                    } else {
                                        ML4WebLog.log("pfxExport error =====> code : " + q.errCode + " message : " + q.errMsg);
                                        h(q.errCode, q.errMsg)
                                    }
                                })
                            } else {
                                ML4WebLog.log("pfxExport error =====> code : " + o.errCode + " message : " + o.errMsg);
                                h(o.errCode, o.errMsg)
                            }
                        })
                    } else {
                        ML4WebLog.log("getCertInfo error =====> code : " + m.errCode + " message : " + m.errMsg);
                        h(m.errCode, m.errMsg)
                    }
                })
            } else {
                h(ML4WebLog.getErrCode("Storage_kftc_SaveCert"), {
                    errCode: j,
                    errMsg: k.errMsg
                })
            }
        })
    },
    GetCertList: function(e, g) {
        ML4WebLog.log("Storage_API_kftc.GetCertList() called...");
        var d = [];
        var f = new Array();
        if (e == null || $.isEmptyObject(e)) {
            ML4WebLog.log("invalid param : storageOpt");
            g(100, $.i18n.prop("ER100") + "[storageOpt]");
            return
        } else {
            if (Storage_API_kftc.opencert == null) {
                ML4WebLog.log("invalid param : opencert");
                g(100, $.i18n.prop("ER100") + "[opencert] => " + $.i18n.prop("ES080"));
                return
            } else {
                if (typeof g != "function" || g == null || g == "") {
                    ML4WebLog.log("invalid param : callback");
                    g(100, $.i18n.prop("ER103"));
                    return
                }
            }
        }
        Storage_API_kftc.localCertInfos = [];
        var b = Storage_API_web.getML4WebCert();
        var c = null;
        if (b != null) {
            c = JSON.parse(decodeURIComponent(b))
        } else {
            c = []
        }
        for (var a = 0; a < c.length; a++) {
            if (typeof(c[a].kftc) != "undefined") {
                Storage_API_kftc.localCertInfos.push(c[a].kftc)
            }
        }
        ML4WebLog.log("opencert.mergeCertInfos start");
        Storage_API_kftc.opencert.mergeCertInfos(Storage_API_kftc.localCertInfos, function(p) {
            if (p.error) {
                if (p.error.code == 5000) {
                    ML4WebLog.log("opencert.mergeCertInfos error =====> code : " + p.error.code + " message : " + $.i18n.prop("ES081"));
                    g(p.error.code, $.i18n.prop("ES081"))
                } else {
                    ML4WebLog.log("opencert.mergeCertInfos error =====> code : " + p.error.code + " message : " + p.error.message);
                    g(p.error.code, p.error.message)
                }
                return
            }
            var n = p.certInfos;
            var m = 0;
            if (Storage_API_kftc.localCertInfos.length > 0) {
                var h = Storage_API_kftc.localCertInfos.length;
                for (m = 0; m < h; m++) {
                    Storage_API_kftc.localCertInfos.pop()
                }
            }
            var k = 0;
            if (Storage_API_kftc.newCertInfos.length > 0) {
                var h = Storage_API_kftc.newCertInfos.length;
                for (k = 0; k < h; k++) {
                    Storage_API_kftc.newCertInfos.pop()
                }
            }
            for (m = 0; m < n.length; m++) {
                Storage_API_kftc.newCertInfos.push(n[m]);
                Storage_API_kftc.localCertInfos.push(n[m])
            }
            var o = 0;
            for (m = 0; m < n.length; m++) {
                if (n[m].status == "REMOVE") {
                    continue
                }
                o = f.length;
                var l = {
                    storageName: "kftc",
                    storageOpt: {}
                };
                l.storageCertIdx = n[m].fingerprint;
                f[o] = {};
                if (typeof(n[m].cloud) != "undefined") {
                    f[o]["cloud"] = n[m].cloud
                }
                f[o]["source"] = n[m].source;
                f[o]["fingerprint"] = n[m].fingerprint;
                f[o]["timestamp"] = n[m].timestamp;
                f[o]["version"] = "";
                f[o]["serialnum"] = "";
                f[o]["signaturealgorithm"] = "";
                f[o]["issuername"] = n[m].issuer;
                f[o]["startdate"] = n[m].notBefore.split(" ")[0];
                f[o]["enddate"] = n[m].notAfter.split(" ")[0];
                f[o]["startdatetime"] = n[m].notBefore;
                f[o]["enddatetime"] = n[m].notAfter;
                f[o]["subjectname"] = n[m].subject;
                f[o]["pubkey"] = "";
                f[o]["pubkeyalgorithm"] = "";
                f[o]["keyusage"] = "";
                f[o]["certpolicy"] = "";
                f[o]["policyid"] = n[m].policyOID;
                f[o]["subjectaltname"] = "";
                f[o]["authkeyid"] = "";
                f[o]["subkeyid"] = "";
                f[o]["crldp"] = "";
                f[o]["aia"] = "";
                f[o]["realname"] = "";
                f[o]["policynotice"] = "";
                f[o]["storageRawCertIdx"] = l;
                d.push(f[o])
            }
            g(0, {
                cert_list: d
            })
        }, {
            mode: "tray"
        })
    },
    GetCertString: function(d, e) {
        ML4WebLog.log("Storage_API_kftc.GetCertString() called...");
        var c = "";
        var a = "";
        var b = ML4WebApi.getCryptoApi();
        if (d == null || $.isEmptyObject(d)) {
            ML4WebLog.log("invalid param : storageRawCertIdx");
            e(100, $.i18n.prop("ER100") + "[storageRawCertIdx]");
            return
        } else {
            if (Storage_API_kftc.opencert == null) {
                ML4WebLog.log("invalid param : opencert");
                e(100, $.i18n.prop("ER100") + "[storageOpt]");
                return
            } else {
                if (typeof(d.storageOpt.password) == "undefined" || typeof(d.storageOpt.password) != "string") {
                    ML4WebLog.log("invalid param : storageRawCertIdx.storageOpt.password");
                    e(100, $.i18n.prop("ER100") + "[storageRawCertIdx.storageOpt.password]");
                    return
                } else {
                    if (typeof e != "function" || e == null || e == "") {
                        ML4WebLog.log("invalid param : callback");
                        e(100, $.i18n.prop("ER103"));
                        return
                    }
                }
            }
        }
        b.generateRandom(20, function(f, g) {
            if (f == 0) {
                c = g.resulthex;
                Storage_API_kftc.createOpencertPassword(d.storageOpt.fingerprint, d.storageOpt.password, function(h, j) {
                    if (h == 0) {
                        a = j.resulthex;
                        Storage_API_kftc.opencert.getPKCS12(d.storageOpt.fingerprint, a, c, function(n) {
                            if (n.error) {
                                if (n.error.code == 5000) {
                                    ML4WebLog.log("opencert.getPKCS12", {
                                        errCode: n.error.code,
                                        errMsg: $.i18n.prop("ES081")
                                    });
                                    e(ML4WebLog.getErrCode("Storage_kftc"), n.error)
                                } else {
                                    if (n.error.code == 3000) {
                                        ML4WebLog.log("opencert.getPKCS12", {
                                            errCode: n.error.code,
                                            errMsg: $.i18n.prop("ES082")
                                        });
                                        e(ML4WebLog.getErrCode("Storage_kftc"), n.error)
                                    } else {
                                        if (n.error.code == 3209) {
                                            ML4WebLog.log("opencert.getPKCS12", {
                                                errCode: n.error.code,
                                                errMsg: $.i18n.prop("ES082")
                                            });
                                            e(ML4WebLog.getErrCode("Storage_kftc"), n.error)
                                        } else {
                                            if (n.error.code == 2211) {
                                                ML4WebLog.log("opencert.getPKCS12", {
                                                    errCode: n.error.code,
                                                    errMsg: $.i18n.prop("ES002")
                                                });
                                                e(ML4WebLog.getErrCode("Storage_kftc"), n.error)
                                            } else {
                                                if (n.error.code == 2212) {
                                                    ML4WebLog.log("opencert.getPKCS12", {
                                                        errCode: n.error.code,
                                                        errMsg: $.i18n.prop("ES032")
                                                    });
                                                    e(ML4WebLog.getErrCode("Storage_kftc"), n.error)
                                                } else {
                                                    ML4WebLog.log("opencert.getPKCS12", {
                                                        errCode: n.error.code,
                                                        errMsg: n.error.message
                                                    });
                                                    e(ML4WebLog.getErrCode("Storage_kftc"), n.error)
                                                }
                                            }
                                        }
                                    }
                                }
                                return
                            }
                            var m = false;
                            var k;
                            if (typeof(n.pkcs12) != "undefined") {
                                k = n.pkcs12
                            }
                            if (typeof(n.notSavePKCS12) != "undefined") {
                                m = true;
                                k = n.notSavePKCS12
                            }
                            var l = n.certInfo;
                            Storage_API_kftc.getEncryptedPKCS12(k, c, Storage_API_kftc.serverNonce, function(o, p) {
                                if (o == 0) {
                                    b.pfxImport(p, d.storageOpt.password, function(q, r) {
                                        if (q == 0) {
                                            if (m == false) {
                                                var s = r.result;
                                                s.accesstime = l.timestamp;
                                                Storage_API_web.SaveCertBag(s, "", function(u, t) {
                                                    e(0, {
                                                        cert: r.result
                                                    })
                                                })
                                            } else {
                                                e(0, {
                                                    cert: r.result
                                                })
                                            }
                                        } else {
                                            ML4WebLog.log("pfxImport error =====> code : " + resultObj.errCode + " message : " + resultObj.errMsg);
                                            e(resultObj.errCode, resultObj.errMsg)
                                        }
                                    })
                                } else {
                                    ML4WebLog.log("pfxImport error =====> code : " + o + " message : " + p);
                                    e(ML4WebLog.getErrCode("Storage_kftc"), p)
                                }
                            })
                        })
                    } else {
                        ML4WebLog.log("createOpencertPassword error =====> code : " + resultObj.errCode + " message : " + resultObj.errMsg);
                        e(resultObj.errCode, resultObj.errMsg)
                    }
                })
            } else {
                ML4WebLog.log("generateRandom error =====> code : " + resultObj.errCode + " message : " + resultObj.errMsg);
                e(resultObj.errCode, resultObj.errMsg)
            }
        })
    },
    DeleteCert: function(a, b) {
        ML4WebLog.log("Storage_API_kftc.DeleteCert() called...");
        if (a == null || $.isEmptyObject(a)) {
            ML4WebLog.log("invalid param : storageRawCertIdx");
            b(100, $.i18n.prop("ER100") + "[storageRawCertIdx]");
            return
        } else {
            if (Storage_API_kftc.opencert == null) {
                ML4WebLog.log("invalid param : opencert");
                b(100, $.i18n.prop("ER100") + "[opencert] => " + $.i18n.prop("ES080"));
                return
            } else {
                if (typeof b != "function" || b == null || b == "") {
                    ML4WebLog.log("invalid param : callback");
                    b(100, $.i18n.prop("ER103"));
                    return
                }
            }
        }
        ML4WebLog.log("fingerprint : [" + a.storageOpt.fingerprint + "]");
        Storage_API_kftc.opencert.removePKCS12(a.storageOpt.fingerprint, function(c) {
            if (c.error) {
                if (c.error.code == 5000) {
                    ML4WebLog.log("opencert.removePKCS12 error =====> code : " + c.error.code + " message : " + $.i18n.prop("ES081"));
                    b(c.error.code, $.i18n.prop("ES081"))
                } else {
                    ML4WebLog.log("opencert.removePKCS12 error =====> code : " + c.error.code + " message : " + c.error.message);
                    b(c.error.code, $.i18n.prop("ES081"))
                }
                return
            } else {
                b(0, $.i18n.prop("ES009") + " (" + a.storageOpt.fingerprint + ")")
            }
        })
    },
    ChangePassword: function(f, b, a, g) {
        ML4WebLog.log("Storage_API_kftc.ChangePassword() called...");
        var e, c;
        var d = ML4WebApi.getCryptoApi();
        if (f == null || $.isEmptyObject(f)) {
            ML4WebLog.log("invalid param : storageRawCertIdx");
            g(100, $.i18n.prop("ER100") + "[storageRawCertIdx]");
            return
        } else {
            if (Storage_API_kftc.opencert == null) {
                ML4WebLog.log("invalid param : opencert");
                g(100, $.i18n.prop("ER100") + "[opencert] => " + $.i18n.prop("ES080"));
                return
            } else {
                if (b == null || b == "") {
                    ML4WebLog.log("invalid param : passwdPre");
                    g(100, $.i18n.prop("ER100") + "[passwdPre]");
                    return
                } else {
                    if (a == null || a == "") {
                        ML4WebLog.log("invalid param : passwdNext");
                        g(100, $.i18n.prop("ER100") + "[passwdNext]");
                        return
                    } else {
                        if (typeof g != "function" || g == null || g == "") {
                            ML4WebLog.log("invalid param : callback");
                            g(100, $.i18n.prop("ER103"));
                            return
                        }
                    }
                }
            }
        }
        f.storageOpt.password = b;
        Storage_API_kftc.GetCertString(f, function(h, j) {
            if (h == 0) {
                e = j.cert;
                d.certChangePassword(e, b, a, "", function(k, l) {
                    if (k == 0) {
                        c = l.result;
                        Storage_API_kftc.SaveCert(c, a, f, function(m, n) {
                            if (m == 0) {
                                g(0, "ChangePassword success...")
                            } else {
                                ML4WebLog.log("Storage_API_kftc.SaveCert error =====> code : " + m + " message : " + n);
                                g(m, n)
                            }
                        })
                    } else {
                        ML4WebLog.log("crypto_api.certChangePassword error =====> code : " + l.errCode + " message : " + l.errMsg);
                        g(l.errCode, l.errMsg)
                    }
                })
            } else {
                ML4WebLog.log("Storage_API_kftc.GetCertString error =====> code : " + h + " message : " + j);
                g(h, j)
            }
        })
    }
};
var Storage_API_web_kftc = {
    SelectStorageInfo: function(a, b) {
        ML4WebLog.log("Storage_API_web_kftc.SelectStorageInfo() called...");
        Storage_API_web.SelectStorageInfo(a, function(c, d) {
            Storage_API_kftc.SelectStorageInfo(a, b)
        })
    },
    SaveCert: function(b, a, c, d) {
        ML4WebLog.log("Storage_API_web_kftc.SaveCert() called...");
        b.accesstime = new Date().getTime();
        Storage_API_web.SaveCert(b, a, c, function(e, f) {
            Storage_API_kftc.SaveCert(b, a, c, d)
        })
    },
    GetCertList: function(a, c) {
        ML4WebLog.log("Storage_API_web_kftc.GetCertList() called...");
        var b = new Array();
        Storage_API_web.GetCertList(a, function(d, f) {
            if (d == 0) {
                for (var e = 0; e < f.cert_list.length; e++) {
                    b.push(f.cert_list[e])
                }
            }
            Storage_API_kftc.GetCertList(a, function(j, m) {
                if (j == 0) {
                    var g = 0;
                    var l = false;
                    var h = b.length;
                    for (var k = 0; k < m.cert_list.length; k++) {
                        l = false;
                        for (g = 0; g < h; g++) {
                            if (b[g].subjectname.toLowerCase() == m.cert_list[k].subjectname.toLowerCase()) {
                                l = true;
                                break
                            }
                        }
                        if (l == true) {
                            if (m.cert_list[k].source.toLowerCase() == "opencert") {
                                b[g] = m.cert_list[k]
                            }
                        } else {
                            if (l == false) {
                                b.push(m.cert_list[k])
                            }
                        }
                    }
                    c(j, {
                        cert_list: b
                    })
                } else {
                    if (b.length == 0) {
                        c(j, m)
                    } else {
                        c(0, {
                            cert_list: b
                        })
                    }
                }
            })
        })
    },
    DeleteCert: function(a, b) {
        Storage_API_web.GetCertString(a, function(d, c) {
            Storage_API_web.DeleteCert(a, function(e, f) {
                if (Object.keys(c.cert).length != 0 && typeof(c.cert.kftc.fingerprint) != "undefined") {
                    a.storageCertIdx = c.cert.kftc.fingerprint
                }
                if (e == 0) {
                    a.storageOpt.fingerprint = a.storageCertIdx;
                    Storage_API_kftc.DeleteCert(a, function(g, h) {
                        b(0, {
                            result: true
                        })
                    })
                } else {
                    b(e, f)
                }
            })
        })
    }
};
var Storage_API_unisign = {
    SelectStorageInfo: function(a, b) {
        ML4WebUI.unblockUI();
        ML4WebLog.log("Storage_API_unisign.SelectStorageInfo() called...");
        getUnisign().certSelect(function(c) {
            if (!c || c.resultCode != 0) {
                b(c.resultCode, c.resultMassage);
                return
            }
            b(0, c)
        })
    },
    Sign: function(d, b, a, c, e) {
        ML4WebLog.log("Storage_API_unisign.Sign() called...");
        getUnisign().digitalSignature(d.certObj.resultIndex, c, "N", function(f) {
            if (!f || f.resultCode != 0) {
                e(f.resultCode, f.resultMassage);
                return
            }
            var h = new Object();
            h.encMsg = f.resultValue;
            var j = ML4WebApi.getCryptoApi();
            var g = null;
            j.getcertInfo(d.certObj.resultCert, [], function(k, l) {
                h.certbag = {};
                h.certbag.signcert = d.certObj.resultCert;
                h.certInfo = l.result;
                ML4WebApi.webConfig.getRandomfromPrivateKey = f.RValue;
                e(0, h)
            })
        })
    },
    Signature: function(d, b, a, c, e) {
        ML4WebLog.log("Storage_API_unisign.Signature() called...");
        getUnisign().digitalSignature(d.certObj.resultIndex, c, "N", function(f) {
            if (!f || f.resultCode != 0) {
                e(f.resultCode, f.resultMassage);
                return
            }
            var h = new Object();
            h.encMsg = f.resultValue;
            var j = ML4WebApi.getCryptoApi();
            var g = null;
            j.getcertInfo(d.certObj.resultCert, [], function(k, l) {
                h.certbag = {};
                h.certbag.signcert = d.certObj.resultCert;
                h.certInfo = l.result;
                ML4WebApi.webConfig.getRandomfromPrivateKey = f.RValue;
                e(0, h)
            })
        })
    },
    getVIDRandom: function(d, b, f) {
        ML4WebLog.log("Storage_API_unisign.getVIDRandom() called...");
        try {
            if (ML4WebApi.webConfig.getRandomfromPrivateKey != null && ML4WebApi.webConfig.getRandomfromPrivateKey != "") {
                var a = {};
                a.VIDRandom = ML4WebApi.webConfig.getRandomfromPrivateKey;
                f(0, a)
            } else {
                f(33333, "")
            }
            return
        } catch (c) {
            f(33333, "");
            return
        }
    },
};
var Storage_API_filter = {
    base_url: "",
    base_dir: "",
    filter_type: "",
    filter_use_type: "",
    filter_expire: "",
    filter_oid: "",
    filter_subject_dn: "",
    filter_issuer_dn: "",
    filter_sign_serial: "",
    filter_km_serial: "",
    oid_name: "",
    issuer_name: "",
    filter_path: [],
    init: function(a) {
        base_url = ML4WebApi.getProperty("cert_base_url");
        base_dir = ML4WebApi.getProperty("cert_base_dir");
        filter_type = ML4WebApi.getProperty("cert_filter_type");
        filter_use_type = ML4WebApi.getProperty("cert_filter_use_type");
        filter_expire = ML4WebApi.getProperty("cert_filter_expire");
        filter_oid = ML4WebApi.getProperty("cert_filter_oid");
        filter_subject_dn = ML4WebApi.getProperty("cert_filter_subject_dn");
        filter_issuer_dn = ML4WebApi.getProperty("cert_filter_issuer_dn");
        filter_sign_serial = ML4WebApi.getProperty("cert_filter_sign_serial");
        filter_km_serial = ML4WebApi.getProperty("cert_filter_km_serial");
        oid_name = ML4WebApi.getProperty("cert_oid_name");
        issuer_name = ML4WebApi.getProperty("cert_issuer_name");
        filter_path = ML4WebApi.getProperty("cert_filter_path");
        a(0, {
            result: "Storage_API_filter init success..."
        })
    },
    selectfilteredCertList: function(u, f) {
        var n = [];
        for (var t = 0; t < u.length; t++) {
            var m = false;
            if (base_url) {}
            if (base_dir) {}
            if (filter_type != null && filter_type != "") {
                var l = filter_type.toString(2);
                var r = "";
                if (3 < filter_type && filter_type < 8) {
                    r = "0" + l
                } else {
                    if (1 < filter_type && filter_type < 4) {
                        r = "00" + l
                    } else {
                        if (filter_type == 1) {
                            r = "000" + l
                        } else {
                            r = l
                        }
                    }
                }
                var a = [];
                for (var s = 0; s < 4; s++) {
                    a.push(r.substring(s, s + 1))
                }
                var e = u[t].issuername.split(",");
                $.each(e, function() {
                    var j = this.split("=");
                    if (j[0].toLowerCase() == "ou") {
                        if (j[1].toLowerCase() == "gpki") {
                            if (a[3] == "0") {
                                m = true
                            } else {
                                m = false
                            }
                        }
                    } else {
                        if (j[0].toLowerCase() == "o") {
                            if (j[1].toLowerCase() == "yessign" || j[1].toLowerCase() == "kica" || j[1].toLowerCase() == "crosscert" || j[1].toLowerCase() == "tradesign" || j[1].toLowerCase() == "signkorea" || j[1].toLowerCase() == "inipass" || j[1].toLowerCase() == "dream security") {
                                if (a[2] == "0") {
                                    m = true
                                } else {
                                    m = false
                                }
                            } else {
                                if (j[1].toLowerCase().indexOf("government") > -1) {
                                    if (a[3] == "0") {
                                        m = true
                                    } else {
                                        m = false
                                    }
                                } else {
                                    if (a[0] == "0") {
                                        m = true
                                    } else {
                                        m = false
                                    }
                                }
                            }
                        }
                    }
                })
            }
            if (!m && filter_use_type != null && filter_use_type != "") {
                var e = u[t].keyusage.split(",");
                var o = "";
                if (e.length == 2) {
                    o = "1"
                } else {
                    if (e.length > 2) {
                        o = "2"
                    }
                }
                if (!m && filter_use_type == o) {
                    m = false
                } else {
                    m = true
                }
            }
            if (!m && filter_expire) {
                var g = ML4WebUtil.isDateExpired(u[t].enddatetime);
                if (g) {
                    m = true
                } else {
                    m = false
                }
            }
            if (!m && filter_oid != null && filter_oid != "") {
                var d = u[t].policyid;
                var a = filter_oid.split(",");
                var v = a.length;
                for (var s = 0; s < v; s++) {
                    if (a[s] == d) {
                        m = false;
                        break
                    } else {
                        m = true
                    }
                }
            }
            if (!m && filter_subject_dn) {
                var d = u[t].policyid;
                var a = oid_name.split(",");
                var v = a.length;
                for (var s = 0; s < v; s++) {
                    if (a[s] == d) {
                        m = false
                    } else {
                        m = true
                    }
                }
            }
            if (!m && filter_issuer_dn) {
                var e = u[t].issuername.split(",");
                var k = "";
                $.each(e, function() {
                    var j = this.split("=");
                    if (j[0].toLowerCase() == "cn") {
                        k = j[1]
                    }
                });
                if (issuer_name == k) {
                    m = false
                } else {
                    m = true
                }
            }
            if (!m && filter_sign_serial != null && filter_sign_serial != "") {
                var h = u[t].serialnum;
                if (filter_sign_serial == h) {
                    m = false
                } else {
                    m = true
                }
            }
            if (!m && filter_km_serial != null && filter_km_serial != "") {
                var h = u[t].serialnum;
                if (filter_km_serial == h) {
                    m = false
                } else {
                    m = true
                }
            }
            if (!m && oid_name != null && oid_name != "") {
                var d = u[t].policyid;
                var a = oid_name.split(",");
                var v = a.length;
                for (var s = 0; s < v; s++) {
                    if (a[s] == d) {
                        m = false
                    } else {
                        m = true
                    }
                }
            }
            if (!m && issuer_name != null && issuer_name != "") {
                var e = u[t].issuername.split(",");
                var k = "";
                $.each(e, function() {
                    var j = this.split("=");
                    if (j[0].toLowerCase() == "cn") {
                        k = j[1]
                    }
                });
                if (!m && issuer_name == k) {
                    m = false
                } else {
                    m = true
                }
            }
            if (!m) {
                n.push(u[t])
            }
            if (!m && filter_path != null && filter_path != "") {
                var p = 0;
                var q = -1;
                for (p = n.length - 1; p >= 0; p--) {
                    if (typeof(n[p].serialnum) != "undefined") {
                        if (n[p].serialnum.indexOf(u[t].serialnum) > -1) {
                            var c = n[p].certpath;
                            c = c.toUpperCase();
                            for (var s = 0; s < filter_path.length; s++) {
                                if (c.indexOf(filter_path[s].toUpperCase()) > -1) {
                                    q = p;
                                    n.splice(q, 1);
                                    break
                                }
                            }
                        }
                    }
                    if (q > -1) {
                        break
                    }
                }
                var b = 0;
                for (p = n.length - 1; p >= 0; p--) {
                    if (n[p].serialnum.indexOf(u[t].serialnum) > -1) {
                        b++
                    }
                }
                if (b >= 2) {
                    n.splice(p, 1)
                }
            } else {
                var p = 0;
                var q = -1;
                for (p = n.length - 1; p >= 0; p--) {
                    if (typeof(n[p].serialnum) != "undefined") {
                        if (u[t].serialnum.indexOf(n[p].serialnum) > -1) {
                            q = p;
                            break
                        }
                    }
                    if (q > -1) {
                        break
                    }
                }
                var b = 0;
                for (p = n.length - 1; p >= 0; p--) {
                    if (u[t].serialnum.indexOf(n[p].serialnum) > -1) {
                        b++
                    }
                }
                if (b >= 2 && q > -1) {
                    n.splice(q, 1)
                }
            }
        }
        f(0, {
            filtered_list: n
        })
    }
};
var CS_Manager_API = (function(p, m) {
    var w;
    var f;
    var b;
    var n;
    var p = p;
    var m = m;

    function s(x) {
        ML4WebLog.log("CS_Manager.Init()...");
        if (p == null) {
            p = ML4WebApi.getResourceApi()
        }
        g(x)
    }

    function j(y) {
        ML4WebLog.log("CS_Manager.checkinstall() called...");
        var x = ML4WebApi.getProperty("os");
        ML4WebApi.setProperty("is_cs_install", false);
        if (x == "Android" || x == "IPHONE" || x == "IPAD" || x == "BlackBerry") {
            y(ML4WebLog.getErrCode("CS_Manager_API_checkInstall"), {
                errCode: 1,
                errMsg: "Mobile Access"
            })
        } else {
            a(y)
        }
    }

    function a(z) {
        var x = ML4WebApi.getProperty("browser");
        var y = p.makeJsonMessage("InstallCheck", m.SessionID, x, m.CsSessionTimeout);
        e(m.CS_UR + m.CS_PORT + "/", y, function(A, B) {
            if (A == 0) {
                if (B != null && B != "") {
                    var C = JSON.parse(B);
                    if (C.ResultCode === 0 && m.SessionID != null && m.SessionID != "") {
                        ML4WebApi.setProperty("is_cs_install", true);
                        z(0, {
                            result: "install success"
                        })
                    } else {
                        z(ML4WebLog.getErrCode("CS_Manager_API_checkInstall"), {
                            errCode: 1,
                            errMsg: "not installed"
                        })
                    }
                } else {
                    z(ML4WebLog.getErrCode("CS_Manager_API_checkInstall"), {
                        errCode: 1,
                        errMsg: "not installed"
                    })
                }
            } else {
                z(ML4WebLog.getErrCode("CS_Manager_API_checkInstall"), {
                    errCode: 1,
                    errMsg: "not installed"
                })
            }
        })
    }

    function c(A) {
        ML4WebLog.log("CS_Manager.checkupdate() called...");
        var x = ML4WebApi.getProperty("browser");
        var y = p.makeJsonMessage("InstallCheck", m.SessionID, x, m.CsSessionTimeout);
        var z = ML4WebApi.getProperty("os");
        ML4WebApi.setProperty("is_cs_update", true);
        if (z == "Android" || z == "IPHONE" || z == "IPAD" || z == "BlackBerry") {
            A(ML4WebLog.getErrCode("CS_Manager_API_checkUpdate"), {
                errCode: 1,
                errMsg: "Mobile Access"
            })
        } else {
            e(m.CS_UR + m.CS_PORT + "/", y, function(B, C) {
                if (B == 0) {
                    if (C != null && C != "") {
                        var D = JSON.parse(C);
                        var E = h(D.ResultMessage);
                        if (E === true) {
                            ML4WebApi.setProperty("is_cs_update", false);
                            A("0", {
                                msg: "ok"
                            })
                        } else {
                            A(B, {
                                msg: "upgrade"
                            })
                        }
                    } else {
                        A(ML4WebLog.getErrCode("CS_Manager_API_checkUpdate"), {
                            errCode: 1,
                            errMsg: "InstallCheck Failed"
                        })
                    }
                } else {
                    A(ML4WebLog.getErrCode("CS_Manager_API_checkUpdate"), {
                        errCode: 2,
                        errMsg: C
                    })
                }
            })
        }
    }

    function r() {
        var A = "";
        try {
            var x = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (var y = 0; y < 20; y++) {
                A += x.charAt(Math.floor(magiclineUtil.makeRandomValue() / Math.pow(10, 16) * x.length))
            }
            return {
                code: 0,
                data: A
            }
        } catch (z) {
            return {
                code: 111,
                data: "makeSessionStringfailed"
            }
        }
    }

    function g(y) {
        if (m.SessionID == null || m.SessionID == "") {
            var x = r();
            if (x.code == 0) {
                ML4WebApi.setProperty("SessionID", $.trim(x.data));
                m.SessionID = $.trim(x.data);
                y(x.code, {
                    sid: m.SessionID
                })
            } else {
                y(ML4WebLog.getErrCode("CS_Manager_API_createSessionID"), {
                    errCode: 111,
                    errMsg: "error"
                })
            }
        } else {
            y(0, {
                sid: m.SessionID
            })
        }
    }

    function k(y) {
        var x = p.makeJsonMessage("SetProperty", encodeURIComponent(JSON.stringify(m)));
        e(m.CS_UR + m.CS_PORT + "/", x, function(z, A) {
            if (A != null && A != "") {
                var B = JSON.parse(A);
                if (B.ResultCode === 0 && m.SessionID != null && m.SessionID != "") {
                    y(0, {
                        msg: "setProperty success"
                    })
                } else {
                    y(1, {
                        msg: "setProperty failed"
                    })
                }
            } else {
                y(2, {
                    msg: "setProperty failed"
                })
            }
        })
    }

    function d() {
        var B = "";
        try {
            var A = navigator.userAgent,
                x;
            var z = A.toLowerCase();
            if (z.indexOf("edge") > -1) {
                B = "Edge" + z.substr(z.indexOf("edge") + 4, 3);
                B = B.replace("/", " ");
                return B
            } else {
                M = A.match(/(OPR|edge|opera|chrome|safari|firefox|msie|trident(?=\/))\/?\s*(\d+)/i) || [];
                if (/trident/i.test(M[1])) {
                    x = /\brv[ :]+(\d+)/g.exec(A) || [];
                    B = "IE " + (x[1] || "")
                }
                if (M[1] === "Chrome") {
                    x = A.match(/\bOPR\/(\d+)/);
                    if (x !== null) {
                        B = "Opera " + x[1];
                        return B
                    }
                }
                M = M[2] ? [M[1], M[2]] : [navigator.appName, navigator.appVersion, "-?"];
                if ((x = A.match(/version\/(\d+)/i)) !== null) {
                    M.splice(1, 1, x[1])
                }
                B = M.join(" ");
                return B
            }
        } catch (y) {
            ML4WebLog.log("[ getBrowser ][ error ][ " + y.message + " ]");
            return ""
        }
    }

    function l(y) {
        var x = false;
        navigator.msLaunchUri(y, function() {
            x = true
        }, function() {
            x = false
        })
    }

    function q(D) {
        try {
            var A = ML4WebApi.detectOs();
            var C = ML4WebApi.detectBrower();
            var z = ML4WebApi.getProperty("cs_url_scheme");
            var B = false;
            var x = location.protocol + "//" + location.host + ML4WebApi.getProperty("dirpath") + "UI/call.html";
            if (C.name.indexOf("Firefox") > -1 || C.name.indexOf("Chrome") > -1 || C.name.indexOf("Opera") > -1 || C.name.indexOf("Safari") > -1) {
                window.document.getElementById("startCs").src = z
            } else {
                if (!B) {
                    pop = window.open(x, "_blank", "width=315,height=115,left=5000,top=5000,resizable=no,toolbar=no,location=no,status=no");
                    pop.focus();
                    B = true
                } else {
                    if (!pop.closed && pop) {} else {
                        pop = window.open(x, "_blank", "width=315,height=115,left=5000,top=5000,resizable=no,toolbar=no,location=no,status=no");
                        B = true
                    }
                }
                setTimeout(function() {
                    pop.close()
                }, 3000)
            }
        } catch (y) {
            ML4WebLog.log("[ sendURLScheme ][ error ][ " + y.message + " ]");
            return ""
        }
    }

    function u(A, z, y, C) {
        var B = window.open(A, z, y);
        var x = window.setInterval(function() {
            try {
                if (B == null || B.closed) {
                    window.clearInterval(x);
                    C(B)
                }
            } catch (D) {
                console.log("Exception error")
            }
        }, 1000);
        return B
    }

    function o() {}

    function v() {}

    function e(x, y, z) {
        p.callLocalServerAPI(x, y, z)
    }

    function t() {
        var z = ML4WebApi.getProperty("os");
        z = z.toUpperCase();
        var x = false;
        var y = "32";
        if (z.indexOf("UBUNTU64") > -1) {
            x = true;
            y = "64"
        } else {
            if (z.indexOf("UBUNTU32") > -1) {
                x = true
            } else {
                if (z.indexOf("FEDORA64") > -1) {
                    x = true;
                    y = "64"
                } else {
                    if (z.indexOf("FEDORA32") > -1) {
                        x = true
                    } else {
                        if (z.indexOf("LINUX64") > -1) {
                            x = true;
                            y = "64"
                        } else {
                            if (z.indexOf("LINUX32") > -1) {
                                x = true
                            }
                        }
                    }
                }
            }
        }
        return {
            isLin: x,
            bit: y
        }
    }

    function h(x, z) {
        var A = x.split(".");
        var B = "";
        var C = ML4WebApi.getProperty("os");
        var y = t();
        if (C.indexOf("win") > -1) {
            B = ML4WebApi.ClientVersion.Win.split(".")
        } else {
            if (C.indexOf("MAC") > -1) {
                B = ML4WebApi.ClientVersion.Mac.split(".")
            }
        }
        if (y.isLin) {
            if (y.bit === "32") {
                B = ML4WebApi.ClientVersion.Lin32.split(".")
            } else {
                if (y.bit === "64") {
                    B = ML4WebApi.ClientVersion.Lin64.split(".")
                }
            }
        }
        if (Number(A[2]) < Number(B[2]) || Number(A[3]) < Number(B[3])) {
            return false
        } else {
            return true
        }
    }
    return {
        init: s,
        setProperty: k,
        callLocalServerAPI: e,
        checkinstall: j,
        checkupdate: c,
        CreateMagicLineSessionID: g,
        sendURLScheme: q
    }
});
var ML4WebApi = {
    ClientVersion: {
        Win: "",
        Mac: "",
        Lin64: "",
        Lin32: ""
    },
    HDSDOption: {
        eOption: false,
        kOption: ""
    },
    NTSOption: {
        signOption: false
    },
    UserInfo: {
        userDn: "",
        selectCertInfo: "",
        opt: ""
    },
    cryptoConfigOpt: {
        signaturescheme: {
            pkcs1v15: "RSASSA-PKCS1-v1_5",
            rsapss: "RSA-PSS"
        },
        encryptionscheme: {
            pkcs1v15: "RSAES-PKCS1-V1_5",
            rsaoaep: "RSA-OAEP"
        },
        mdalg: {
            sha1: "sha1",
            sha256: "sha256"
        },
        ds_symetric_algo: {
            seed: "seed"
        },
        ds_symmetric_algo: {
            PKI_CIPER_ALGO_SEEDCBC: "SEED-CBC",
            PKI_CIPER_ALGO_3DESCBC: "3DES-CBC",
            PKI_CIPER_ALGO_AIRACBC: "ARIA-CBC",
            PKI_CIPER_ALGO_AES128CBC: "AES128-CBC",
            PKI_CIPER_ALGO_AES192CBC: "AES192-CBC",
            PKI_CIPER_ALGO_AES256CBC: "AES256-CBC"
        },
        ds_pki_sign: {
            PKI_CERT_SIGN_OPT_NONE: "OPT_NONE",
            PKI_CERT_SIGN_OPT_USE_CONTNET_INFO: "OPT_USE_CONTNET_INFO",
            PKI_CERT_SIGN_OPT_NO_CONTENT: "OPT_NO_CONTENT",
            PKI_CERT_SIGN_OPT_SIGNKOREA_FORMAT: "OPT_SIGNKOREA_FORMAT"
        },
        ds_pki_irosSign: {
            PKI_CERT_SIGN_OPT_NONE: "OPT_NONE",
            PKI_CERT_SIGN_OPT_USE_CONTNET_INFO: "OPT_USE_CONTNET_INFO",
            PKI_CERT_SIGN_OPT_NO_CONTENT: "OPT_NO_CONTENT",
            PKI_CERT_SIGN_OPT_SIGNKOREA_FORMAT: "OPT_SIGNKOREA_FORMAT"
        },
        ds_pki_hash: {
            PKI_HASH_SHA1: "sha1",
            PKI_HASH_SHA256: "sha256",
            PKI_HASH_SHA384: "sha384",
            PKI_HASH_SHA512: "sha512"
        },
        ds_pki_rsa: {
            PKI_RSA_1_5: "rsa15",
            PKI_RSA_2_0: "rsa20"
        }
    },
    webConfig: {
        version: 1,
        protocoltype: "",
        dirpath: "",
        baseUrl: "",
        mlcertUrl: "",
        storageList_lnb: [],
        storageList: [],
        storageList_m: [],
        storageListMgmt: [],
        saveStorageList: [],
        defaultStorage: "",
        libType: 1,
        banner: false,
        bannerCloseButton: false,
        adminBanner: false,
        showCertDiv: false,
        logType: "console",
        ServiceID: "",
        CsServiceID: "",
        SessionID: "",
        AuthKey: "",
        MessageID: "",
        CsUrl: "",
        PfxExportDownloadUrl: "",
        isUseMLCert: false,
        selectedStorage: {},
        selectedCertificate: {},
        browser: "",
        os: "",
        is_cs_install: false,
        is_cs_update: false,
        encCert: "MIIFDzCCA/egAwIBAgIDP5lLMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAmtyMRAwDgYDVQQKDAd5ZXNzaWduMRUwEwYDVQQLDAxBY2NyZWRpdGVkQ0ExHzAdBgNVBAMMFnllc3NpZ25DQS1UZXN0IENsYXNzIDIwHhcNMTUwNDA5MTUwMDAwWhcNMTUwNTEwMTQ1OTU5WjByMQswCQYDVQQGEwJrcjEQMA4GA1UECgwHeWVzc2lnbjESMBAGA1UECwwJeFVzZTRrZnRjMQ0wCwYDVQQLDARLRlRDMS4wLAYDVQQDDCXqtIDshLjssq1UZXN0M08oKTAwOTk2OTMyMDE1MDQxMDAwMDA0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx7SjIDfGVJHL1kPeZ88w5YPKuU0zyVwze2v8P6fLOnFKwEnzhHs/FYq4D/ll/0xtFwUEmoizxI8Zag+rN32WuwqkXCfJe+h4RGO+MBmOjZxMsL6t3ZvkGS0424uNabCEMdYubQIoHha2zwlkKF2UaetNqCcnqrLyLHTC14T55F8/pGO3mYzuaIi1Gzajb0ECrQnWxzSFlNweoO/7E0Vtw4odawJLjDUbxddyw4RkSuQQ4vxawrT3S+5O3JLXGJBPnXTQ+w9Ks2qCWkeZ35lsbYurBSsV+2IVeUboye4IppsO+8MuJNJVE1mZloaTR78jStlypnwlAQfi5iVb1bT/1QIDAQABo4IBxzCCAcMwgZMGA1UdIwSBizCBiIAUFI+gSgul8+b3zCZGsZDSXYCc0vShbaRrMGkxCzAJBgNVBAYTAktSMQ0wCwYDVQQKDARLSVNBMS4wLAYDVQQLDCVLb3JlYSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBDZW50cmFsMRswGQYDVQQDDBJLaXNhIFRlc3QgUm9vdENBIDWCASUwHQYDVR0OBBYEFPAMqT+Iwa401xrdo8pbLNQBYhx2MA4GA1UdDwEB/wQEAwIFIDAaBgNVHSABAf8EEDAOMAwGCiqDGoyaRQEBBmMwKwYDVR0RBCQwIqAgBgkqgxqMmkQKAQGgEzARDA/qtIDshLjssq1UZXN0M08wdQYDVR0fBG4wbDBqoGigZoZkbGRhcDovL3Nub29weS55ZXNzaWduLm9yLmtyOjYwMjAvb3U9ZHAxNnA3NixvdT1BY2NyZWRpdGVkQ0Esbz15ZXNzaWduLGM9a3I/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdDA8BggrBgEFBQcBAQQwMC4wLAYIKwYBBQUHMAGGIGh0dHA6Ly9zbm9vcHkueWVzc2lnbi5vci5rcjo0NjEyMA0GCSqGSIb3DQEBCwUAA4IBAQAS9aqrS9/J+cPGiHKGlHVO/MZ73UK3XDCd7Eb2uc/P73eyvgdGeRz8ETswpU3ZEp4F94qkT4BFQLKet99lpKzf/CQ4KQeLvXawABQ4IZnZapPVufiN5e7yJdChcxMuzELA96KPASfsqk98/JjCF4WVa+rhoaRqYboe3c/i7OhIH3Eh0TfvuNKwP3tWoKLxfJcbhEJQ+EFuDks4WF0rz+wSbRBY7Yyck+JrBDb1b4dOi9EEbEmae+tyV53OgQKmO9sTiACH9o0qiMejx8Nt65sLz9e3NT3GFOtFfWh80zuCHrzNrh54xyCap33P87U8VwyswX6QCJbIkgYJWSJlwwRx",
        passwordFailCount: 0,
        sign_option: {},
        envelop_option: {},
        signenvelop_option: {},
        asymencrypt_option: {},
        asymdecrypt_option: {},
        language: "",
        usevirtualkeyboard: "",
        cs_port: "",
        cs_port_select: "",
        cs_ur: "",
        cs_download_win: "",
        cs_download_mac: "",
        cs_download_linux_fedora: "",
        cs_download_linux_ubuntu: "",
        cs_authserver_url: "",
        cs_authserver_cert: "",
        cs_timeout: "",
        cs_url_scheme: "",
        cs_install_type: "",
        cs_install_page_url: "",
        cert_base_url: "",
        cert_base_dir: "",
        cert_filter_type: "",
        cert_filter_use_type: "",
        cert_filter_expire: "",
        cert_filter_oid: "",
        cert_filter_subject_dn: "",
        cert_filter_issuer_dn: "",
        cert_filter_sign_serial: "",
        cert_filter_km_serial: "",
        cert_oid_name: "",
        cert_issuer_name: "",
        cert_filter_path: [],
        smartcert_type: "",
        cs_smartcert_serverip: "",
        cs_smartcert_serverport: "",
        cs_smartcert_sitedomain: "",
        cs_smartcert_raonsitecode: "",
        cs_smartcert_issuerdn: "",
        cs_smartcert_installurl: "",
        cs_smartcert_hidetokenlist: "",
        cs_smartcert_size: "",
        cs_smartcert_signorgview: "",
        cs_phone_type: "",
        cs_ubikey_version: "",
        cs_ubikey_popupurl: "",
        cs_ubikey_sparam: "",
        cs_ubikey_lparam: "",
        cs_ubikey_url: "",
        cs_mobilekey_popupurl: "",
        cs_mobisign_version: "",
        cs_mobisign_popupurl: "",
        cs_mobisign_sitecode: "",
        cs_smartcard_type: "",
        web_smartcert_multisign_yn: "",
        web_smartcert_subject: "",
        web_smartcert_issuer: "",
        web_smartcert_serial: "",
        web_smartcert_validate: false,
        web_smartcert_url: "",
        token_filter: [],
        tranx2PEM: "",
        getRandomfromPrivateKey: "",
        kftc_script_url_relay: "",
        kftc_script_url_opencert: "",
        kftc_corp_code: "",
        kftc_apikey: "",
        fincert_org_code: "",
        fincert_apikey: "",
        fincert_url: "",
        fincert_user_url: "",
        fincert_corp_url: "",
        cloud_server_host: "",
        cloud_server_port: "",
        cloud_clauseurl: "",
        cloud_site_code: "",
        cloud_app_id: "",
        cloud_customer_id: "",
        cloud_api_key: "",
        cloud_securedata_key: "",
        use_keyboard_secure: false,
        keyboard_secure_type: "",
        cryptoOpt: this.cryptoConfigOpt,
        use_session_storage: false
    },
    sessionConfig: {
        API_E2E_KEY: {},
        SESSION_ID: "",
        SESSION_KEY: "MLSession"
    },
    init: function(c) {
        ML4WebLog.init();
        try {
            ML4WebApi.detectBrower();
            ML4WebApi.detectOs()
        } catch (b) {
            ML4WebLog.log("ML4WebApi.init() === " + b.message);
            return
        }
        var a = "js/ML4Web_Config.js";
        if (a != "") {
            try {
                $.ajax({
                    async: false,
                    type: "GET",
                    dataType: "script",
                    url: a
                }).done(function(e, d) {
                    ML4WebApi.webConfig.protocoltype = ConfigObject.ProtocolType;
                    ML4WebApi.webConfig.dirpath = ConfigObject.DirPath;
                    ML4WebApi.webConfig.baseUrl = ConfigObject.BaseURL;
                    ML4WebApi.webConfig.mlcertUrl = ConfigObject.MLCertURL;
                    ML4WebApi.webConfig.storageList_lnb = ConfigObject.STORAGELIST_LNB;
                    ML4WebApi.webConfig.storageList = ConfigObject.STORAGELIST;
                    ML4WebApi.webConfig.storageList_m = ConfigObject.STORAGELIST_M;
                    ML4WebApi.webConfig.storageListMgmt = ConfigObject.STORAGELISTMGMT;
                    ML4WebApi.webConfig.saveStorageList = ConfigObject.saveStorageList;
                    ML4WebApi.webConfig.defaultStorage = ConfigObject.STORAGESELECT;
                    ML4WebApi.webConfig.libType = ConfigObject.CRYPTO;
                    ML4WebApi.webConfig.banner = ConfigObject.banner;
                    ML4WebApi.webConfig.bannerCloseButton = ConfigObject.bannerCloseButton;
                    ML4WebApi.webConfig.adminBanner = ConfigObject.adminBanner;
                    ML4WebApi.webConfig.showCertDiv = ConfigObject.showCertDiv;
                    ML4WebApi.webConfig.logType = ConfigObject.logType;
                    ML4WebApi.webConfig.ServiceID = ConfigObject.ServiceID;
                    ML4WebApi.webConfig.CsServiceID = ConfigObject.CsServiceID;
                    ML4WebApi.webConfig.MessageID = ConfigObject.MessageID;
                    ML4WebApi.webConfig.CsUrl = ConfigObject.CsUrl;
                    ML4WebApi.webConfig.PfxExportDownloadUrl = ConfigObject.PfxExportDownloadUrl;
                    ML4WebApi.webConfig.isUseMLCert = ConfigObject.isUseMLCert;
                    ML4WebApi.webConfig.passwordCountLimit = ConfigObject.passwordCountLimit;
                    ML4WebApi.webConfig.sign_option = ConfigObject.SIGN_OPTION;
                    ML4WebApi.webConfig.envelop_option = ConfigObject.ENVELOP_OPTION;
                    ML4WebApi.webConfig.signenvelop_option = ConfigObject.SIGNENVELOP_OPTION;
                    ML4WebApi.webConfig.asymencrypt_option = ConfigObject.ASYMENCRYPT_OPTION;
                    ML4WebApi.webConfig.asymdecrypt_option = ConfigObject.ASYMDECRYPT_OPTION;
                    ML4WebApi.webConfig.language = ConfigObject.LANGUAGE;
                    ML4WebApi.webConfig.useVirtualKeyboard = ConfigObject.USEVIRTUALKEYBOARD;
                    ML4WebApi.webConfig.virtualKeyboardType = ConfigObject.VIRTUALKEYBOARDTYPE;
                    ML4WebApi.webConfig.cs_port = ConfigObject.CS_PORT;
                    ML4WebApi.webConfig.cs_port_select = ConfigObject.CS_PORT_SELECT;
                    ML4WebApi.webConfig.cs_ur = ConfigObject.CS_UR;
                    ML4WebApi.webConfig.cs_download_win = ConfigObject.CS_DOWNLOAD_WIN;
                    ML4WebApi.webConfig.cs_download_mac = ConfigObject.CS_DOWNLOAD_MAC;
                    ML4WebApi.webConfig.cs_download_linux_fedora64 = ConfigObject.CS_DOWNLOAD_LINUX_FEDORA64;
                    ML4WebApi.webConfig.cs_download_linux_fedora32 = ConfigObject.CS_DOWNLOAD_LINUX_FEDORA32;
                    ML4WebApi.webConfig.cs_download_linux_ubuntu64 = ConfigObject.CS_DOWNLOAD_LINUX_UBUNTU64;
                    ML4WebApi.webConfig.cs_download_linux_ubuntu32 = ConfigObject.CS_DOWNLOAD_LINUX_UBUNTU32;
                    ML4WebApi.webConfig.cs_authserver_url = ConfigObject.CS_AUTHSERVER_URL;
                    ML4WebApi.webConfig.cs_authserver_cert = ConfigObject.CS_AUTHSERVER_CERT;
                    ML4WebApi.webConfig.cs_timeout = ConfigObject.CS_TIMEOUT;
                    ML4WebApi.webConfig.cs_url_scheme = ConfigObject.CS_URL_SCHEME, ML4WebApi.webConfig.cs_install_type = ConfigObject.CS_INSTALL_TYPE, ML4WebApi.webConfig.cs_install_page_url = ConfigObject.CS_INSTALL_PAGE_URL, ML4WebApi.webConfig.cert_base_url = ConfigObject.CERT_BASE_URL;
                    ML4WebApi.webConfig.cert_base_dir = ConfigObject.CERT_BASE_DIR;
                    ML4WebApi.webConfig.cert_filter_type = ConfigObject.CERT_FILTER_TYPE;
                    ML4WebApi.webConfig.cert_filter_use_type = ConfigObject.CERT_FILTER_USE_TYPE;
                    ML4WebApi.webConfig.cert_filter_expire = ConfigObject.CERT_FILTER_EXPIRE;
                    ML4WebApi.webConfig.cert_filter_oid = ConfigObject.CERT_FILTER_OID;
                    ML4WebApi.webConfig.cert_oid_name = ConfigObject.CERT_OID_NAME;
                    ML4WebApi.webConfig.cert_issuer_name = ConfigObject.CERT_ISSUER_NAME;
                    ML4WebApi.webConfig.cert_filter_path = ConfigObject.CERT_FILTER_PATH;
                    ML4WebApi.webConfig.smartcert_type = ConfigObject.SMARTCERT_TYPE;
                    ML4WebApi.webConfig.cs_smartcert_serverip = ConfigObject.CS_SMARTCERT_ServerIP;
                    ML4WebApi.webConfig.cs_smartcert_serverport = ConfigObject.CS_SMARTCERT_ServerPort;
                    ML4WebApi.webConfig.cs_smartcert_sitedomain = ConfigObject.CS_SMARTCERT_SiteDomain;
                    ML4WebApi.webConfig.cs_smartcert_installurl = ConfigObject.CS_SMARTCERT_InstallURL;
                    ML4WebApi.webConfig.cs_smartcert_raonsitecode = ConfigObject.CS_SMARTCERT_RaonSiteCode;
                    ML4WebApi.webConfig.cs_smartcert_issuerdn = ConfigObject.CS_SMARTCERT_IssuerDN;
                    ML4WebApi.webConfig.cs_smartcert_hidetokenlist = ConfigObject.CS_SMARTCERT_HideTokenList;
                    ML4WebApi.webConfig.cs_smartcert_signorgview = ConfigObject.CS_SMARTCERT_SignOrgView;
                    ML4WebApi.webConfig.cs_smartcert_size = ConfigObject.CS_SMARTCERT_SIZE;
                    ML4WebApi.webConfig.cs_phone_type = ConfigObject.CS_PHONE_TYPE;
                    ML4WebApi.webConfig.cs_ubikey_version = ConfigObject.CS_UBIKEY_Version;
                    ML4WebApi.webConfig.cs_ubikey_popupurl = ConfigObject.CS_UBIKEY_PopupURL;
                    ML4WebApi.webConfig.cs_ubikey_wparam = ConfigObject.CS_UBIKEY_wParam;
                    ML4WebApi.webConfig.cs_ubikey_lparam = ConfigObject.CS_UBIKEY_lParam;
                    ML4WebApi.webConfig.cs_ubikey_url = ConfigObject.CS_UBIKEY_URL;
                    ML4WebApi.webConfig.cs_mobilekey_popupurl = ConfigObject.CS_MOBILEKEY_PopupURL;
                    ML4WebApi.webConfig.cs_mobisign_version = ConfigObject.CS_MOBISIGN_Version;
                    ML4WebApi.webConfig.cs_mobisign_popupurl = ConfigObject.CS_MOBISIGN_PopupURL;
                    ML4WebApi.webConfig.cs_mobisign_sitecode = ConfigObject.CS_MOBISIGN_SiteCode;
                    ML4WebApi.webConfig.cs_smartcard_type = ConfigObject.CS_SMARTCARD_TYPE;
                    ML4WebApi.webConfig.web_smartcert_multisign_yn = ConfigObject.WEB_SMARTCERT_MultisignYn;
                    ML4WebApi.webConfig.web_smartcert_subject = ConfigObject.WEB_SMARTCERT_Subject;
                    ML4WebApi.webConfig.web_smartcert_issuer = ConfigObject.WEB_SMARTCERT_Issuer;
                    ML4WebApi.webConfig.web_smartcert_serial = ConfigObject.WEB_SMARTCERT_Serial;
                    ML4WebApi.webConfig.web_smartcert_validate = ConfigObject.WEB_SMARTCERT_Validate;
                    ML4WebApi.webConfig.web_smartcert_url = ConfigObject.WEB_SMARTCERT_URL;
                    ML4WebApi.webConfig.browserNoticeShow = ConfigObject.BROWSER_NOTICE_SHOW;
                    ML4WebApi.webConfig.browserNoticeImg = ConfigObject.BROWSER_NOTICE_IMG;
                    ML4WebApi.HDSDOption.eOption = ConfigObject.eOption;
                    ML4WebApi.HDSDOption.kOption = ConfigObject.kOption;
                    ML4WebApi.MobileOption = ConfigObject.MobileOption;
                    ML4WebApi.ClientVersion.Win = ConfigObject.WinClientVersion;
                    ML4WebApi.ClientVersion.Mac = ConfigObject.MacClientVersion;
                    ML4WebApi.ClientVersion.Lin64 = ConfigObject.Lin64ClientVersion;
                    ML4WebApi.ClientVersion.Lin32 = ConfigObject.Lin32ClientVersion;
                    ML4WebApi.DS_PKI_CERT_PATH = ConfigObject.DS_PKI_CERT_PATH;
                    ML4WebApi.DS_PKI_POLICY_OID = ConfigObject.DS_PKI_POLICY_OID;
                    ML4WebApi.webConfig.kftc_script_url_relay = ConfigObject.KFTC_SCRIPT_URL_RELAY;
                    ML4WebApi.webConfig.kftc_script_url_opencert = ConfigObject.KFTC_SCRIPT_URL_OPENCERT;
                    ML4WebApi.webConfig.kftc_corp_code = ConfigObject.KFTC_CORP_CODE;
                    ML4WebApi.webConfig.kftc_apikey = ConfigObject.KFTC_APIKEY;
                    ML4WebApi.webConfig.fincert_org_code = ConfigObject.FINCERT_ORGCODE;
                    ML4WebApi.webConfig.fincert_apikey = ConfigObject.FINCERT_APIKEY;
                    ML4WebApi.webConfig.fincert_url = ConfigObject.FINCERT_URL;
                    ML4WebApi.webConfig.fincert_user_url = ConfigObject.FINCERT_USER_URL;
                    ML4WebApi.webConfig.fincert_corp_url = ConfigObject.FINCERT_CORP_URL;
                    ML4WebApi.webConfig.use_keyboard_secure = ConfigObject.USE_KEYBOARD_SECURE;
                    ML4WebApi.webConfig.keyboard_secure_type = ConfigObject.KEYBOARD_SECURE_TYPE;
                    ML4WebApi.webConfig.token_filter = ConfigObject.TOKEN_FILTER;
                    ML4WebApi.webConfig.AuthKey = ConfigObject.AuthKey;
                    ML4WebApi.webConfig.cloud_server_host = ConfigObject.CLOUD_SERVER_HOST;
                    ML4WebApi.webConfig.cloud_server_port = ConfigObject.CLOUD_SERVER_PORT;
                    ML4WebApi.webConfig.cloud_clauseurl = ConfigObject.CLOUD_CLAUSEURL;
                    ML4WebApi.webConfig.cloud_site_code = ConfigObject.CLOUD_SITE_CODE;
                    ML4WebApi.webConfig.cloud_app_id = ConfigObject.CLOUD_APP_ID;
                    ML4WebApi.webConfig.cloud_customer_id = ConfigObject.CLOUD_CUSTOMER_ID;
                    ML4WebApi.webConfig.cloud_api_key = ConfigObject.CLOUD_API_KEY;
                    ML4WebApi.webConfig.cloud_securedata_key = ConfigObject.CLOUD_SECUREDATA_KEY;
                    ML4WebApi.webConfig.magicjs_lic = ConfigObject.MAGICJS_LIC;
                    ML4WebApi.webConfig.use_session_storage = ConfigObject.USE_SESSION_STORAGE;
                    csConfigOpt = {
                        Version: ML4WebApi.webConfig.version,
                        ServiceID: ML4WebApi.webConfig.ServiceID,
                        CsServiceID: ML4WebApi.webConfig.CsServiceID,
                        SessionID: ML4WebApi.webConfig.SessionID,
                        AuthKey: ML4WebApi.webConfig.AuthKey,
                        MessageID: ML4WebApi.webConfig.MessageID,
                        CrossServerURL: ML4WebApi.webConfig.cs_authserver_url,
                        CrossServerCert: ML4WebApi.webConfig.cs_authserver_cert,
                        SessionTimeout: ML4WebApi.webConfig.cs_timeout,
                        CS_PORT: ML4WebApi.webConfig.cs_port,
                        CS_PORT_SELECT: ML4WebApi.webConfig.cs_port_select,
                        CS_UR: ML4WebApi.webConfig.cs_ur,
                        CS_DOWNLOAD_WIN: ML4WebApi.webConfig.cs_download_win,
                        CS_DOWNLOAD_MAC: ML4WebApi.webConfig.cs_download_mac,
                        CS_DOWNLOAD_FEDORA64: ML4WebApi.webConfig.cs_download_linux_fedora64,
                        CS_DOWNLOAD_FEDORA32: ML4WebApi.webConfig.cs_download_linux_fedora32,
                        CS_DOWNLOAD_UBUNTU64: ML4WebApi.webConfig.cs_download_linux_ubuntu64,
                        CS_DOWNLOAD_UBUNTU32: ML4WebApi.webConfig.cs_download_linux_ubuntu32,
                        CrossServerURL: ML4WebApi.webConfig.cs_authserver_url,
                        CsSessionTimeout: ML4WebApi.webConfig.cs_timeout,
                        CS_URL_SCHEME: ML4WebApi.webConfig.cs_url_scheme,
                        CS_INSTALL_TYPE: ML4WebApi.webConfig.cs_install_type,
                        CS_INSTALL_PAGE_URL: ML4WebApi.webConfig.cs_install_page_url,
                        CERT_FILTER_TYPE: ML4WebApi.webConfig.cert_filter_type,
                        CERT_FILTER_USE_TYPE: ML4WebApi.webConfig.cert_filter_use_type,
                        CERT_FILTER_OID: ML4WebApi.webConfig.cert_filter_oid,
                        CERT_FILTER_SIGN_SERIAL: ML4WebApi.webConfig.cert_filter_sign_serial,
                        CERT_FILTER_KM_SERIAL: ML4WebApi.webConfig.cert_filter_km_serial,
                        CERT_FILTER_SUBJECT_DN: ML4WebApi.webConfig.cert_filter_subject_dn,
                        CERT_FILTER_ISSUER_DN: ML4WebApi.webConfig.cert_filter_issuer_dn,
                        CERT_FILTER_EXPIRE: ML4WebApi.webConfig.cert_filter_expire,
                        CERT_FILTER_PATH: ML4WebApi.webConfig.cert_filter_path,
                        CS_SMARTCERT_HideTokenList: ML4WebApi.webConfig.cs_smartcert_hidetokenlist,
                        CS_SMARTCARD_TYPE: ML4WebApi.webConfig.cs_smartcard_type,
                        CS_PHONE_TYPE: ML4WebApi.webConfig.cs_phone_type,
                        CS_UBIKEY_Version: ML4WebApi.webConfig.cs_ubikey_version,
                        CS_UBIKEY_PopupURL: ML4WebApi.webConfig.cs_ubikey_popupurl,
                        CS_UBIKEY_wParam: ML4WebApi.webConfig.cs_ubikey_wparam,
                        CS_UBIKEY_lParam: ML4WebApi.webConfig.cs_ubikey_lparam,
                        CS_MOBILEKEY_PopupURL: ML4WebApi.webConfig.cs_mobilekey_popupurl,
                        CS_MOBISIGN_Version: ML4WebApi.webConfig.cs_mobisign_version,
                        CS_MOBISIGN_PopupUrl: ML4WebApi.webConfig.cs_mobisign_popupurl,
                        CS_MOBISIGN_SiteCode: ML4WebApi.webConfig.cs_mobisign_sitecode,
                        CS_SMARTCERT_ServerIP: ML4WebApi.webConfig.cs_smartcert_serverip,
                        CS_SMARTCERT_ServerPort: ML4WebApi.webConfig.cs_smartcert_serverport,
                        CS_SMARTCERT_SiteDomain: ML4WebApi.webConfig.cs_smartcert_sitedomain,
                        CS_SMARTCERT_RaonSiteCode: ML4WebApi.webConfig.cs_smartcert_raonsitecode,
                    };
                    ML4WebApi.setDSCertFieldInfo();
                    ML4WebApi.loadResource(c)
                }).fail(function(e, d) {
                    ML4WebLog.log("Config Load fail... === status : " + d)
                })
            } catch (b) {
                ML4WebLog.log("[Error] ML4WebApi.init() config load === " + b.message);
                return
            }
        }
    },
    setProperty: function(a, b) {
        ML4WebApi.webConfig[a] = b
    },
    getProperty: function(a) {
        return ML4WebApi.webConfig[a]
    },
    getResourceApi: function() {
        return ML4WebApi.ml4web_resource_api
    },
    getStorageApi: function() {
        return ML4WebApi.ml4web_storage_api
    },
    getCryptoApi: function() {
        return ML4WebApi.ml4web_crypto_api
    },
    getCsManager: function() {
        return ML4WebApi.ml4web_cs_manager
    },
    getSupportStorage: function(a) {
        if (typeof a != "function" || a == null || a == "") {
            a("getSupportStorage", {
                errCode: 103,
                errMsg: $.i18n.prop("ER103")
            });
            return
        }
        return a(0, {
            storagelist: ML4WebApi.webConfig.storageList
        })
    },
    getCertiList: function(a) {
        ML4WebLog.log("ML4WebApi.getCertiList() called...");
        return ML4WebApi.webConfig.selectedStorage.certificates.certi_list
    },
    saveSelectCert: function(b) {
        ML4WebLog.log("ML4WebApi.saveSelectCert() called...");
        var a = JSON.stringify(b);
        selectedCertificate = b
    },
    makeSignData: function(a, b, c, f, g) {
        ML4WebLog.log("ML4WebApi.makeSignData() called... ");
        ML4WebApi.UserInfo.selectCertInfo = a;
        ML4WebApi.UserInfo.opt = c;
        if (a == null || a == "") {
            if (ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                storageRawCertIdx = {};
                storageRawCertIdx.storageName = "smartcert";
                storageRawCertIdx.storageOpt = {};
                storageRawCertIdx.storageOpt.smartCertOpt = {};
                storageRawCertIdx.storageCertIdx = "";
                if (ML4WebApi.getProperty("smartcert_type") == "C") {
                    storageRawCertIdx.storageOpt.smartCertOpt.servicename = "dreamCS";
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt = {};
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMServerIP = ML4WebApi.getProperty("cs_smartcert_serverip");
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMServerPort = ML4WebApi.getProperty("cs_smartcert_serverport");
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMSiteDomain = ML4WebApi.getProperty("cs_smartcert_sitedomain");
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMInstallURL = ML4WebApi.getProperty("cs_smartcert_installurl");
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMRaonSiteCode = "";
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMTokenInstallURL = ""
                }
            } else {
                g(ML4WebLog.getErrCode("ML4Web_API_MakeSignData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            }
        } else {
            if (ML4WebApi.getProperty("selectedStorage").key == "mobile" && b == "mobisign") {
                storageRawCertIdx = {};
                storageRawCertIdx.storageName = "mobile";
                storageRawCertIdx.storageOpt = c;
                storageRawCertIdx.storageCertIdx = "0"
            } else {
                if (b == null || b == "") {
                    g(ML4WebLog.getErrCode("ML4Web_API_MakeSignData"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof g != "function" || g == null || g == "") {
                        g(ML4WebLog.getErrCode("ML4Web_API_MakeSignData"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    } else {
                        if (f === "" || $.isEmptyObject(f)) {
                            f = "signMessage"
                        }
                        if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                            storageRawCertIdx = JSON.parse(a)
                        } else {
                            if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                                storageRawCertIdx = JSON.parse(ML4WebApi.dsDecrypt(a))
                            } else {
                                storageRawCertIdx = JSON.parse(a)
                            }
                        }
                    }
                }
            }
        }
        try {
            ML4WebApi.ml4web_storage_api.Sign(storageRawCertIdx, c, b, f, function(e, j) {
                if (e == 0) {
                    var h = "";
                    if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert" || (ML4WebApi.getProperty("selectedStorage").key == "mobile" && b == "mobisign")) {
                        var k = JSON.stringify(j);
                        h = k
                    } else {
                        var k = JSON.stringify(j.storageCertIdx);
                        if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                            h = ML4WebApi.dsencrypt(k)
                        } else {
                            h = k
                        }
                    }
                    j.storageCertIdx = h;
                    j.serverCert = ML4WebApi.getProperty("cs_authserver_cert");
                    var l = j.userCert.length;
                    j.tranx2PEM = "-----BEGIN CERTIFICATE-----\n";
                    for (i = 0; i < l; i += 64) {
                        j.tranx2PEM += j.userCert.substr(i, 64) + "\n"
                    }
                    j.tranx2PEM += "-----END CERTIFICATE-----\n";
                    ML4WebApi.webConfig.tranx2PEM = j.tranx2PEM;
                    ML4WebApi.ml4web_crypto_api.getcertInfo(j.userCert, [], function(m, n) {
                        ML4WebApi.UserInfo.userDn = ML4WebApi.makeReverseDN(n.result.subjectname)
                    });
                    j.selectStorage = ML4WebApi.getProperty("selectedStorage").key;
                    g(0, j);
                    return
                } else {
                    g(e, j);
                    return
                }
            })
        } catch (d) {
            g(ML4WebLog.getErrCode("ML4Web_API_MakeSignData"), {
                errCode: 888,
                errMsg: d.message
            });
            return
        }
    },
    signFinCertAPI: function(f, o) {
        var d = "";
        ML4WebCert.criteria.signType = "";
        ML4WebApi.setProperty("getRandomfromPrivateKey", "");
        if ((typeof(f.signOpt) != "undefined") && (typeof(f.signOpt.ds_msg_decode) != "undefined") && (f.signOpt.ds_msg_decode === "hash")) {
            d = "hash"
        }
        var b = [];
        var k = [];
        if (f != null && typeof(f) != "undefined" && typeof(f.signOpt) != "undefined" && typeof(f.signOpt.ds_pki_sign_type) != "undefined" && f.signOpt.ds_pki_sign_type == "sign") {
            f.signType = "xmlsignature"
        }
        if (typeof(f.signType) != "undefined" && f.signType.toLowerCase() == "xmlsignature") {
            if (typeof(f.msg) != "undefined" && f.msg instanceof Array) {
                for (var j = 0; j < f.msg.length; j++) {
                    b.push(ML4WebApi.encodeUrlSafeBase64(unescape(encodeURIComponent(f.msg[j]))))
                }
            } else {
                b.push(ML4WebApi.encodeUrlSafeBase64(unescape(encodeURIComponent(f.msg))))
            }
            FinCertInt.Sdk.sign({
                signFormat: {
                    type: "PKCS1",
                    PKCS1Info: {
                        includeR: true
                    }
                },
                content: {
                    binary: {
                        binaries: b
                    }
                },
                view: {
                    lastAccessCert: false,
                    oid: {
                        "1.2.410.200005.1.1.1.10": true,
                    }
                },
                info: {
                    signType: "01"
                },
                success: function(p) {
                    var t;
                    var r = p.certificate;
                    ML4WebApi.setProperty("getRandomfromPrivateKey", ML4WebApi.decodeUrlSafeBase64(p.rValue));
                    if (typeof(f.msg) != "undefined" && f.msg instanceof Array) {
                        t = [];
                        for (var s = 0; s < f.msg.length; s++) {
                            t.push(ML4WebApi.decodeUrlSafeBase64(p.signedVals[s]))
                        }
                    } else {
                        t = ML4WebApi.decodeUrlSafeBase64(p.signedVals[0])
                    }
                    var q = {
                        certInfo: "",
                        certbag: {
                            signcert: ML4WebApi.decodeUrlSafeBase64(r)
                        },
                        code: 0,
                        encMsg: t,
                        isPosted: true,
                        selectStorage: "fincert"
                    };
                    ML4WebCert.criteria.signType = "fincert";
                    ML4WebApi.ml4web_crypto_api.getcertInfo(q.certbag.signcert, [], function(u, v) {
                        if (u == 0) {
                            q.certInfo = v.result;
                            o("0", q)
                        } else {
                            ML4WebDraw.errorHandler("main", $.i18n.prop("ES054"), null, null)
                        }
                    })
                },
                fail: function(p) {
                    console.log(p.code + " : " + p.message);
                    o("1", p.message)
                },
            })
        } else {
            if (typeof(f.signType) != "undefined" && f.signType.toLowerCase() == "makesigndata") {
                var h = false;
                var g = {};
                if (d === "hash") {
                    h = true;
                    if (typeof(f) == "object" && f.msg instanceof Array) {
                        for (var j = 0; j < f.msg.length; j++) {
                            k.push(ML4WebApi.encodeUrlSafeBase64(magicjs.hex.decode(f.msg[j])))
                        }
                    } else {
                        k.push(ML4WebApi.encodeUrlSafeBase64(magicjs.hex.decode(f.msg)))
                    }
                    g.hash = {};
                    g.hash.hashes = [];
                    g.hash.hashes = k;
                    g.hash.hashAlgorithm = "SHA-256"
                } else {
                    if ((typeof(f.signOpt) != "undefined") && (typeof(f.signOpt.ds_msg_decode) != "undefined") && (f.signOpt.ds_msg_decode === "true")) {
                        if (f.signOpt.ds_pki_sign != null && typeof(f.signOpt.ds_pki_sign) != "undefined" && f.signOpt.ds_pki_sign.indexOf("OPT_HASHED_CONTENT") >= 0) {
                            h = true;
                            if (typeof(f) == "object" && f.msg instanceof Array) {
                                for (var j = 0; j < f.msg.length; j++) {
                                    k.push(ML4WebApi.encodeUrlSafeBase64(magicjs.base64.decode(f.msg[j])))
                                }
                            } else {
                                k.push(ML4WebApi.encodeUrlSafeBase64(magicjs.base64.decode(f.msg)))
                            }
                            g.hash = {};
                            g.hash.hashes = [];
                            g.hash.hashes = k;
                            g.hash.hashAlgorithm = "SHA-256"
                        } else {
                            if (typeof(f) == "object" && f.msg instanceof Array) {
                                for (var j = 0; j < f.msg.length; j++) {
                                    var n = magicjs.base64.decode(f.msg[j]);
                                    n = ML4WebApi.encodeUrlSafeBase64(n);
                                    b.push(n)
                                }
                            } else {
                                var n = magicjs.base64.decode(f.msg);
                                n = ML4WebApi.encodeUrlSafeBase64(n);
                                b.push(n)
                            }
                            if (typeof(f.signOpt.ds_msg_decode) != "undefined" && f.signOpt.ds_msg_decode == "true") {
                                g.binary = {};
                                g.binary.binaries = b
                            } else {
                                g.plainText = {};
                                g.plainText.plainTexts = [];
                                g.plainText.plainTexts = b;
                                g.plainText.encoding = "UTF-8"
                            }
                        }
                    } else {
                        if (typeof(f) == "object" && f.msg instanceof Array) {
                            for (var j = 0; j < f.msg.length; j++) {
                                b.push(f.msg[j])
                            }
                        } else {
                            if (typeof(f.signOpt.ds_msg_decode) != "undefined" && f.signOpt.ds_msg_decode == "true") {
                                var n = magicjs.base64.decode(f.msg);
                                n = ML4WebApi.encodeUrlSafeBase64(n);
                                b.push(n)
                            } else {
                                b.push(f.msg)
                            }
                        }
                        if (typeof(f.signOpt.ds_msg_decode) != "undefined" && f.signOpt.ds_msg_decode == "true") {
                            g.binary = {};
                            g.binary.binaries = b
                        } else {
                            g.plainText = {};
                            g.plainText.plainTexts = [];
                            g.plainText.plainTexts = b;
                            g.plainText.encoding = "UTF-8"
                        }
                    }
                }
                var a = getTimeStamp();
                var m = new DSASN1();
                var e = {};
                e.signFormat = {};
                e.signFormat.type = "CMS";
                e.signFormat.CMSInfo = {};
                e.signFormat.CMSInfo.ssn = "dummy";
                e.signFormat.CMSInfo.time = a;
                e.signFormat.CMSInfo.includeR = true;
                e.signFormat.CMSInfo.withoutContent = h;
                e.content = g;
                e.info = {};
                e.info.signType = "01";
                e.success = function(v) {
                    var p;
                    var q = [];
                    if (typeof(f) == "object" && f.msg instanceof Array) {
                        p = [];
                        for (var B = 0; B < v.signedVals.length; B++) {
                            p.push(ML4WebApi.decodeUrlSafeBase64(v.signedVals[B]))
                        }
                        cmsMsg = p[0]
                    } else {
                        p = ML4WebApi.decodeUrlSafeBase64(v.signedVals[0]);
                        cmsMsg = p
                    }
                    var t = m.ASN1Util.decode(magicjs.base64.decode(cmsMsg));
                    var E = t.sub[1];
                    var r = E.sub[0];
                    var s = magicjs.base64.encode(magicjs.hex.decode(r.sub[3].sub[0].toHexString()));
                    var y = r.sub[4];
                    var z = y.sub[0];
                    var A = z.sub[6];
                    var H = A.sub[0];
                    var x = H.sub[1];
                    var w = x.sub[0];
                    var D = w.sub[0];
                    var C = D.sub[0];
                    var G = D.sub[1];
                    var F = magicjs.base64.encode(G.stream.enc.slice(G.stream.pos + G.header + 1, G.stream.pos + G.header + 1 + G.length));
                    ML4WebApi.setProperty("getRandomfromPrivateKey", ML4WebApi.decodeUrlSafeBase64(F));
                    var u = {
                        certInfo: "",
                        certbag: {
                            signcert: ML4WebApi.decodeUrlSafeBase64(s)
                        },
                        code: 0,
                        encMsg: p,
                        isPosted: true,
                        selectStorage: "fincert"
                    };
                    ML4WebCert.criteria.signType = "fincert";
                    ML4WebApi.ml4web_crypto_api.getcertInfo(u.certbag.signcert, [], function(I, J) {
                        if (I == 0) {
                            u.certInfo = J.result;
                            if (f.vidType == "client") {
                                magiclineController.getVIDRandom(ML4WebCert.certCallback, u)
                            } else {
                                u.randonNum = F;
                                o("0", u)
                            }
                        } else {
                            ML4WebDraw.errorHandler("main", $.i18n.prop("ES054"), null, null)
                        }
                    })
                };
                e.fail = function(p) {
                    o("1", p.message)
                };
                if (typeof(f.signOpt.ds_pki_sign_type) != "undefined" && f.signOpt.ds_pki_sign_type == "addsigneddata") {
                    var l = {};
                    var c = {};
                    c.multiSigner = {};
                    c.multiSigner.signedData = [];
                    c.multiSigner.signedData.push(ML4WebApi.encodeUrlSafeBase64(magicjs.base64.decode(f.msg)));
                    l.signFormat = {};
                    l.signFormat.type = "CMS";
                    l.signFormat.CMSInfo = {};
                    l.signFormat.CMSInfo.ssn = "dummy";
                    l.signFormat.CMSInfo.time = "CLIENT";
                    l.signFormat.CMSInfo.includeR = true;
                    l.signFormat.CMSInfo.withoutContent = false;
                    l.content = c;
                    l.info = {};
                    l.info.signType = "01";
                    l.success = function(v) {
                        var p;
                        var q = [];
                        if (typeof(f) == "object" && f.msg instanceof Array) {
                            p = [];
                            for (var B = 0; B < v.signedVals.length; B++) {
                                p.push(ML4WebApi.decodeUrlSafeBase64(v.signedVals[B]))
                            }
                            cmsMsg = p[0]
                        } else {
                            p = ML4WebApi.decodeUrlSafeBase64(v.signedVals[0]);
                            cmsMsg = p
                        }
                        var t = m.ASN1Util.decode(magicjs.base64.decode(cmsMsg));
                        var E = t.sub[1];
                        var r = E.sub[0];
                        var G = r.sub[3].sub.length;
                        if (G > 1) {
                            G = G - 1
                        }
                        var s = magicjs.base64.encode(magicjs.hex.decode(r.sub[3].sub[G].toHexString()));
                        var y = r.sub[4];
                        var z = y.sub[G];
                        var A = z.sub[6];
                        var I = A.sub[0];
                        var x = I.sub[1];
                        var w = x.sub[0];
                        var D = w.sub[0];
                        var C = D.sub[0];
                        var H = D.sub[1];
                        var F = magicjs.base64.encode(H.stream.enc.slice(H.stream.pos + H.header + 1, H.stream.pos + H.header + 1 + H.length));
                        ML4WebApi.setProperty("getRandomfromPrivateKey", ML4WebApi.decodeUrlSafeBase64(F));
                        var u = {
                            certInfo: "",
                            certbag: {
                                signcert: ML4WebApi.decodeUrlSafeBase64(s)
                            },
                            code: 0,
                            encMsg: p,
                            isPosted: true,
                            selectStorage: "fincert"
                        };
                        ML4WebCert.criteria.signType = "fincert";
                        ML4WebApi.ml4web_crypto_api.getcertInfo(u.certbag.signcert, [], function(J, K) {
                            if (J == 0) {
                                u.certInfo = K.result;
                                if (f.vidType == "client") {
                                    magiclineController.getVIDRandom(ML4WebCert.certCallback, u)
                                } else {
                                    u.randonNum = F;
                                    o("0", u)
                                }
                            } else {
                                ML4WebDraw.errorHandler("main", $.i18n.prop("ES054"), null, null)
                            }
                        });
                        return
                    };
                    l.fail = function(p) {
                        o("1", p.message)
                    };
                    FinCertInt.Sdk.sign(l)
                } else {
                    FinCertInt.Sdk.sign(e)
                }
            }
        }
    },
    signFinCertUserAPI: function(d, l) {
        var c = "";
        ML4WebCert.criteria.signType = "";
        ML4WebApi.setProperty("getRandomfromPrivateKey", "");
        if ((typeof(d.signOpt) != "undefined") && (typeof(d.signOpt.ds_msg_decode) != "undefined") && (d.signOpt.ds_msg_decode === "hash")) {
            c = "hash"
        }
        if (d != null && typeof(d) != "undefined" && typeof(d.signOpt) != "undefined" && typeof(d.signOpt.ds_pki_sign_type) != "undefined" && d.signOpt.ds_pki_sign_type == "sign") {
            d.signType = "xmlsignature"
        }
        var b = [];
        var h = [];
        if (typeof(d.signType) != "undefined" && d.signType.toLowerCase() == "xmlsignature") {
            if (typeof(d.msg) != "undefined" && d.msg instanceof Array) {
                for (var g = 0; g < d.msg.length; g++) {
                    b.push(ML4WebApi.encodeUrlSafeBase64(unescape(encodeURIComponent(d.msg[g]))))
                }
            } else {
                b.push(ML4WebApi.encodeUrlSafeBase64(unescape(encodeURIComponent(d.msg))))
            }
            FinCert.Sdk.sign({
                signFormat: {
                    type: "PKCS1",
                    PKCS1Info: {
                        includeR: true
                    }
                },
                content: {
                    binary: {
                        binaries: b
                    }
                },
                view: {
                    lastAccessCert: false,
                    oid: {
                        "1.2.410.200005.1.1.1.10": true,
                    }
                },
                info: {
                    signType: "01"
                },
                success: function(m) {
                    var q;
                    var o = m.certificate;
                    ML4WebApi.setProperty("getRandomfromPrivateKey", ML4WebApi.decodeUrlSafeBase64(m.rValue));
                    if (typeof(d.msg) != "undefined" && d.msg instanceof Array) {
                        q = [];
                        for (var p = 0; p < d.msg.length; p++) {
                            q.push(ML4WebApi.decodeUrlSafeBase64(m.signedVals[p]))
                        }
                    } else {
                        q = ML4WebApi.decodeUrlSafeBase64(m.signedVals[0])
                    }
                    var n = {
                        certInfo: "",
                        certbag: {
                            signcert: ML4WebApi.decodeUrlSafeBase64(o)
                        },
                        code: 0,
                        encMsg: q,
                        isPosted: true,
                        selectStorage: "fincert_user"
                    };
                    ML4WebCert.criteria.signType = "fincert_user";
                    ML4WebApi.ml4web_crypto_api.getcertInfo(n.certbag.signcert, [], function(r, s) {
                        if (r == 0) {
                            n.certInfo = s.result;
                            l("0", n)
                        } else {
                            ML4WebDraw.errorHandler("main", $.i18n.prop("ES054"), null, null)
                        }
                    })
                },
                fail: function(m) {
                    console.log(m.code + " : " + m.message);
                    l("1", m.message)
                },
            })
        } else {
            if (typeof(d.signType) != "undefined" && d.signType.toLowerCase() == "makesigndata") {
                var f = false;
                var e = {};
                if (c === "hash") {
                    f = true;
                    if (typeof(d) == "object" && d.msg instanceof Array) {
                        for (var g = 0; g < d.msg.length; g++) {
                            h.push(ML4WebApi.encodeUrlSafeBase64(magicjs.hex.decode(d.msg[g])))
                        }
                    } else {
                        h.push(ML4WebApi.encodeUrlSafeBase64(magicjs.hex.decode(d.msg)))
                    }
                    e.hash = {};
                    e.hash.hashes = [];
                    e.hash.hashes = h;
                    e.hash.hashAlgorithm = "SHA-256"
                } else {
                    if (typeof(d) == "object" && d.msg instanceof Array) {
                        for (var g = 0; g < d.msg.length; g++) {
                            b.push(d.msg[g])
                        }
                    } else {
                        if (typeof(d.signOpt.ds_msg_decode) != "undefined" && d.signOpt.ds_msg_decode == "true") {
                            var k = magicjs.base64.decode(d.msg);
                            k = ML4WebApi.encodeUrlSafeBase64(k);
                            b.push(k)
                        } else {
                            b.push(d.msg)
                        }
                    }
                    if (typeof(d.signOpt.ds_msg_decode) != "undefined" && d.signOpt.ds_msg_decode == "true") {
                        e.binary = {};
                        e.binary.binaries = b
                    } else {
                        e.plainText = {};
                        e.plainText.plainTexts = [];
                        e.plainText.plainTexts = b;
                        e.plainText.encoding = "UTF-8"
                    }
                }
                var a = getTimeStamp();
                var j = new DSASN1();
                FinCert.Sdk.sign({
                    signFormat: {
                        type: "CMS",
                        CMSInfo: {
                            ssn: "dummy",
                            time: a,
                            withoutContent: f
                        }
                    },
                    content: e,
                    info: {
                        signType: "01"
                    },
                    success: function(s) {
                        var m;
                        var n = [];
                        if (typeof(d) == "object" && d.msg instanceof Array) {
                            m = [];
                            for (var y = 0; y < s.signedVals.length; y++) {
                                m.push(ML4WebApi.decodeUrlSafeBase64(s.signedVals[y]))
                            }
                            cmsMsg = m[0]
                        } else {
                            m = ML4WebApi.decodeUrlSafeBase64(s.signedVals[0]);
                            cmsMsg = m
                        }
                        var q = j.ASN1Util.decode(magicjs.base64.decode(cmsMsg));
                        var B = q.sub[1];
                        var o = B.sub[0];
                        var p = magicjs.base64.encode(magicjs.hex.decode(o.sub[3].sub[0].toHexString()));
                        var v = o.sub[4];
                        var w = v.sub[0];
                        var x = w.sub[6];
                        var E = x.sub[0];
                        var u = E.sub[1];
                        var t = u.sub[0];
                        var A = t.sub[0];
                        var z = A.sub[0];
                        var D = A.sub[1];
                        var C = magicjs.base64.encode(D.stream.enc.slice(D.stream.pos + D.header + 1, D.stream.pos + D.header + 1 + D.length));
                        ML4WebApi.setProperty("getRandomfromPrivateKey", ML4WebApi.decodeUrlSafeBase64(C));
                        var r = {
                            certInfo: "",
                            certbag: {
                                signcert: ML4WebApi.decodeUrlSafeBase64(p)
                            },
                            code: 0,
                            encMsg: m,
                            isPosted: true,
                            selectStorage: "fincert_user"
                        };
                        ML4WebCert.criteria.signType = "fincert_user";
                        ML4WebApi.ml4web_crypto_api.getcertInfo(r.certbag.signcert, [], function(F, G) {
                            if (F == 0) {
                                r.certInfo = G.result;
                                if (d.vidType == "client") {
                                    magiclineController.getVIDRandom(ML4WebCert.certCallback, r)
                                } else {
                                    l("0", r)
                                }
                            } else {
                                ML4WebDraw.errorHandler("main", $.i18n.prop("ES054"), null, null)
                            }
                        })
                    },
                    fail: function(m) {
                        console.log(m.code + " : " + m.message);
                        l("1", m.message)
                    },
                })
            }
        }
    },
    signAndUCPIDFinCertUserAPI: function(d, m) {
        var c = "";
        ML4WebCert.criteria.signType = "";
        ML4WebApi.setProperty("getRandomfromPrivateKey", "");
        if ((typeof(d.signOpt) != "undefined") && (typeof(d.signOpt.ds_msg_decode) != "undefined") && (d.signOpt.ds_msg_decode === "hash")) {
            c = "hash"
        }
        if (d != null && typeof(d) != "undefined" && typeof(d.signOpt) != "undefined" && typeof(d.signOpt.ds_pki_sign_type) != "undefined" && d.signOpt.ds_pki_sign_type == "sign") {
            d.signType = "xmlsignature"
        }
        var b = [];
        var h = [];
        if (typeof(d.signType) != "undefined" && d.signType.toLowerCase() == "makesigndata") {
            var f = false;
            var e = {};
            var n = {};
            if (c === "hash") {
                f = true;
                if (typeof(d) == "object" && d.msg instanceof Array) {
                    for (var g = 0; g < d.msg.length; g++) {
                        h.push(ML4WebApi.encodeUrlSafeBase64(magicjs.hex.decode(d.msg[g])))
                    }
                } else {
                    h.push(ML4WebApi.encodeUrlSafeBase64(magicjs.hex.decode(d.msg)))
                }
                e.hash = {};
                e.hash.hashes = [];
                e.hash.hashes = h;
                e.hash.hashAlgorithm = "SHA-256"
            } else {
                if (typeof(d) == "object" && d.msg instanceof Array) {
                    for (var g = 0; g < d.msg.length; g++) {
                        b.push(d.msg[g])
                    }
                } else {
                    if (typeof(d.signOpt.ds_msg_decode) != "undefined" && d.signOpt.ds_msg_decode == "true") {
                        var k = magicjs.base64.decode(d.msg);
                        k = ML4WebApi.encodeUrlSafeBase64(k);
                        b.push(k)
                    } else {
                        b.push(d.msg)
                    }
                }
                if (typeof(d.signOpt.ds_msg_decode) != "undefined" && d.signOpt.ds_msg_decode == "true") {
                    e.binary = {};
                    e.binary.binaries = b
                } else {
                    e.plainText = {};
                    e.plainText.plainTexts = [];
                    e.plainText.plainTexts = b;
                    e.plainText.encoding = "UTF-8"
                }
            }
            n.ucpidInfo = {};
            n.ucpidInfo.ispUrlInfo = d.ispUrlInfo;
            var l = d.ucpidNonce;
            n.ucpidInfo.ucpidNonce = l;
            n.ucpidInfo.userAgreement = d.userAgreement;
            n.ucpidInfo.userAgreeInfo = {};
            n.ucpidInfo.userAgreeInfo.realName = d.userAgreeInfo.realName;
            n.ucpidInfo.userAgreeInfo.gender = d.userAgreeInfo.gender;
            n.ucpidInfo.userAgreeInfo.nationalInfo = d.userAgreeInfo.nationalInfo;
            n.ucpidInfo.userAgreeInfo.birthDate = d.userAgreeInfo.birthDate;
            n.ucpidInfo.userAgreeInfo.ci = d.userAgreeInfo.ci;
            var a = getTimeStamp();
            var j = new DSASN1();
            FinCert.Sdk.sign([{
                signFormat: {
                    type: "CMS",
                    CMSInfo: {
                        ssn: "dummy",
                        time: a,
                        withoutContent: f
                    }
                },
                content: e,
                info: {
                    signType: "01"
                },
                success: function(v) {
                    var o;
                    var p = [];
                    if (typeof(d) == "object" && d.msg instanceof Array) {
                        o = [];
                        for (var B = 0; B < v[0].signedVals.length; B++) {
                            o.push(ML4WebApi.decodeUrlSafeBase64(v[0].signedVals[B]))
                        }
                        cmsMsg = o[0]
                    } else {
                        o = ML4WebApi.decodeUrlSafeBase64(v[0].signedVals[0]);
                        cmsMsg = o
                    }
                    var s = j.ASN1Util.decode(magicjs.base64.decode(cmsMsg));
                    var F = s.sub[1];
                    var q = F.sub[0];
                    var r = magicjs.base64.encode(magicjs.hex.decode(q.sub[3].sub[0].toHexString()));
                    var y = q.sub[4];
                    var z = y.sub[0];
                    var A = z.sub[6];
                    var I = A.sub[0];
                    var x = I.sub[1];
                    var w = x.sub[0];
                    var E = w.sub[0];
                    var D = E.sub[0];
                    var H = E.sub[1];
                    var G = magicjs.base64.encode(H.stream.enc.slice(H.stream.pos + H.header + 1, H.stream.pos + H.header + 1 + H.length));
                    ML4WebApi.setProperty("getRandomfromPrivateKey", ML4WebApi.decodeUrlSafeBase64(G));
                    var C = ML4WebApi.decodeUrlSafeBase64(v[1].signedVals[0]);
                    var u = d.ucpidNonce;
                    var t = {
                        certInfo: "",
                        certbag: {
                            signcert: ML4WebApi.decodeUrlSafeBase64(r)
                        },
                        code: 0,
                        encMsg: o,
                        isPosted: true,
                        selectStorage: "fincert_user",
                        ucpidRequestInfo: C,
                        vidRandom: G,
                        ucpidNonce: u
                    };
                    ML4WebCert.criteria.signType = "fincert_user";
                    m("0", t)
                },
                fail: function(o) {
                    console.log(o.code + " : " + o.message);
                    m("1", o.message)
                },
            }, {
                signFormat: {
                    type: "CMS",
                    CMSInfo: {
                        ssn: "dummy",
                        time: a,
                        withoutContent: f
                    }
                },
                content: n,
                info: {
                    signType: "01"
                },
                success: function(u) {
                    var o;
                    var p = [];
                    if (typeof(d) == "object" && d.msg instanceof Array) {
                        o = [];
                        for (var A = 0; A < u.signedVals.length; A++) {
                            o.push(ML4WebApi.decodeUrlSafeBase64(u.signedVals[A]))
                        }
                        cmsMsg = o[0]
                    } else {
                        o = ML4WebApi.decodeUrlSafeBase64(u.signedVals[0]);
                        cmsMsg = o
                    }
                    var s = j.ASN1Util.decode(magicjs.base64.decode(cmsMsg));
                    var D = s.sub[1];
                    var q = D.sub[0];
                    var r = magicjs.base64.encode(magicjs.hex.decode(q.sub[3].sub[0].toHexString()));
                    var x = q.sub[4];
                    var y = x.sub[0];
                    var z = y.sub[6];
                    var G = z.sub[0];
                    var w = G.sub[1];
                    var v = w.sub[0];
                    var C = v.sub[0];
                    var B = C.sub[0];
                    var F = C.sub[1];
                    var E = magicjs.base64.encode(F.stream.enc.slice(F.stream.pos + F.header + 1, F.stream.pos + F.header + 1 + F.length));
                    ML4WebApi.setProperty("getRandomfromPrivateKey", ML4WebApi.decodeUrlSafeBase64(E));
                    var t = {
                        certInfo: "",
                        certbag: {
                            signcert: ML4WebApi.decodeUrlSafeBase64(r)
                        },
                        code: 0,
                        encMsg: o,
                        isPosted: true,
                        selectStorage: "fincert_user"
                    };
                    ML4WebCert.criteria.signType = "fincert_user";
                    ML4WebApi.ml4web_crypto_api.getcertInfo(t.certbag.signcert, [], function(H, I) {
                        if (H == 0) {
                            t.certInfo = I.result;
                            if (d.vidType == "client") {
                                magiclineController.getVIDRandom(ML4WebCert.certCallback, t)
                            } else {
                                m("0", t)
                            }
                        } else {
                            ML4WebDraw.errorHandler("main", $.i18n.prop("ES054"), null, null)
                        }
                    })
                },
                fail: function(o) {
                    console.log(o.code + " : " + o.message);
                    m("1", o.message)
                },
            }])
        }
    },
    signFinCertCorpAPI: function(d, l) {
        var c = "";
        ML4WebCert.criteria.signType = "";
        ML4WebApi.setProperty("getRandomfromPrivateKey", "");
        if ((typeof(d.signOpt) != "undefined") && (typeof(d.signOpt.ds_msg_decode) != "undefined") && (d.signOpt.ds_msg_decode === "hash")) {
            c = "hash"
        }
        if (d != null && typeof(d) != "undefined" && typeof(d.signOpt) != "undefined" && typeof(d.signOpt.ds_pki_sign_type) != "undefined" && d.signOpt.ds_pki_sign_type == "sign") {
            d.signType = "xmlsignature"
        }
        var b = [];
        var h = [];
        if (typeof(d.signType) != "undefined" && d.signType.toLowerCase() == "xmlsignature") {
            if (typeof(d.msgArray) != "undefined" && d.msgArray.length > 0) {
                for (var g = 0; g < d.msgArray.length; g++) {
                    b.push(ML4WebApi.encodeUrlSafeBase64(unescape(encodeURIComponent(d.msgArray[g]))))
                }
            } else {
                if (typeof(d.msg) != "undefined" && d.msg instanceof Array) {
                    for (var g = 0; g < d.msg.length; g++) {
                        b.push(ML4WebApi.encodeUrlSafeBase64(unescape(encodeURIComponent(d.msg[g]))))
                    }
                } else {
                    b.push(ML4WebApi.encodeUrlSafeBase64(unescape(encodeURIComponent(d.msg))))
                }
            }
            FinCertCorp.Sdk.sign({
                signFormat: {
                    type: "PKCS1",
                    PKCS1Info: {
                        includeR: true
                    }
                },
                content: {
                    binary: {
                        binaries: b
                    }
                },
                view: {
                    lastAccessCert: false,
                    oid: {
                        "1.2.410.200005.1.1.1.10": true,
                    }
                },
                info: {
                    signType: "01"
                },
                success: function(m) {
                    var q;
                    var o = m.certificate;
                    ML4WebApi.setProperty("getRandomfromPrivateKey", ML4WebApi.decodeUrlSafeBase64(m.rValue));
                    if (typeof(d.msgArray) != "undefined") {
                        q = [];
                        for (var p = 0; p < d.msgArray.length; p++) {
                            q.push(ML4WebApi.decodeUrlSafeBase64(m.signedVals[p]))
                        }
                    } else {
                        if (typeof(d.msg) != "undefined" && d.msg instanceof Array) {
                            q = [];
                            for (var p = 0; p < d.msg.length; p++) {
                                q.push(ML4WebApi.decodeUrlSafeBase64(m.signedVals[p]))
                            }
                        } else {
                            q = ML4WebApi.decodeUrlSafeBase64(m.signedVals[0])
                        }
                    }
                    var n = {
                        certInfo: "",
                        certbag: {
                            signcert: ML4WebApi.decodeUrlSafeBase64(o)
                        },
                        code: 0,
                        encMsg: q,
                        isPosted: true,
                        selectStorage: "fincert_corp",
                        vidRandom: ML4WebApi.getProperty("getRandomfromPrivateKey")
                    };
                    ML4WebCert.criteria.signType = "fincert_corp";
                    ML4WebApi.ml4web_crypto_api.getcertInfo(n.certbag.signcert, [], function(r, s) {
                        if (r == 0) {
                            n.certInfo = s.result;
                            l("0", n)
                        } else {
                            ML4WebDraw.errorHandler("main", $.i18n.prop("ES054"), null, null)
                        }
                    })
                },
                fail: function(m) {
                    console.log(m.code + " : " + m.message);
                    l("1", m.message)
                },
            })
        } else {
            if (typeof(d.signType) != "undefined" && d.signType.toLowerCase() == "makesigndata") {
                var f = false;
                var e = {};
                if (c === "hash") {
                    f = true;
                    if (typeof(d) == "object" && d.msg instanceof Array) {
                        for (var g = 0; g < d.msg.length; g++) {
                            h.push(ML4WebApi.encodeUrlSafeBase64(magicjs.hex.decode(d.msg[g])))
                        }
                    } else {
                        h.push(ML4WebApi.encodeUrlSafeBase64(magicjs.hex.decode(d.msg)))
                    }
                    e.hash = {};
                    e.hash.hashes = [];
                    e.hash.hashes = h;
                    e.hash.hashAlgorithm = "SHA-256"
                } else {
                    if (typeof(d) == "object" && d.msg instanceof Array) {
                        for (var g = 0; g < d.msg.length; g++) {
                            b.push(d.msg[g])
                        }
                    } else {
                        if (typeof(d.signOpt.ds_msg_decode) != "undefined" && d.signOpt.ds_msg_decode == "true") {
                            var k = magicjs.base64.decode(d.msg);
                            k = ML4WebApi.encodeUrlSafeBase64(k);
                            b.push(k)
                        } else {
                            b.push(d.msg)
                        }
                    }
                    if (typeof(d.signOpt.ds_msg_decode) != "undefined" && d.signOpt.ds_msg_decode == "true") {
                        e.binary = {};
                        e.binary.binaries = b
                    } else {
                        e.plainText = {};
                        e.plainText.plainTexts = [];
                        e.plainText.plainTexts = b;
                        e.plainText.encoding = "UTF-8"
                    }
                }
                var a = getTimeStamp();
                var j = new DSASN1();
                FinCertCorp.Sdk.sign({
                    signFormat: {
                        type: "CMS",
                        CMSInfo: {
                            ssn: "dummy",
                            time: a,
                            withoutContent: f
                        }
                    },
                    content: e,
                    info: {
                        signType: "01"
                    },
                    success: function(s) {
                        var n;
                        var m = [];
                        if (typeof(d) == "object" && d.msg instanceof Array) {
                            n = [];
                            for (var y = 0; y < s.signedVals.length; y++) {
                                n.push(ML4WebApi.decodeUrlSafeBase64(s.signedVals[y]))
                            }
                            m = n[0]
                        } else {
                            n = ML4WebApi.decodeUrlSafeBase64(s.signedVals[0]);
                            m = n
                        }
                        var q = j.ASN1Util.decode(magicjs.base64.decode(m));
                        var B = q.sub[1];
                        var o = B.sub[0];
                        var p = magicjs.base64.encode(magicjs.hex.decode(o.sub[3].sub[0].toHexString()));
                        var v = o.sub[4];
                        var w = v.sub[0];
                        var x = w.sub[6];
                        var E = x.sub[0];
                        var u = E.sub[1];
                        var t = u.sub[0];
                        var A = t.sub[0];
                        var z = A.sub[0];
                        var D = A.sub[1];
                        var C = magicjs.base64.encode(D.stream.enc.slice(D.stream.pos + D.header + 1, D.stream.pos + D.header + 1 + D.length));
                        ML4WebApi.setProperty("getRandomfromPrivateKey", ML4WebApi.decodeUrlSafeBase64(C));
                        var r = {
                            certInfo: "",
                            certbag: {
                                signcert: ML4WebApi.decodeUrlSafeBase64(p)
                            },
                            code: 0,
                            encMsg: n,
                            isPosted: true,
                            selectStorage: "fincert_corp"
                        };
                        ML4WebCert.criteria.signType = "fincert_corp";
                        ML4WebApi.ml4web_crypto_api.getcertInfo(r.certbag.signcert, [], function(F, G) {
                            if (F == 0) {
                                r.certInfo = G.result;
                                if (d.vidType == "client") {
                                    magiclineController.getVIDRandom(ML4WebCert.certCallback, r)
                                } else {
                                    l("0", r)
                                }
                            } else {
                                ML4WebDraw.errorHandler("main", $.i18n.prop("ES054"), null, null)
                            }
                        })
                    },
                    fail: function(m) {
                        console.log(m.code + " : " + m.message);
                        l("1", m.message)
                    },
                })
            }
        }
    },
    encodeUrlSafeBase64: function(a) {
        a = magicjs.base64.encode(a);
        a = a.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        return a
    },
    decodeUrlSafeBase64: function(a) {
        if (a.length % 4 != 0) {
            a += Array(5 - a.length % 4).join("=")
        }
        a = a.replace(/\-/g, "+").replace(/\_/g, "/");
        return a
    },
    makeSignatureData: function(a, b, c, f, g) {
        ML4WebLog.log("ML4WebApi.makeSignatureData() called... ");
        ML4WebApi.UserInfo.selectCertInfo = a;
        ML4WebApi.UserInfo.opt = c;
        if (a == null || a == "") {
            if (ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                storageRawCertIdx = {};
                storageRawCertIdx.storageName = "smartcert";
                storageRawCertIdx.storageOpt = {};
                storageRawCertIdx.storageOpt.smartCertOpt = {};
                storageRawCertIdx.storageCertIdx = "";
                if (ML4WebApi.getProperty("smartcert_type") == "C") {
                    storageRawCertIdx.storageOpt.smartCertOpt.servicename = "dreamCS";
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt = {};
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMServerIP = ML4WebApi.getProperty("cs_smartcert_serverip");
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMServerPort = ML4WebApi.getProperty("cs_smartcert_serverport");
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMSiteDomain = ML4WebApi.getProperty("cs_smartcert_sitedomain");
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMInstallURL = ML4WebApi.getProperty("cs_smartcert_installurl");
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMRaonSiteCode = "";
                    storageRawCertIdx.storageOpt.smartCertOpt.serviceOpt.USIMTokenInstallURL = ""
                }
            } else {
                g(ML4WebLog.getErrCode("ML4Web_API_makeSignatureData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            }
        } else {
            if (ML4WebApi.getProperty("selectedStorage").key == "mobile" && b == "mobisign") {
                storageRawCertIdx = {};
                storageRawCertIdx.storageName = "mobile";
                storageRawCertIdx.storageOpt = c;
                storageRawCertIdx.storageCertIdx = "0"
            } else {
                if (b == null || b == "") {
                    g(ML4WebLog.getErrCode("ML4Web_API_makeSignatureData"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof g != "function" || g == null || g == "") {
                        g(ML4WebLog.getErrCode("ML4Web_API_makeSignatureData"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    } else {
                        if (f === "" || $.isEmptyObject(f)) {
                            f = "signMessage"
                        }
                        if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                            storageRawCertIdx = JSON.parse(a)
                        } else {
                            if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                                storageRawCertIdx = JSON.parse(ML4WebApi.dsDecrypt(a))
                            } else {
                                storageRawCertIdx = JSON.parse(a)
                            }
                        }
                    }
                }
            }
        }
        try {
            ML4WebApi.ml4web_storage_api.Signature(storageRawCertIdx, c, b, f, function(e, j) {
                if (e == 0) {
                    var h = "";
                    if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert" || (ML4WebApi.getProperty("selectedStorage").key == "mobile" && b == "mobisign")) {
                        var k = JSON.stringify(j);
                        h = k
                    } else {
                        var k = JSON.stringify(j.storageCertIdx);
                        if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                            h = ML4WebApi.dsencrypt(k)
                        } else {
                            h = k
                        }
                    }
                    j.storageCertIdx = h;
                    j.serverCert = ML4WebApi.getProperty("cs_authserver_cert");
                    var l = j.userCert.length;
                    j.tranx2PEM = "-----BEGIN CERTIFICATE-----\n";
                    for (i = 0; i < l; i += 64) {
                        j.tranx2PEM += j.userCert.substr(i, 64) + "\n"
                    }
                    j.tranx2PEM += "-----END CERTIFICATE-----\n";
                    ML4WebApi.webConfig.tranx2PEM = j.tranx2PEM;
                    ML4WebApi.ml4web_crypto_api.getcertInfo(j.userCert, [], function(m, n) {
                        ML4WebApi.UserInfo.userDn = ML4WebApi.makeReverseDN(n.result.subjectname)
                    });
                    j.selectStorage = ML4WebApi.getProperty("selectedStorage").key;
                    g(0, j);
                    return
                } else {
                    g(e, j);
                    return
                }
            })
        } catch (d) {
            g(ML4WebLog.getErrCode("ML4Web_API_makeSignatureData"), {
                errCode: 888,
                errMsg: d.message
            });
            return
        }
    },
    makeEnvelopData: function(c, d, b, l) {
        ML4WebLog.log("ML4WebApi.makeEnvelopData() called... ");
        var f = JSON.parse(ML4WebApi.dsDecrypt(c));
        try {
            var h = "MIIEODCCAyCgAwIBAgIBLDANBgkqhkiG9w0BAQUFADBNMQswCQYDVQQGEwJLUjENMAsGA1UECgwES0lDQTEVMBMGA1UECwwMQWNjcmVkaXRlZENBMRgwFgYDVQQDDA9zaWduR0FURSBGVENBMDIwHhcNMTAwMzExMDkxMDAwWhcNMTEwMzExMDkwOTU5WjBPMQswCQYDVQQGEwJLUjENMAsGA1UECgwES0lDQTEVMBMGA1UECwwMQWNjcmVkaXRlZENBMRowGAYDVQQDDBFTR1Rlc3QxMDI0KHZhbGlkKTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAxiIJBNmSX8i/zWgG7fpmycOXtcJ5Ww3dxySghzSxctazodN2OQ2RSwyxQC2D2LhGMI0VbvnHDZ1hJiIqZBBmCKDsBfgKyh/uAcqfRuEss4FUt4441DiomhrcjuBJ13VE/Qp600KgWclUweUo5nYUSGErNdBpTCxXRWQTKFuRJJ0CAwEAAaOCAaMwggGfMIGUBgNVHSMEgYwwgYmAFDHO//V7tgLkh1DwmD73U8Ry0Ih+oW2kazBpMQswCQYDVQQGEwJLUjENMAsGA1UECgwES0lTQTEuMCwGA1UECwwlS29yZWEgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgQ2VudHJhbDEbMBkGA1UEAwwSS0lTQSBUZXN0IFJvb3RDQSA0ggIn0zAdBgNVHQ4EFgQUcngKL5PvhbjJNt87ZsvgQRpLIoIwDgYDVR0PAQH/BAQDAgUgMBkGA1UdIAEB/wQPMA0wCwYJKoMajJpEAoFJMGAGA1UdEQRZMFegVQYJKoMajJpECgEBoEgwRgwRU0dUZXN0MTAyNCh2YWxpZCkwMTAvBgoqgxqMmkQKAQEBMCEwBwYFKw4DAhqgFgQUfEFOxehZcoGfAR6bnEyt2Px0YQ0wWgYDVR0fBFMwUTBPoE2gS4ZJbGRhcDovL2FwcC5zaWduZ2F0ZS5jb206Mzg5L291PWRwMnAxLG91PWNybGRwLG91PUFjY3JlZGl0ZWRDQSxvPUtJQ0EsYz1LUjANBgkqhkiG9w0BAQUFAAOCAQEATgDc4qeAjY1Hlo9ZUy6xNOWH5eSnJ+ymcGrZygWlQX+9+qpJICEz2omeqBs66Aou+RyCnGru/j+2wxIQjUFvxqAXXFwzEs2ja/lNYsjMSTHXwq57ZAo5Hyc6W9vEjhEQ/aYiBFNz76crJcaq3S9KzoMVMS4IejSADXhbr90h166nNhu8Fk02xnvrgZZJXrtdlNJY9x1el71bNZoJiS5qW2sAS/P7S9uuEVPcUb1rLBRBp4uQe/NPo/Yvmmm0G20uLfp21qOyWwn2O/xInYmGkfPf764KsE+oSxXOJWu7bTJsZghQiITbKUMzkphiRlKewaG4eD3Rl7LHQZNd5/JSZQ==";
            var a = b;
            var j = "SEED-CBC";
            var k = ML4WebApi.webConfig.envelop_option;
            ML4WebApi.ml4web_crypto_api.envelopedData(h, a, j, k, function(e, m) {
                if (e == 0) {
                    if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                        var n = JSON.stringify(m);
                        encCertIdxStr = n
                    } else {
                        var n = JSON.stringify(m.storageCertIdx);
                        if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                            encCertIdxStr = ML4WebApi.dsencrypt(n)
                        } else {
                            encCertIdxStr = n
                        }
                    }
                    m.storageCertIdx = encCertIdxStr;
                    l(0, m);
                    return
                } else {
                    l(e, m);
                    return
                }
            })
        } catch (g) {
            l(ML4WebLog.getErrCode("ML4Web_API_MakeEnvelopData"), {
                errCode: 888,
                errMsg: g.message
            });
            return
        }
    },
    makeSignedEnvelopedData: function(a, d, b, c, h, j) {
        ML4WebLog.log("ML4WebApi.makeSignedEnvelopedData() called... ");
        var g = JSON.parse(ML4WebUtil.ML4WebApi.dsDecrypt(a));
        if (encCert == null) {
            encCert = ML4WebApi.webConfig.encCert
        }
        try {
            if (g.storageName == "hdd" || g.storageName == "token") {
                ml4web_storage_api.SingedEnvelopedData(g, d, c, b, h, function(e, l) {
                    if (e == 0) {
                        var m = JSON.stringify(l.storageCertIdx);
                        var k = m;
                        l.storageCertIdx = k;
                        j(0, l)
                    } else {
                        j(e, l)
                    }
                })
            } else {
                getCertString(JSON.parse(g), function(e, k) {
                    if (e == 0) {
                        if (k != null) {
                            ML4WebApi.ml4web_crypto_api.signedEnvelopedData(k.cert.kmcert, funcOpt.b64SignCert, funcOpt.b64SignPri, b, c.sAlgo, c.sSignOption, function(l, n) {
                                if (l == 0) {
                                    var m = "";
                                    if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                                        var o = JSON.stringify(n);
                                        m = o
                                    } else {
                                        var o = JSON.stringify(n.storageCertIdx);
                                        if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                                            m = ML4WebApi.dsencrypt(o)
                                        } else {
                                            m = o
                                        }
                                    }
                                    n.storageCertIdx = m;
                                    j(0, n)
                                } else {
                                    j(l, n)
                                }
                            })
                        } else {
                            j(ML4WebLog.getErrCode("ML4Web_API_MakeSignedEnvelopedData"), {
                                errCode: 202,
                                errMsg: $.i18n.prop("ER202")
                            })
                        }
                    } else {
                        j(ML4WebLog.getErrCode("ML4Web_API_MakeSignedEnvelopedData"), {
                            errCode: e,
                            errMsg: k.errMsg
                        })
                    }
                })
            }
        } catch (f) {
            j(ML4WebLog.getErrCode("ML4Web_API_MakeSignedEnvelopedData"), {
                errCode: 888,
                errMsg: f.message
            })
        }
    },
    makeIrosSignData: function(a, b, c, g, h) {
        ML4WebLog.log("ML4WebApi.makeIrosSignData() called... ");
        var f = "";
        if (a == null || a == "") {
            if (ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                f = {};
                f.storageName = "smartcert";
                f.storageOpt = {};
                f.storageOpt.smartCertOpt = {};
                if (ML4WebApi.getProperty("smartcert_type") == "C") {
                    f.storageOpt.smartCertOpt.servicename = "dreamCS";
                    f.storageOpt.smartCertOpt.serviceOpt = {};
                    f.storageOpt.smartCertOpt.serviceOpt.USIMServerIP = ML4WebApi.getProperty("cs_smartcert_serverip");
                    f.storageOpt.smartCertOpt.serviceOpt.USIMSiteDomain = ML4WebApi.getProperty("cs_smartcert_sitedomain");
                    f.storageOpt.smartCertOpt.serviceOpt.USIMInstallURL = ML4WebApi.getProperty("cs_smartcert_installurl")
                }
            } else {
                h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosSignData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            }
        } else {
            if (b == null || b == "") {
                h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosSignData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (g == null || g == "") {
                    h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosSignData"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof h != "function" || h == null || h == "") {
                        h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosSignData"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    } else {
                        if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                            f = JSON.parse(a)
                        } else {
                            if (ML4WebUI.selectedStorage.current_option.storageName == "web" || ML4WebUI.selectedStorage.current_option.storageName == "pfx") {
                                f = JSON.parse(ML4WebApi.dsDecrypt(a))
                            } else {
                                f = JSON.parse(a)
                            }
                        }
                    }
                }
            }
        }
        try {
            ML4WebApi.ml4web_storage_api.IrosSign(f, c, b, g, function(e, k) {
                if (e == 0) {
                    var j = "";
                    if (ML4WebApi.webConfig.libType == 0) {
                        var l = JSON.stringify(k);
                        j = l
                    } else {
                        var l = JSON.stringify(k.storageCertIdx);
                        j = ML4WebApi.dsencrypt(l)
                    }
                    k.storageCertIdx = j;
                    k.serverCert = ML4WebApi.getProperty("cs_authserver_cert");
                    h(0, k)
                } else {
                    h(e, k)
                }
            })
        } catch (d) {
            h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosSignData"), {
                errCode: 888,
                errMsg: d.message
            })
        }
    },
    makeIrosAddSignData: function(a, b, c, g, h) {
        ML4WebLog.log("ML4WebApi.makeIrosAddSignData() called... ");
        var f = "";
        if (a == null || a == "") {
            if (ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                f = {};
                f.storageName = "smartcert";
                f.storageOpt = {};
                f.storageOpt.smartCertOpt = {};
                if (ML4WebApi.getProperty("smartcert_type") == "C") {
                    f.storageOpt.smartCertOpt.servicename = "dreamCS";
                    f.storageOpt.smartCertOpt.serviceOpt = {};
                    f.storageOpt.smartCertOpt.serviceOpt.USIMServerIP = ML4WebApi.getProperty("cs_smartcert_serverip");
                    f.storageOpt.smartCertOpt.serviceOpt.USIMSiteDomain = ML4WebApi.getProperty("cs_smartcert_sitedomain");
                    f.storageOpt.smartCertOpt.serviceOpt.USIMInstallURL = ML4WebApi.getProperty("cs_smartcert_installurl")
                }
            } else {
                h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosAddSignData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            }
        } else {
            if (b == null || b == "") {
                h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosAddSignData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (g == null || g == "") {
                    h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosAddSignData"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof h != "function" || h == null || h == "") {
                        h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosAddSignData"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    } else {
                        if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                            f = JSON.parse(a)
                        } else {
                            if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                                f = JSON.parse(ML4WebApi.dsDecrypt(a))
                            } else {
                                f = JSON.parse(a)
                            }
                        }
                    }
                }
            }
        }
        try {
            ML4WebApi.ml4web_storage_api.IrosAddSignData(f, c, b, g, function(e, k) {
                if (e == 0) {
                    var j = "";
                    if (ML4WebApi.webConfig.libType == 0) {
                        var l = JSON.stringify(k);
                        j = l
                    } else {
                        var l = JSON.stringify(k.storageCertIdx);
                        j = ML4WebApi.dsencrypt(l)
                    }
                    k.storageCertIdx = j;
                    k.serverCert = ML4WebApi.getProperty("cs_authserver_cert");
                    h(0, k)
                } else {
                    h(e, k)
                }
            })
        } catch (d) {
            h(ML4WebLog.getErrCode("ML4Web_API_MakeIrosAddSignData"), {
                errCode: 888,
                errMsg: d.message
            })
        }
    },
    makeIrosMultiData: function(d, a, f, b) {
        ML4WebLog.log("ML4WebApi.makeIrosMultiData() called... ");
        var g = "";
        if (d == null || d == "") {
            if (ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                g = {};
                g.storageName = "smartcert";
                g.storageOpt = {};
                g.storageOpt.smartCertOpt = {};
                if (ML4WebApi.getProperty("smartcert_type") == "C") {
                    g.storageOpt.smartCertOpt.servicename = "dreamCS";
                    g.storageOpt.smartCertOpt.serviceOpt = {};
                    g.storageOpt.smartCertOpt.serviceOpt.USIMServerIP = ML4WebApi.getProperty("cs_smartcert_serverip");
                    g.storageOpt.smartCertOpt.serviceOpt.USIMSiteDomain = ML4WebApi.getProperty("cs_smartcert_sitedomain");
                    g.storageOpt.smartCertOpt.serviceOpt.USIMInstallURL = ML4WebApi.getProperty("cs_smartcert_installurl")
                }
            } else {
                return {
                    code: ML4WebLog.getErrCode("ML4Web_API_MakeIrosMultiData"),
                    data: {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    }
                }
            }
        } else {
            if (a == null || a == "") {
                return {
                    code: ML4WebLog.getErrCode("ML4Web_API_MakeIrosMultiData"),
                    data: {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    }
                }
            } else {
                if (b == null || b == "") {
                    return {
                        code: ML4WebLog.getErrCode("ML4Web_API_MakeIrosMultiData"),
                        data: {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        }
                    }
                } else {
                    if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
                        g = JSON.parse(d)
                    } else {
                        if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                            g = JSON.parse(ML4WebApi.dsDecrypt(d))
                        } else {
                            g = JSON.parse(d)
                        }
                    }
                }
            }
        }
        try {
            var c = new Array();
            var m;
            var l = JSON.parse(b);
            var o = Object.keys(l);
            var k = 0;
            var n = "";
            if (Object.keys(l).length >= 1) {
                for (k = 0; k < Object.keys(l).length; k++) {
                    m = o[k];
                    if (m.substring(m.length - 4).indexOf("sig") > -1) {
                        try {
                            var j = ML4WebApi.ml4web_resource_api.getSignedDataAndPdf(l[m]);
                            f.ds_pki_signdata = j.signedData;
                            n = ML4WebApi.ml4web_storage_api.IrosMultiAddSign(g, f, a, j.pdf);
                            if (n.code != 0) {
                                return {
                                    code: n.code,
                                    data: n.data
                                };
                                break
                            } else {
                                c[k] = m + "&&" + n.data
                            }
                        } catch (h) {
                            return {
                                code: ML4WebLog.getErrCode("ML4Web_API_MakeIrosMultiData"),
                                data: {
                                    errCode: 888,
                                    errMsg: h.message
                                }
                            };
                            break
                        }
                    } else {
                        if (m.substring(m.length - 4).indexOf("pdf") > -1) {
                            try {
                                f.ds_pki_signdata = "";
                                n = ML4WebApi.ml4web_storage_api.IrosMultiSign(g, f, a, magicjs.base64.decode(l[m]));
                                if (n.code != 0) {
                                    return {
                                        code: n.code,
                                        data: n.data
                                    };
                                    break
                                } else {
                                    c[k] = m + "&&" + n.data
                                }
                            } catch (h) {
                                return {
                                    code: ML4WebLog.getErrCode("ML4Web_API_MakeIrosMultiData"),
                                    data: {
                                        errCode: 888,
                                        errMsg: h.message
                                    }
                                };
                                break
                            }
                        } else {
                            return {
                                code: ML4WebLog.getErrCode("ML4Web_API_MakeIrosMultiData"),
                                data: {
                                    errCode: 888,
                                    errMsg: "not support data"
                                }
                            }
                        }
                    }
                }
                return {
                    code: 0,
                    data: ML4WebApi.ml4web_resource_api.makeIrosJson(c)
                }
            }
        } catch (h) {
            return {
                code: ML4WebLog.getErrCode("ML4Web_API_MakeIrosMultiData"),
                data: {
                    errCode: 888,
                    errMsg: h.message
                }
            }
        }
    },
    getCertInfo: function(a, c, f) {
        ML4WebLog.log("ML4WebApi.getCertInfo() called... ");
        if (a == null || a == "") {
            f(ML4WebLog.getErrCode("ML4Web_API_getCertInfo"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof f != "function" || f == null || f == "") {
                f(ML4WebLog.getErrCode("ML4Web_API_getCertInfo"), {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            }
        }
        var d = "";
        if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
            d = JSON.parse(a)
        } else {
            if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "new_cloud") {
                d = JSON.parse(ML4WebApi.dsDecrypt(a))
            } else {
                d = JSON.parse(a)
            }
        }
        if (typeof(ML4WebApi.webConfig.selectedStorage.key) == "undefined") {
            HandleApi.selectStorageInfo(d.storageName, function() {})
        }
        try {
            ML4WebApi.ml4web_storage_api.GetDetailCert(d, null, f)
        } catch (b) {
            f(ML4WebLog.getErrCode("ML4Web_API_getCertInfo"), {
                errCode: 888,
                errMsg: b.message
            })
        }
    },
    saveCertToStorage: function(d, b, e, a, f) {
        ML4WebLog.log("ML4WebApi.saveCertToStorage() called... ");
        if (d == null || $.isEmptyObject(d)) {
            f(ML4WebLog.getErrCode("ML4Web_API_CopyCertToStorage"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof f != "function" || f == null || f == "") {
                f(ML4WebLog.getErrCode("ML4Web_API_CopyCertToStorage"), {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            }
        }
        var c = {};
        c.storageName = e;
        c.storageOpt = a;
        c.storageCertIdx = "";
        ML4WebApi.ml4web_storage_api.SaveCert(d, b, c, f)
    },
    copyCertToStorage: function(b, c, f, a, g) {
        ML4WebLog.log("ML4WebApi.copyCertToStorage() called... ");
        if (b == null || b == "") {
            g(ML4WebLog.getErrCode("ML4Web_API_CopyCertToStorage"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (c == null || c == "") {
                g(ML4WebLog.getErrCode("ML4Web_API_CopyCertToStorage"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (f == null || f == "") {
                    g(ML4WebLog.getErrCode("ML4Web_API_CopyCertToStorage"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (a == null || $.isEmptyObject(a)) {
                        g(ML4WebLog.getErrCode("ML4Web_API_CopyCertToStorage"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (typeof g != "function" || g == null || g == "") {
                            g(ML4WebLog.getErrCode("ML4Web_API_CopyCertToStorage"), {
                                errCode: 103,
                                errMsg: $.i18n.prop("ER103")
                            });
                            return
                        }
                    }
                }
            }
        }
        try {
            ML4WebApi.ml4web_storage_api.GetCertString(b, function(h, j) {
                if (h == 0) {
                    var e = j.cert;
                    ML4WebApi.ml4web_storage_api.SaveCert(e, c, a, g)
                } else {
                    g(h, j)
                }
            })
        } catch (d) {
            g(ML4WebLog.getErrCode("ML4Web_API_CopyCertToStorage"), {
                errCode: 888,
                errMsg: d.message
            })
        }
    },
    deleteStorageCert: function(a, b, e) {
        ML4WebLog.log("ML4WebApi.deleteStorageCert() called...");
        if (a == null || a == "") {
            e(ML4WebLog.getErrCode("ML4Web_API_DeleteStorageCert"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (typeof e != "function" || e == null || e == "") {
                e(ML4WebLog.getErrCode("ML4Web_API_DeleteStorageCert"), {
                    errCode: 103,
                    errMsg: $.i18n.prop("ER103")
                });
                return
            }
        }
        var c;
        if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
            c = JSON.parse(a)
        } else {
            if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                c = JSON.parse(ML4WebApi.dsDecrypt(a))
            } else {
                c = JSON.parse(a)
            }
        }
        var d = ML4WebApi.getProperty("selectedStorage").key;
        if (d == "token") {
            ML4WebApi.ml4web_storage_api.DeleteCert_Token(c, b, e)
        } else {
            ML4WebApi.ml4web_storage_api.DeleteCert(c, e)
        }
    },
    changeStorageCertPasswd: function(c, b, a, e) {
        ML4WebLog.log("ML4WebApi.changeStorageCertPasswd() called... ");
        if (c == null || c == "") {
            e(ML4WebLog.getErrCode("ML4Web_API_ChageStorageCertPasswd"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (b == null || b == "") {
                e(ML4WebLog.getErrCode("ML4Web_API_ChageStorageCertPasswd"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    e(ML4WebLog.getErrCode("ML4Web_API_ChageStorageCertPasswd"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof e != "function" || e == null || e == "") {
                        e(ML4WebLog.getErrCode("ML4Web_API_ChageStorageCertPasswd"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
        }
        var d;
        if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
            d = JSON.parse(c)
        } else {
            if (ML4WebUI.selectedStorage.current_option.storageName == "web" || ML4WebUI.selectedStorage.current_option.storageName == "pfx") {
                d = JSON.parse(ML4WebApi.dsDecrypt(c))
            } else {
                d = JSON.parse(c)
            }
        }
        ML4WebApi.ml4web_storage_api.ChangePassword(d, b, a, e)
    },
    verifyVID: function(a, b, c, e) {
        var d = JSON.parse(ML4WebApi.dsDecrypt(a));
        ML4WebApi.ml4web_storage_api.verifyVID(d, b, c, e)
    },
    getVIDRandom: function(a, b, d) {
        var c = "";
        if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert" || ML4WebApi.getProperty("selectedStorage").key == "mobile") {
            c = JSON.parse(a)
        } else {
            if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                c = JSON.parse(ML4WebApi.dsDecrypt(a))
            } else {
                c = JSON.parse(a)
            }
        }
        ML4WebApi.ml4web_storage_api.getVIDRandom(c, b, function(e, f) {
            ML4WebApi.webConfig.getRandomfromPrivateKey = f.VIDRandom;
            d(e, f);
            return
        })
    },
    getVIDRandomHash: function(a, b, c, e) {
        var d = "";
        if (ML4WebApi.webConfig.libType == 0 || ML4WebApi.getProperty("selectedStorage").key == "smartcert") {
            d = JSON.parse(a)
        } else {
            if (ML4WebApi.webConfig.selectedStorage.current_option.storageName == "web" || ML4WebApi.webConfig.selectedStorage.current_option.storageName == "pfx") {
                d = JSON.parse(ML4WebApi.dsDecrypt(a))
            } else {
                d = JSON.parse(a)
            }
        }
        ML4WebApi.ml4web_storage_api.getVIDRandomHash(d, b, c, e);
        return
    },
    createCryptoMsg: function(a, c, b, d) {
        ML4WebLog.log("ML4WebApi.createCryptoMsg() called...");
        if (ML4WebApi.webConfig.libType == null) {
            d(ML4WebLog.getErrCode("ML4Web_API_createCryptoMsg"), {
                errCode: 100,
                errMsg: $.i18n.prop("ER100")
            });
            return
        } else {
            if (c == null || c == "") {
                d(ML4WebLog.getErrCode("ML4Web_API_createCryptoMsg"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || $.isEmptyObject(b)) {
                    d(ML4WebLog.getErrCode("ML4Web_API_createCryptoMsg"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof d != "function" || d == null || d == "") {
                        d(ML4WebLog.getErrCode("ML4Web_API_createCryptoMsg"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
        }
        switch (c) {
            case "genHmac":
                ML4WebApi.ml4web_crypto_api.genHmac(b.sAlg, b.sBase64Password, b.sMsg, d);
                break;
            case "verifyHmac":
                ML4WebApi.ml4web_crypto_api.verifyHmac(b.sAlg, b.sBase64Password, b.sMsg, b.hamcValue, d);
                break;
            case "encrypt":
                ML4WebApi.ml4web_crypto_api.encrypt(b.sAlg, b.b64key, b.b64iv, b.sMsg, d);
                break;
            case "decrypt":
                ML4WebApi.ml4web_crypto_api.decrypt(b.sAlg, b.b64key, b.b64iv, b.b64EncryptMsg, d);
                break;
            case "getcertInfo":
                ML4WebApi.ml4web_crypto_api.getcertInfo(b.b64Cert, b.jsonOption, d);
                break;
            case "sign":
                ML4WebApi.ml4web_crypto_api.sign(b.b64cert, b.b64priKey, b.sCertPassword, b.signData, b.signOpt, d);
                break;
            case "envelopedData":
                ML4WebApi.ml4web_crypto_api.envelopedData(b.b64KMCert, b.sPlainText, b.sAlgo, b.envelopOption, d);
                break;
            case "signedEnvelopedData":
                ML4WebApi.ml4web_crypto_api.signedEnvelopedData(b.b64KMCert, b.b64SignCert, b.b64SignPri, b.sSignCertPassword, b.sPlainText, b.sAlgo, b.sSignOption, d);
                break;
            case "verifyVID":
                ML4WebApi.ml4web_crypto_api.verifyVID(b.b64SignCert, b.b64SignPri, b.sCertPassword, b.idn, d);
                break;
            case "getVIDRandomHash":
                ML4WebApi.ml4web_crypto_api.getVIDRandomHash(b.b64SignCert, b.b64SignPri, b.sCertPassword, b.idn, d);
                break;
            case "generateRandom":
                ML4WebApi.ml4web_crypto_api.generateRandom(b.size, d);
                break;
            case "genKeypair":
                ML4WebApi.ml4web_crypto_api.genKeypair(b.sAlgo, b.iKeyLenth, d);
                break;
            case "genHash":
                ML4WebApi.ml4web_crypto_api.genHash(b.sAlg, b.oMsg, d);
                break;
            case "prikeyDecrypt":
                ML4WebApi.ml4web_crypto_api.prikeyDecrypt(b.b64CertPri, b.sCertPassword, d);
                break;
            case "prikeyEncrypt":
                ML4WebApi.ml4web_crypto_api.prikeyEncrypt(b.b64certPriDec, b.sCertPassword, b.oOption, d);
                break;
            case "prikeyChangePassword":
                ML4WebApi.ml4web_crypto_api.prikeyChangePassword(b.b64certPriDec, b.sCertOldPassword, b.sCertNewPassword, b.oOption, d);
                break;
            case "certChangePassword":
                ML4WebApi.ml4web_crypto_api.certChangePassword(b.jsonCert, b.sCertOldPassword, b.sCertNewPassword, b.oOption, d);
                break;
            case "getVIDRandom":
                ML4WebApi.ml4web_crypto_api.getVIDRandom(b.b64SignPri, b.sCertPassword, d);
                break;
            case "asymEncrypt":
                ML4WebApi.ml4web_crypto_api.asymEncrypt(b.b64EncryptedKey, b.sPlaintext, b.oAlgo, d);
                break;
            case "asymDecrypt":
                ML4WebApi.ml4web_crypto_api.prikeyDecrypt(b.b64EncryptedKey, b.sCertPassword, function(f, e) {
                    if (f == 0) {
                        b.b64EncryptedKey = e.Base64String;
                        ML4WebApi.ml4web_crypto_api.asymDecrypt(b.b64EncryptedKey, b.sCertPassword, b.sEncryptext, b.oAlgo, d)
                    } else {
                        d(ML4WebLog.getErrCode("ML4Web_API_createCryptoMsg"), {
                            errCode: e.errCode,
                            errMsg: e.errMsg
                        })
                    }
                });
                break;
            case "pfxImport":
                ML4WebApi.ml4web_crypto_api.pfxImport(b.b64Pfx, b.sPassword, d);
                break;
            case "pfxExport":
                ML4WebApi.ml4web_crypto_api.pfxExport(b.oJsonCert, b.sPassword, d);
                break;
            case "getFilePicker":
                ML4WebApi.ml4web_crypto_api.getFilePicker(b.fileExt, d);
                break;
            default:
                d(ML4WebLog.getErrCode("ML4Web_API_createCryptoMsg"), {
                    errCode: 104,
                    errMsg: $.i18n.prop("ER104")
                });
                break
        }
    },
    checkCSModule: function(b) {
        var a = {
            isInstall: ML4WebApi.webConfig.is_cs_install,
            isUpdate: ML4WebApi.webConfig.is_cs_update
        };
        b(0, a)
    },
    makeEncMssage: function(a) {
        return ML4WebApi.dsencrypt(a)
    },
    makeDecMssage: function(a) {
        return ML4WebApi.dsDecrypt(a)
    },
    tranx2PEM: function(a, f) {
        try {
            if (a == "UI") {
                if (ML4WebApi.webConfig.tranx2PEM != "") {
                    f("0", ML4WebApi.webConfig.tranx2PEM)
                } else {
                    f("1", "")
                }
            } else {
                var d = ML4WebApi.getResourceApi();
                var b = d.makeCsJsonMessage("tranx2PEM");
                d.csAsyncCall(ML4WebApi.getProperty("CsUrl"), b, function(e) {
                    f(e.ResultCode, e);
                    return
                })
            }
        } catch (c) {
            f(ML4WebLog.getErrCode("ML4Web_API_tranx2PEM"), {
                errCode: c.code,
                errMsg: c.message
            });
            return
        }
    },
    getRandomfromPrivateKey: function(a, f) {
        try {
            if (a == "UI") {
                if (ML4WebApi.isEmpty(ML4WebApi.webConfig.getRandomfromPrivateKey)) {
                    ML4WebApi.ml4web_storage_api.getVIDRandom(JSON.parse(ML4WebApi.UserInfo.selectCertInfo), ML4WebApi.ml4web_crypto_api.HD_result, function(e, g) {
                        ML4WebApi.webConfig.getRandomfromPrivateKey = g.VIDRandom;
                        f(e, g);
                        return
                    })
                } else {
                    f("0", {
                        VIDRandom: ML4WebApi.webConfig.getRandomfromPrivateKey
                    });
                    return
                }
            } else {
                var d = ML4WebApi.getResourceApi();
                var b = d.makeCsJsonMessage("getRandomfromPrivateKey");
                d.csAsyncCall(ML4WebApi.getProperty("CsUrl"), b, function(e) {
                    f(e.ResultCode, e);
                    return
                })
            }
        } catch (c) {
            f(ML4WebLog.getErrCode("ML4Web_API_getRandomfromPrivateKey"), {
                errCode: c.code,
                errMsg: c.message
            });
            return
        }
    },
    setSessionID: function(b, a, g) {
        try {
            if (b == "UI") {
                if (ML4WebApi.webConfig.strSessionID != "") {
                    g("1", a)
                } else {
                    g("1", "")
                }
            } else {
                var f = ML4WebApi.getResourceApi();
                var c = f.makeCsJsonMessage("setSessionID", a);
                f.csAsyncCall(ML4WebApi.getProperty("CsUrl"), c, function(e) {
                    g(e.ResultCode, e)
                })
            }
        } catch (d) {
            g(ML4WebLog.getErrCode("ML4Web_API_setSessionID"), {
                errCode: d.code,
                errMsg: d.message
            })
        }
    },
    setMobileKeyURL: function(a, g, f) {
        try {
            if (a == "UI") {
                f("1", "")
            } else {
                var d = ML4WebApi.getResourceApi();
                var b = d.makeCsJsonMessage("SetMobileKeyURL", g);
                d.csAsyncCall(ML4WebApi.getProperty("CsUrl"), b, function(e) {
                    f(e.ResultCode, e)
                })
            }
        } catch (c) {
            f(ML4WebLog.getErrCode("ML4Web_API_setMobileKeyURL"), {
                errCode: c.code,
                errMsg: c.message
            })
        }
    },
    UbiKeyInit: function(c, f, b, a, g, j) {
        try {
            if (c == "UI") {
                j("1", "")
            } else {
                var h = ML4WebApi.getResourceApi();
                var k = h.makeCsJsonMessage("UbiKeyInit", f, b, a, g);
                h.csAsyncCall(ML4WebApi.getProperty("CsUrl"), k, function(e) {
                    j(e.ResultCode, e)
                })
            }
        } catch (d) {
            j(ML4WebLog.getErrCode("ML4Web_API_UbiKeyInit"), {
                errCode: d.code,
                errMsg: d.message
            })
        }
    },
    setHashOption: function(a, d, g) {
        try {
            if (a == "UI") {
                g("0", "")
            } else {
                var f = ML4WebApi.getResourceApi();
                var b = f.makeCsJsonMessage("setHashOption", d);
                f.csAsyncCall(ML4WebApi.getProperty("CsUrl"), b, function(e) {
                    g(e.ResultCode, e)
                })
            }
        } catch (c) {
            g(ML4WebLog.getErrCode("ML4Web_API_setHashOption"), {
                errCode: c.code,
                errMsg: c.message
            })
        }
    },
    setExtraOption: function(b, h, a, g) {
        try {
            if (b == "UI") {
                g("0", "")
            } else {
                var f = ML4WebApi.getResourceApi();
                var c = f.makeCsJsonMessage("SetExtraOption", h, a);
                f.csAsyncCall(ML4WebApi.getProperty("CsUrl"), c, function(e) {
                    g(e.ResultCode, e)
                })
            }
        } catch (d) {
            g(ML4WebLog.getErrCode("ML4Web_API_setExtraOption"), {
                errCode: d.code,
                errMsg: d.message
            })
        }
    },
    console: window.console || {
        log: function() {}
    },
    csConfigOpt: {},
    ml4web_crypto_api: {
        libType: "",
        cryptObj: "",
        PKI_CIPER_ALGO_SEEDCBC: "SEED-CBC",
        PKI_CIPER_ALGO_3DESCBC: "3DES-CBC",
        PKI_CIPER_ALGO_AIRACBC: "ARIA128-CBC",
        PKI_CIPER_ALGO_AIRACBC: "ARIA192-CBC",
        PKI_CIPER_ALGO_AIRACBC: "ARIA256-CBC",
        PKI_CIPER_ALGO_AES128CBC: "AES128-CBC",
        PKI_CIPER_ALGO_AES192CBC: "AES192-CBC",
        PKI_CIPER_ALGO_AES256CBC: "AES256-CBC",
        PKI_CERT_SIGN_OPT_NONE: "OPT_NONE",
        PKI_CERT_SIGN_OPT_USE_CONTNET_INFO: "OPT_USE_CONTNET_INFO",
        PKI_CERT_SIGN_OPT_NO_CONTENT: "OPT_NO_CONTENT",
        PKI_CERT_SIGN_OPT_SIGNKOREA_FORMAT: "OPT_SIGNKOREA_FORMAT",
        PKI_HASH_SHA1: "sha1",
        PKI_HASH_SHA256: "sha256",
        PKI_HASH_SHA384: "sha384",
        PKI_HASH_SHA512: "sha512",
        PKI_RSA_1_5: "rsa15",
        PKI_RSA_2_0: "rsa20",
        HD_result: "",
        SD_result: "",
        CERT_INFO_VERSION: "version",
        CERT_INFO_SERIALNUM: "serialnum",
        CERT_INFO_SIGNATUREALGORITHM: "signaturealgorithm",
        CERT_INFO_ISSUERNAME: "issuername",
        CERT_INFO_STARTDATE: "startdate",
        CERT_INFO_ENDDATE: "enddate",
        CERT_INFO_SUBJECTNAME: "subjectname",
        CERT_INFO_PUBKEY: "pubkey",
        CERT_INFO_PUBKEYALGORITHM: "pubkeyalgorithm",
        CERT_INFO_KEYUSAGE: "keyusage",
        CERT_INFO_CERTPOLICY: "certpolicy",
        CERT_INFO_POLICYID: "policyid",
        CERT_INFO_POLICYNOTICE: "policynotice",
        CERT_INFO_SUBJECTALTNAME: "subjectaltname",
        CERT_INFO_AUTHKEYID: "authkeyid",
        CERT_INFO_SUBKEYID: "subkeyid",
        CERT_INFO_CRLDP: "crldp",
        CERT_INFO_AIA: "aia",
        CERT_INFO_REALNAME: "realname",
        encodeUtf8andBase64: function(d) {
            var h = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            var a = "";
            var c = "";
            var g, e, b;
            var f = 0;
            d = unescape(encodeURIComponent(d));
            maxline = (d.length + 2 - ((d.length + 2) % 3)) / 3 * 4;
            while (f < d.length) {
                g = d.charCodeAt(f++);
                e = d.charCodeAt(f++);
                b = d.charCodeAt(f++);
                a += h.charAt(g >> 2);
                a += h.charAt(((g & 3) << 4) | (e >> 4));
                if (isNaN(e)) {
                    a += "=="
                } else {
                    a += h.charAt(((e & 15) << 2) | (b >> 6));
                    a += isNaN(b) ? "=" : h.charAt(b & 63)
                }
                if (maxline && a.length > maxline) {
                    c += a.substr(0, maxline) + "\r\n";
                    a = a.substr(maxline)
                }
            }
            c += a;
            return c
        },
        init: function(b, d, c) {
            ML4WebLog.log("Crypto_API Init() called...");
            if (b == null || b == "undefined") {
                libType = d.checkCS()
            } else {
                libType = b
            }
            if (libType == 0) {
                cryptObj = new C_Crypto_API(d)
            } else {
                if (libType == 1) {
                    cryptObj = new JS_Crypto_API(d)
                } else {
                    if (libType == 2) {
                        cryptObj = new JS_Crypto_Raw_API(d)
                    }
                }
            }
            var a = "js/crypto/magicjs_1.2.7.2.min.js";
            $.nonCachedScript(a).done(function(f, e) {
                new Function(f)();
                cryptObj.init(c)
            })
        },
        genHmac: function(b, d, a, f) {
            ML4WebLog.log("call genHmac!!");
            if (b == null || b == "") {
                f(ML4WebLog.getErrCode("Crypto_API_genHmac"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (d == null || d == "") {
                    f(ML4WebLog.getErrCode("Crypto_API_genHmac"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (a == null || a == "") {
                        f(ML4WebLog.getErrCode("Crypto_API_genHmac"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (typeof f != "function" || f == null || f == "") {
                            f(ML4WebLog.getErrCode("Crypto_API_genHmac"), {
                                errCode: 103,
                                errMsg: $.i18n.prop("ER103")
                            });
                            return
                        }
                    }
                }
            }
            try {
                cryptObj.genHmac(b, d, a, f)
            } catch (c) {
                f(ML4WebLog.getErrCode("Crypto_API_genHmac"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        },
        verifyHmac: function(c, f, b, a, g) {
            ML4WebLog.log("call verifyHmac !!");
            if (c == null || c == "") {
                g(ML4WebLog.getErrCode("Crypto_API_verifyHmac"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (f == null || f == "") {
                    g(ML4WebLog.getErrCode("Crypto_API_verifyHmac"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (b == null || b == "") {
                        g(ML4WebLog.getErrCode("Crypto_API_verifyHmac"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (a == null || a == "") {
                            g(ML4WebLog.getErrCode("Crypto_API_verifyHmac"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        } else {
                            if (typeof g != "function" || g == null || g == "") {
                                g(ML4WebLog.getErrCode("Crypto_API_verifyHmac"), {
                                    errCode: 103,
                                    errMsg: $.i18n.prop("ER103")
                                });
                                return
                            }
                        }
                    }
                }
            }
            try {
                cryptObj.verifyHmac(c, f, b, a, g)
            } catch (d) {
                g(ML4WebLog.getErrCode("Crypto_API_verifyHmac"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        },
        encrypt: function(c, g, b, a, f) {
            ML4WebLog.log("call encrypt !!");
            if (c == null || c == "") {
                f(ML4WebLog.getErrCode("Crypto_API_encrypt"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (g == null || g == "") {
                    f(ML4WebLog.getErrCode("Crypto_API_encrypt"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (b == null || b == "") {
                        f(ML4WebLog.getErrCode("Crypto_API_encrypt"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (a == null || a == "") {
                            f(ML4WebLog.getErrCode("Crypto_API_encrypt"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        } else {
                            if (typeof f != "function" || f == null || f == "") {
                                f(ML4WebLog.getErrCode("Crypto_API_encrypt"), {
                                    errCode: 103,
                                    errMsg: $.i18n.prop("ER103")
                                });
                                return
                            }
                        }
                    }
                }
            }
            try {
                cryptObj.encrypt(c, g, b, a, f)
            } catch (d) {
                f(ML4WebLog.getErrCode("Crypto_API_encrypt"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        },
        decrypt: function(c, g, a, b, f) {
            ML4WebLog.log("call decrypt !!");
            if (c == null || c == "") {
                f(ML4WebLog.getErrCode("Crypto_API_decrypt"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (g == null || g == "") {
                    f(ML4WebLog.getErrCode("Crypto_API_decrypt"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (a == null || a == "") {
                        f(ML4WebLog.getErrCode("Crypto_API_decrypt"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (b == null || b == "") {
                            f(ML4WebLog.getErrCode("Crypto_API_decrypt"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        } else {
                            if (typeof f != "function" || f == null || f == "") {
                                f(ML4WebLog.getErrCode("Crypto_API_decrypt"), {
                                    errCode: 103,
                                    errMsg: $.i18n.prop("ER103")
                                });
                                return
                            }
                        }
                    }
                }
            }
            try {
                cryptObj.decrypt(c, g, a, b, f)
            } catch (d) {
                f(ML4WebLog.getErrCode("Crypto_API_decrypt"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        },
        sign: function(b, a, f, d, c, h) {
            ML4WebLog.log("call sign !!");
            if (b == null || b == "") {
                h(ML4WebLog.getErrCode("Crypto_API_sign"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    h(ML4WebLog.getErrCode("Crypto_API_sign"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (f == null || f == "") {
                        h(ML4WebLog.getErrCode("Crypto_API_sign"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    }
                }
            }
            try {
                if (typeof h === "function") {
                    cryptObj.sign(b, a, f, d, c, h)
                } else {
                    return cryptObj.sign(b, a, f, d, c, h)
                }
            } catch (g) {
                h(ML4WebLog.getErrCode("Crypto_API_sign"), {
                    errCode: 888,
                    errMsg: g.message
                });
                return
            }
        },
        signature: function(b, a, f, d, c, h) {
            ML4WebLog.log("call sign !!");
            if (b == null || b == "") {
                h(ML4WebLog.getErrCode("Crypto_API_sign"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    h(ML4WebLog.getErrCode("Crypto_API_sign"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (f == null || f == "") {
                        h(ML4WebLog.getErrCode("Crypto_API_sign"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    }
                }
            }
            try {
                if (typeof h === "function") {
                    cryptObj.signature(b, a, f, d, c, h)
                } else {
                    return cryptObj.signature(b, a, f, d, c, h)
                }
            } catch (g) {
                h(ML4WebLog.getErrCode("Crypto_API_sign"), {
                    errCode: 888,
                    errMsg: g.message
                });
                return
            }
        },
        irosSign: function(b, a, f, d, c) {
            ML4WebLog.log("call irosSign !!");
            if (b == null || b == "") {
                return {
                    code: ML4WebLog.getErrCode("Crypto_API_irosSign"),
                    data: {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    }
                }
            } else {
                if (a == null || a == "") {
                    return {
                        code: ML4WebLog.getErrCode("Crypto_API_irosSign"),
                        data: {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        }
                    }
                } else {
                    if (f == null || f == "") {
                        return {
                            code: ML4WebLog.getErrCode("Crypto_API_irosSign"),
                            data: {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            }
                        }
                    } else {
                        if (d == null || d == "") {
                            return {
                                code: ML4WebLog.getErrCode("Crypto_API_irosSign"),
                                data: {
                                    errCode: 100,
                                    errMsg: $.i18n.prop("ER100")
                                }
                            }
                        }
                    }
                }
            }
            try {
                return cryptObj.irosSign(b, a, f, d, c)
            } catch (g) {
                return {
                    code: ML4WebLog.getErrCode("Crypto_API_irosSign"),
                    data: {
                        errCode: 888,
                        errMsg: g.message
                    }
                }
            }
        },
        envelopedData: function(f, a, b, d, g) {
            ML4WebLog.log("call envelopedData !!");
            if (f == null || f == "") {
                g(ML4WebLog.getErrCode("Crypto_API_envelopedData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    g(ML4WebLog.getErrCode("Crypto_API_envelopedData"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (b == null || $.isEmptyObject(b)) {
                        g(ML4WebLog.getErrCode("Crypto_API_envelopedData"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (typeof g != "function" || g == null || g == "") {
                            g(ML4WebLog.getErrCode("Crypto_API_envelopedData"), {
                                errCode: 103,
                                errMsg: $.i18n.prop("ER103")
                            });
                            return
                        }
                    }
                }
            }
            try {
                cryptObj.envelopedData(f, a, b, d, g)
            } catch (c) {
                g(ML4WebLog.getErrCode("Crypto_API_envelopedData"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        },
        signedEnvelopedData: function(g, k, a, f, b, h, c, j) {
            ML4WebLog.log("call signedEnvelopedData !!");
            if (g == null || g == "") {
                j(ML4WebLog.getErrCode("Crypto_API_signedEnvelopedData"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (k == null || k == "") {
                    j(ML4WebLog.getErrCode("Crypto_API_signedEnvelopedData"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (a == null || a == "") {
                        j(ML4WebLog.getErrCode("Crypto_API_signedEnvelopedData"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (f == null || f == "") {
                            j(ML4WebLog.getErrCode("Crypto_API_signedEnvelopedData"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        } else {
                            if (b == null || b == "") {
                                j(ML4WebLog.getErrCode("Crypto_API_signedEnvelopedData"), {
                                    errCode: 100,
                                    errMsg: $.i18n.prop("ER100")
                                });
                                return
                            } else {
                                if (h == null || h == "") {
                                    j(ML4WebLog.getErrCode("Crypto_API_signedEnvelopedData"), {
                                        errCode: 100,
                                        errMsg: $.i18n.prop("ER100")
                                    });
                                    return
                                } else {
                                    if (typeof j != "function" || j == null || j == "") {
                                        j(ML4WebLog.getErrCode("Crypto_API_signedEnvelopedData"), {
                                            errCode: 103,
                                            errMsg: $.i18n.prop("ER103")
                                        });
                                        return
                                    }
                                }
                            }
                        }
                    }
                }
            }
            try {
                cryptObj.signedEnvelopedData(g, k, a, f, b, h, c, j)
            } catch (d) {
                j(ML4WebLog.getErrCode("Crypto_API_signedEnvelopedData"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        },
        verifyVID: function(c, b, d, a, g) {
            ML4WebLog.log("call verifyVID !!");
            if (c == null || c == "") {
                g(ML4WebLog.getErrCode("Crypto_API_verifyVID"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || b == "") {
                    g(ML4WebLog.getErrCode("Crypto_API_verifyVID"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (d == null || d == "") {
                        g(ML4WebLog.getErrCode("Crypto_API_verifyVID"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (a == null || a == "") {
                            g(ML4WebLog.getErrCode("Crypto_API_verifyVID"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        } else {
                            if (typeof g != "function" || g == null || g == "") {
                                g(ML4WebLog.getErrCode("Crypto_API_verifyVID"), {
                                    errCode: 103,
                                    errMsg: $.i18n.prop("ER103")
                                });
                                return
                            }
                        }
                    }
                }
            }
            try {
                cryptObj.verifyVID(c, b, d, a, g)
            } catch (f) {
                g(ML4WebLog.getErrCode("Crypto_API_verifyVID"), {
                    errCode: 888,
                    errMsg: f.message
                });
                return
            }
        },
        generateRandom: function(a, c) {
            ML4WebLog.log("call generateRandom !!");
            if (a == null || a == 0) {
                c(ML4WebLog.getErrCode("Crypto_API_generateRandom"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (typeof c != "function" || c == null || c == "") {
                    c(ML4WebLog.getErrCode("Crypto_API_generateRandom"), {
                        errCode: 103,
                        errMsg: $.i18n.prop("ER103")
                    });
                    return
                }
            }
            try {
                cryptObj.generateRandom(a, c)
            } catch (b) {
                c(ML4WebLog.getErrCode("Crypto_API_generateRandom"), {
                    errCode: 888,
                    errMsg: b.message
                });
                return
            }
        },
        genKeypair: function(a, b, d) {
            ML4WebLog.log("call genKeypair by javascript!!");
            if (a == null || a == "") {
                d(ML4WebLog.getErrCode("Crypto_API_genKeypair"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || b == 0) {
                    d(ML4WebLog.getErrCode("Crypto_API_genKeypair"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof d != "function" || d == null || d == "") {
                        d(ML4WebLog.getErrCode("Crypto_API_genKeypair"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
            try {
                cryptObj.genKeypair(a, b, d)
            } catch (c) {
                d(ML4WebLog.getErrCode("Crypto_API_genKeypair"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        },
        genHash: function(b, a, d) {
            ML4WebLog.log("call genHash by javascript!!");
            if (b == null || b == "") {
                d(ML4WebLog.getErrCode("Crypto_API_genHash"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    d(ML4WebLog.getErrCode("Crypto_API_genHash"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                }
            }
            try {
                if (typeof(d) == "undefined") {
                    return cryptObj.genHash(b, a, d)
                } else {
                    cryptObj.genHash(b, a, d)
                }
            } catch (c) {
                d(ML4WebLog.getErrCode("Crypto_API_genHash"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        },
        genHashCount: function(b, a, c, f) {
            ML4WebLog.log("call genHashCount by javascript!!");
            if (b == null || b == "") {
                f(ML4WebLog.getErrCode("Crypto_API_genHashCount"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    f(ML4WebLog.getErrCode("Crypto_API_genHashCount"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (c == null || c == "") {
                        f(ML4WebLog.getErrCode("Crypto_API_genHashCount"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (typeof f != "function" || f == null || f == "") {
                            f(ML4WebLog.getErrCode("Crypto_API_genHashCount"), {
                                errCode: 103,
                                errMsg: $.i18n.prop("ER103")
                            });
                            return
                        }
                    }
                }
            }
            try {
                cryptObj.genHashCount(b, a, c, f)
            } catch (d) {
                f(ML4WebLog.getErrCode("Crypto_API_genHashCount"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        },
        genCreateToken: function() {
            var a = magicjs.base64.decode("YWVkZWNiOWYyNTA4YzdlMjBiOWYwYmI2ZjBhODk4NDQ=");
            var c = a.substring(0, a.length / 2);
            var b = a.substring(a.length / 2);
            return b + c
        },
        genInitToken: function() {
            var a = magicjs.base64.decode("NjhlZWE4NDRkMmQyYzE4NzY5MDY4Mzc0YmE4NGQ4NWI=");
            var c = a.substring(0, a.length / 2);
            var b = a.substring(a.length / 2);
            return b + c
        },
        genIncaToken: function() {
            var a = magicjs.base64.decode("ZDI1NGZlZDAyNjM3YWJjZTYwNWE4ODdlMWMzOTNkZGVkNDIxOWE2YmU2YjgzOWUzNGU3M2U1MmM5YjIyMTNjMw==");
            var c = a.substring(0, a.length / 2);
            var b = a.substring(a.length / 2);
            return b + c
        },
        genDsToken: function() {
            var a = magicjs.base64.decode("ZlNwNlNkMmc3UT09d3FwUlJIQWpwVzQ4");
            var c = a.substring(0, a.length / 2);
            var b = a.substring(a.length / 2);
            return b + c
        },
        prikeyDecrypt: function(c, a, d) {
            if (c == null || c == "") {
                d(ML4WebLog.getErrCode("Crypto_API_prikeyDecrypt"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    d(ML4WebLog.getErrCode("Crypto_API_prikeyDecrypt"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof d != "function" || d == null || d == "") {
                        d(ML4WebLog.getErrCode("Crypto_API_prikeyDecrypt"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
            try {
                cryptObj.prikeyDecrypt(c, a, d)
            } catch (b) {
                d(ML4WebLog.getErrCode("Crypto_API_prikeyDecrypt"), {
                    errCode: 888,
                    errMsg: b.message
                });
                return
            }
        },
        prikeyEncrypt: function(d, a, c, f) {
            if (d == null || d == "") {
                f(ML4WebLog.getErrCode("Crypto_API_prikeyEncrypt"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    f(ML4WebLog.getErrCode("Crypto_API_prikeyEncrypt"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof f != "function" || f == null || f == "") {
                        f(ML4WebLog.getErrCode("Crypto_API_prikeyEncrypt"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
            try {
                cryptObj.prikeyEncrypt(d, a, c, f)
            } catch (b) {
                f(ML4WebLog.getErrCode("Crypto_API_prikeyEncrypt"), {
                    errCode: 888,
                    errMsg: b.message
                });
                return
            }
        },
        getVIDRandom: function(a, b, d) {
            if (a == null || a == "") {
                d(ML4WebLog.getErrCode("Crypto_API_getVIDRandom"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || b == "") {
                    d(ML4WebLog.getErrCode("Crypto_API_getVIDRandom"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof d != "function" || d == null || d == "") {
                        d(ML4WebLog.getErrCode("Crypto_API_getVIDRandom"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
            try {
                cryptObj.getVIDRandom(a, b, d)
            } catch (c) {
                d(ML4WebLog.getErrCode("Crypto_API_getVIDRandom"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        },
        getVIDRandomHash: function(c, b, d, a, g) {
            if (c == null || c == "") {
                g(ML4WebLog.getErrCode("Crypto_API_getVIDRandom"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || b == "") {
                    g(ML4WebLog.getErrCode("Crypto_API_getVIDRandom"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (d == null || d == "") {
                        g(ML4WebLog.getErrCode("Crypto_API_getVIDRandom"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (a == null || a == "") {
                            g(ML4WebLog.getErrCode("Crypto_API_getVIDRandom"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        } else {
                            if (typeof g != "function" || g == null || g == "") {
                                g(ML4WebLog.getErrCode("Crypto_API_getVIDRandom"), {
                                    errCode: 103,
                                    errMsg: $.i18n.prop("ER103")
                                });
                                return
                            }
                        }
                    }
                }
            }
            try {
                cryptObj.getVIDRandomHash(c, b, d, a, g)
            } catch (f) {
                g(ML4WebLog.getErrCode("Crypto_API_getVIDRandomHash"), {
                    errCode: 888,
                    errMsg: f.message
                });
                return
            }
        },
        asymEncrypt: function(c, b, a, f) {
            if (c == null || c == "") {
                f(ML4WebLog.getErrCode("Crypto_API_asymEncrypt"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || b == "") {
                    f(ML4WebLog.getErrCode("Crypto_API_asymEncrypt"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (a == null || a == "") {
                        f(ML4WebLog.getErrCode("Crypto_API_asymEncrypt"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (typeof f != "function" || f == null || f == "") {
                            f(ML4WebLog.getErrCode("Crypto_API_asymEncrypt"), {
                                errCode: 103,
                                errMsg: $.i18n.prop("ER103")
                            });
                            return
                        }
                    }
                }
            }
            try {
                cryptObj.asymEncrypt(c, b, a, f)
            } catch (d) {
                f(ML4WebLog.getErrCode("Crypto_API_asymEncrypt"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        },
        asymDecrypt: function(b, d, a, c, g) {
            if (b == null || b == "") {
                g(ML4WebLog.getErrCode("Crypto_API_asymDecrypt"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    g(ML4WebLog.getErrCode("Crypto_API_asymDecrypt"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (d == null || d == "") {
                        g(ML4WebLog.getErrCode("Crypto_API_asymDecrypt"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (c == null || c == "") {
                            g(ML4WebLog.getErrCode("Crypto_API_asymDecrypt"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        } else {
                            if (typeof g != "function" || g == null || g == "") {
                                g(ML4WebLog.getErrCode("Crypto_API_asymDecrypt"), {
                                    errCode: 103,
                                    errMsg: $.i18n.prop("ER103")
                                });
                                return
                            }
                        }
                    }
                }
            }
            try {
                cryptObj.asymDecrypt(b, d, a, c, g)
            } catch (f) {
                g(ML4WebLog.getErrCode("Crypto_API_asymDecrypt"), {
                    errCode: 888,
                    errMsg: f.message
                });
                return
            }
        },
        pfxImport: function(a, b, d) {
            if (a == null || a == "") {
                d(ML4WebLog.getErrCode("Crypto_API_pfxImport"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || b == "") {
                    d(ML4WebLog.getErrCode("Crypto_API_pfxImport"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof d != "function" || d == null || d == "") {
                        d(ML4WebLog.getErrCode("Crypto_API_pfxImport"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
            try {
                cryptObj.pfxImport(a, b, d)
            } catch (c) {
                d(ML4WebLog.getErrCode("Crypto_API_pfxImport"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        },
        pfxExport: function(b, a, d) {
            if (b == null || b == "") {
                d(ML4WebLog.getErrCode("Crypto_API_pfxExport"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null || a == "") {
                    d(ML4WebLog.getErrCode("Crypto_API_pfxExport"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof d != "function" || d == null || d == "") {
                        d(ML4WebLog.getErrCode("Crypto_API_pfxExport"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
            try {
                cryptObj.pfxExport(b, a, d)
            } catch (c) {
                d(ML4WebLog.getErrCode("Crypto_API_pfxExport"), {
                    errCode: 888,
                    errMsg: c.message
                });
                return
            }
        },
        getcertInfo: function(d, a, f) {
            if (d == null || d == "") {
                f(ML4WebLog.getErrCode("Crypto_API_getcertInfo"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (a == null) {
                    f(ML4WebLog.getErrCode("Crypto_API_getcertInfo"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (typeof f != "function" || f == null || f == "") {
                        f(ML4WebLog.getErrCode("Crypto_API_getcertInfo"), {
                            errCode: 103,
                            errMsg: $.i18n.prop("ER103")
                        });
                        return
                    }
                }
            }
            try {
                var c = [];
                if (a.length == 0) {
                    c.push(DS_CERT_INFO.VERSION);
                    c.push(DS_CERT_INFO.SERIALNUM);
                    c.push(DS_CERT_INFO.SIGNATUREALGORITHM);
                    c.push(DS_CERT_INFO.ISSUERNAME);
                    c.push(DS_CERT_INFO.STARTDATE);
                    c.push(DS_CERT_INFO.ENDDATE);
                    c.push(DS_CERT_INFO.STARTDATETIME);
                    c.push(DS_CERT_INFO.ENDDATETIME);
                    c.push(DS_CERT_INFO.SUBJECTNAME);
                    c.push(DS_CERT_INFO.PUBKEY);
                    c.push(DS_CERT_INFO.PUBKEYALGORITHM);
                    c.push(DS_CERT_INFO.KEYUSAGE);
                    c.push(DS_CERT_INFO.CERTPOLICY);
                    c.push(DS_CERT_INFO.POLICYID);
                    c.push(DS_CERT_INFO.POLICYNOTICE);
                    c.push(DS_CERT_INFO.SUBJECTALTNAME);
                    c.push(DS_CERT_INFO.AUTHKEYID);
                    c.push(DS_CERT_INFO.SUBKEYID);
                    c.push(DS_CERT_INFO.CRLDP);
                    c.push(DS_CERT_INFO.AIA);
                    c.push(DS_CERT_INFO.REALNAME)
                } else {
                    c = a
                }
                cryptObj.getcertInfo(d, c, f)
            } catch (b) {
                f(ML4WebLog.getErrCode("Crypto_API_getcertInfo"), {
                    errCode: 888,
                    errMsg: b.message
                });
                return
            }
        },
        prikeyChangePassword: function(c, b, a, f, g) {
            if (c == null || c == "") {
                g(ML4WebLog.getErrCode("Crypto_API_prikeyChangePassword"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || b == "") {
                    g(ML4WebLog.getErrCode("Crypto_API_prikeyChangePassword"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (a == null || a == "") {
                        g(ML4WebLog.getErrCode("Crypto_API_prikeyChangePassword"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (typeof g != "function" || g == null || g == "") {
                            g(ML4WebLog.getErrCode("Crypto_API_prikeyChangePassword"), {
                                errCode: 103,
                                errMsg: $.i18n.prop("ER103")
                            });
                            return
                        }
                    }
                }
            }
            try {
                cryptObj.prikeyChangePassword(c, b, a, f, g)
            } catch (d) {
                g(ML4WebLog.getErrCode("Crypto_API_prikeyChangePassword"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        },
        certChangePassword: function(c, b, a, f, g) {
            if (c == null || c == "") {
                g(ML4WebLog.getErrCode("Crypto_API_certChangePassword"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || b == "") {
                    g(ML4WebLog.getErrCode("Crypto_API_certChangePassword"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (a == null || a == "") {
                        g(ML4WebLog.getErrCode("Crypto_API_certChangePassword"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (typeof g != "function" || g == null || g == "") {
                            g(ML4WebLog.getErrCode("Crypto_API_certChangePassword"), {
                                errCode: 103,
                                errMsg: $.i18n.prop("ER103")
                            });
                            return
                        }
                    }
                }
            }
            try {
                cryptObj.certChangePassword(c, b, a, f, g)
            } catch (d) {
                g(ML4WebLog.getErrCode("Crypto_API_certChangePassword"), {
                    errCode: 888,
                    errMsg: d.message
                });
                return
            }
        },
        getFilePicker: function(b, d) {
            if (b == null || b == "") {
                d(ML4WebLog.getErrCode("Crypto_API_getFilePicker"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (typeof d != "function" || d == null || d == "") {
                    d(ML4WebLog.getErrCode("Crypto_API_getFilePicker"), {
                        errCode: 103,
                        errMsg: $.i18n.prop("ER103")
                    });
                    return
                }
            }
            var a = new C_Crypto_API(resource_api);
            a.init(function() {});
            try {
                a.getFilePicker(b, d)
            } catch (c) {
                d(ML4WebLog.getErrCode("Crypto_API_getFilePicker"), {
                    errCode: 888,
                    errMsg: c.message
                })
            }
        },
        getEncryptedCert: function(b) {
            try {
                if (b !== null && typeof b !== "undefined" && b !== "") {
                    var a = magicjs.cipher.create(true, "SEED-CBC", magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genCreateToken()));
                    a.init(magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genInitToken()));
                    a.update(b);
                    a.finish();
                    return magicjs.base64.encode(a.output)
                }
            } catch (c) {
                return ""
            }
        },
        getDecryptedCert: function(b) {
            try {
                if (b !== null && typeof b !== "undefined" && b !== "") {
                    var a = magicjs.cipher.create(false, "SEED-CBC", magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genCreateToken()));
                    a.init(magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genInitToken()));
                    a.update(magicjs.base64.decode(b));
                    a.finish();
                    return a.output.data
                }
            } catch (c) {
                return ""
            }
        },
        HD_api: function(b) {
            if (ML4WebApi.HDSDOption.eOption) {
                try {
                    if (b !== null && typeof b !== "undefined" && b !== "") {
                        var a = magicjs.cipher.create(true, "SEED-CBC", magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genCreateToken()));
                        a.init(magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genInitToken()));
                        a.update(b);
                        a.finish();
                        ML4WebApi.ml4web_crypto_api.HD_result = magicjs.base64.encode(a.output);
                        return ML4WebApi.ml4web_crypto_api.HD_result
                    }
                } catch (c) {
                    return ""
                }
            } else {
                return b
            }
        },
        SD_api: function(b) {
            if (ML4WebApi.HDSDOption.eOption) {
                try {
                    if (b !== null && typeof b !== "undefined" && b !== "") {
                        var a = magicjs.cipher.create(false, "SEED-CBC", magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genCreateToken()));
                        a.init(magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genInitToken()));
                        a.update(magicjs.base64.decode(b));
                        a.finish();
                        return a.output.data
                    }
                } catch (c) {
                    return ""
                }
            } else {
                return b
            }
        },
        get_SD_Result: function() {
            if (ML4WebApi.HDSDOption.eOption) {
                try {
                    var a = magicjs.cipher.create(false, "SEED-CBC", magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genCreateToken()));
                    a.init(magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genInitToken()));
                    a.update(magicjs.base64.decode(ML4WebApi.ml4web_crypto_api.HD_result));
                    a.finish();
                    return a.output.data
                } catch (b) {
                    return ""
                }
            } else {
                return string
            }
        },
        incaDecrypt: function(d, g) {
            var b = d.substr(0, 32);
            var c = d.substr(32);
            var f = magicjs.base64.encode(magicjs.hex.decode(ML4WebApi.ml4web_crypto_api.genIncaToken()));
            var a = magicjs.base64.encode(magicjs.hex.decode(b));
            var e = magicjs.base64.encode(magicjs.hex.decode(c));
            ML4WebApi.ml4web_crypto_api.decrypt("ARIA256-CBC", f, a, e, function(h, j) {
                if (h == 0) {
                    g(h, j)
                }
            })
        },
        pkcs7: function(g, b, f, a, d) {
            if (g == null || g == "") {
                callback(ML4WebLog.getErrCode("Crypto_API_pkcs7"), {
                    errCode: 100,
                    errMsg: $.i18n.prop("ER100")
                });
                return
            } else {
                if (b == null || b == "") {
                    callback(ML4WebLog.getErrCode("Crypto_API_pkcs7"), {
                        errCode: 100,
                        errMsg: $.i18n.prop("ER100")
                    });
                    return
                } else {
                    if (f == null || f == "") {
                        callback(ML4WebLog.getErrCode("Crypto_API_pkcs7"), {
                            errCode: 100,
                            errMsg: $.i18n.prop("ER100")
                        });
                        return
                    } else {
                        if (a == null || a == "") {
                            callback(ML4WebLog.getErrCode("Crypto_API_pkcs7"), {
                                errCode: 100,
                                errMsg: $.i18n.prop("ER100")
                            });
                            return
                        }
                    }
                }
            }
            try {
                var c = cryptObj.pkcs7(g, b, f, a, d, arguments[5], arguments[6]);
                return c
            } catch (h) {
                callback(ML4WebLog.getErrCode("Crypto_API_pkcs7"), {
                    errCode: 888,
                    errMsg: h.message
                });
                return
            }
        }
    },
    ml4web_storage_api: null,
    ml4web_resource_api: null,
    ml4web_cs_manager: null,
    get_browser_info: function() {
        var b = navigator.userAgent,
            a, c = b.match(/(opera|chrome|safari|firefox|msie|trident(?=\/))\/?\s*(\d+)/i) || [];
        if (/trident/i.test(c[1])) {
            a = /\brv[ :]+(\d+)/g.exec(b) || [];
            return {
                name: "IE",
                version: (a[1] || "")
            }
        }
        if (c[1] === "Chrome") {
            a = b.match(/\bOPR\/(\d+)/);
            if (a != null) {
                return {
                    name: "Opera",
                    version: a[1]
                }
            }
            a = b.match(/\bEdge\/(\d+)/);
            if (a != null) {
                return {
                    name: "Edge",
                    version: a[1]
                }
            }
        }
        c = c[2] ? [c[1], c[2]] : [navigator.appName, navigator.appVersion, "-?"];
        if ((a = b.match(/version\/(\d+)/i)) != null) {
            c.splice(1, 1, a[1])
        }
        return {
            name: c[0],
            version: c[1]
        }
    },
    dsencrypt: function(b) {
        var a = magicjs.cipher.create(true, "SEED-CBC", magicjs.base64.decode(ML4WebApi.ml4web_crypto_api.genDsToken()));
        a.init(magicjs.generateRandomBytes(16));
        a.update("0000000000000000" + magicjs.utf8.encode(b));
        a.finish();
        return magicjs.base64.encode(a.output)
    },
    dsDecrypt: function(b) {
        var a = magicjs.cipher.create(false, "SEED-CBC", magicjs.base64.decode("wqpRRHAjpW48fSp6Sd2g7Q=="));
        a.init(magicjs.generateRandomBytes(16));
        a.update(magicjs.base64.decode(b));
        a.finish();
        var c = magicjs.utf8.decode(a.output.data.substring(16, a.output.data.length));
        return c
    },
    setDSCertFieldInfo: function() {
        DS_CERT_INFO.VERSION = "version";
        DS_CERT_INFO.SERIALNUM = "serialnum";
        DS_CERT_INFO.SIGNATUREALGORITHM = "signaturealgorithm";
        DS_CERT_INFO.ISSUERNAME = "issuername";
        DS_CERT_INFO.STARTDATE = "startdate";
        DS_CERT_INFO.ENDDATE = "enddate";
        DS_CERT_INFO.SUBJECTNAME = "subjectname";
        DS_CERT_INFO.PUBKEY = "pubkey";
        DS_CERT_INFO.PUBKEYALGORITHM = "pubkeyalgorithm";
        DS_CERT_INFO.KEYUSAGE = "keyusage";
        DS_CERT_INFO.CERTPOLICY = "certpolicy";
        DS_CERT_INFO.POLICYID = "policyid";
        DS_CERT_INFO.POLICYNOTICE = "policynotice";
        DS_CERT_INFO.SUBJECTALTNAME = "subjectaltname";
        DS_CERT_INFO.AUTHKEYID = "authkeyid";
        DS_CERT_INFO.SUBKEYID = "subkeyid";
        DS_CERT_INFO.CRLDP = "crldp";
        DS_CERT_INFO.AIA = "aia";
        DS_CERT_INFO.REALNAME = "realname";
        DS_CERT_INFO.STARTDATETIME = "startdatetime";
        DS_CERT_INFO.ENDDATETIME = "enddatetime"
    },
    loadResource: function(a) {
        ML4WebLog.log("ML4WebApi.loadResource() called... ");
        if (ML4WebApi.ml4web_resource_api == null) {
            ML4WebApi.ml4web_resource_api = new Resource_API(csConfigOpt, (ML4WebApi.webConfig.libType == 0) ? true : false);
            ML4WebApi.ml4web_resource_api.init(10000, function(b, c) {
                if (b == 0) {
                    if (ML4WebApi.ml4web_storage_api == null) {
                        ML4WebApi.ml4web_storage_api = new Storage_API();
                        ML4WebApi.ml4web_storage_api.init(function(d, e) {
                            if (d == 0) {
                                ML4WebApi.ml4web_crypto_api.init(ML4WebApi.webConfig.libType, ML4WebApi.ml4web_resource_api, function(f, g) {
                                    if (ML4WebApi.ml4web_cs_manager == null) {
                                        ML4WebApi.ml4web_cs_manager = new CS_Manager_API(ML4WebApi.ml4web_resource_api, csConfigOpt);
                                        ML4WebApi.ml4web_cs_manager.init(function(j, h) {
                                            if (j == 0) {
                                                a(0, {
                                                    isInstall: ML4WebApi.webConfig.is_cs_install,
                                                    isUpdate: ML4WebApi.webConfig.is_cs_update
                                                });
                                                return
                                            } else {
                                                a(j, {
                                                    isInstall: ML4WebApi.webConfig.is_cs_install,
                                                    isUpdate: ML4WebApi.webConfig.is_cs_update
                                                });
                                                return
                                            }
                                        })
                                    }
                                })
                            }
                        })
                    }
                }
            })
        }
    },
    isEmpty: function(a) {
        if (a == null | typeof a == "undefined" || a.trim().length < 1) {
            return true
        } else {
            return false
        }
    },
    detectBrower: function() {
        try {
            var a = ML4WebApi.get_browser_info();
            ML4WebApi.webConfig.browser = a.name + " " + a.version;
            return a
        } catch (b) {
            ML4WebLog.log("[ERROR]ML4WebApi.detectBrower() : " + b.message)
        }
    },
    detectOs: function() {
        try {
            var b = navigator.userAgent;
            b = b.toUpperCase();
            if (b.indexOf("IPHONE") > -1) {
                ML4WebApi.webConfig.os = "IPHONE"
            } else {
                if (b.indexOf("IPAD") > -1) {
                    ML4WebApi.webConfig.os = "IPAD"
                } else {
                    if (b.indexOf("NT 4.0") > -1) {
                        ML4WebApi.webConfig.os = "windows NT 4.0"
                    } else {
                        if (b.indexOf("NT 5.0") > -1) {
                            ML4WebApi.webConfig.os = "windows 2000"
                        } else {
                            if (b.indexOf("NT 5.01") > -1) {
                                ML4WebApi.webConfig.os = "windows 2000 sp1"
                            } else {
                                if (b.indexOf("NT 5.1") > -1) {
                                    ML4WebApi.webConfig.os = "windows XP"
                                } else {
                                    if (b.indexOf("NT 5.2") > -1) {
                                        ML4WebApi.webConfig.os = "windows 2003"
                                    } else {
                                        if (b.indexOf("NT 6.0") > -1) {
                                            ML4WebApi.webConfig.os = "windows Vista/Server 2008"
                                        } else {
                                            if (b.indexOf("NT 6.1") > -1) {
                                                ML4WebApi.webConfig.os = "windows 7"
                                            } else {
                                                if (b.indexOf("NT 6.2") > -1) {
                                                    ML4WebApi.webConfig.os = "windows 8"
                                                } else {
                                                    if (b.indexOf("NT 6.3") > -1) {
                                                        ML4WebApi.webConfig.os = "windows 8.1"
                                                    } else {
                                                        if (b.indexOf("NT 10.0") > -1) {
                                                            ML4WebApi.webConfig.os = "windows 10"
                                                        } else {
                                                            if (b.indexOf("ANDROID") > -1) {
                                                                ML4WebApi.webConfig.os = "Android"
                                                            } else {
                                                                if (b.indexOf("BLACKBERRY") > -1) {
                                                                    ML4WebApi.webConfig.os = "BlackBerry"
                                                                } else {
                                                                    if (b.indexOf("MAC") > -1) {
                                                                        ML4WebApi.webConfig.os = "MAC"
                                                                    } else {
                                                                        if (b.indexOf("SYMBIAN") > -1) {
                                                                            ML4WebApi.webConfig.os = "Symbian"
                                                                        } else {
                                                                            if (b.indexOf("UBUNTU") != -1) {
                                                                                if (b.indexOf("86_64") != -1) {
                                                                                    ML4WebApi.webConfig.os = "LINUX64_UBUNTU64"
                                                                                } else {
                                                                                    ML4WebApi.webConfig.os = "LINUX32_UBUNTU32"
                                                                                }
                                                                            } else {
                                                                                if (b.indexOf("FEDORA") != -1) {
                                                                                    if (b.indexOf("86_64") != -1) {
                                                                                        ML4WebApi.webConfig.os = "LINUX64_FEDORA64"
                                                                                    } else {
                                                                                        ML4WebApi.webConfig.os = "LINUX32_FEDORA32"
                                                                                    }
                                                                                } else {
                                                                                    if (b.indexOf("LINUX") != -1) {
                                                                                        if (b.indexOf("86_64") != -1) {
                                                                                            ML4WebApi.webConfig.os = "LINUX64"
                                                                                        } else {
                                                                                            ML4WebApi.webConfig.os = "LINUX32"
                                                                                        }
                                                                                    } else {
                                                                                        ML4WebApi.webConfig.os = "Unknown"
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return ML4WebApi.webConfig.os;
            ML4WebLog.log("ML4WebApi.detectOs() called...")
        } catch (a) {
            ML4WebLog.log("[ERROR]ML4WebApi.detectOs() : " + a.message)
        }
    },
    base64Encode: function(a) {
        try {
            return magicjs.base64.encode(a)
        } catch (b) {
            return ""
        }
    },
    base64Decode: function(a) {
        try {
            return magicjs.base64.decode(a)
        } catch (b) {
            return ""
        }
    },
    makeReverseDN: function(c) {
        try {
            var f = "";
            var a = c.split(",");
            for (var b = a.length - 1; b >= 0; b--) {
                cutStr = a[b].substr(0, a[b].indexOf("="));
                if (b == 0) {
                    f += a[b].replace(cutStr, cutStr.toUpperCase())
                } else {
                    f += a[b].replace(cutStr, cutStr.toUpperCase()) + "/"
                }
            }
            return f
        } catch (d) {
            return ""
        }
    },
    getSignDN: function(b) {
        try {
            if (ML4WebApi.UserInfo.userDn != "") {
                b("0", ML4WebApi.UserInfo.userDn)
            } else {
                b("1", "")
            }
        } catch (a) {
            b(ML4WebLog.getErrCode("ML4Web_API_getSignDN"), {
                errCode: a.code,
                errMsg: a.message
            })
        }
    },
    signatureData: function(b, c) {
        try {
            ML4WebApi.makeSignData(ML4WebApi.UserInfo.selectCertInfo, ML4WebApi.ml4web_crypto_api.HD_result, ML4WebApi.UserInfo.opt, b, c)
        } catch (a) {
            c(ML4WebLog.getErrCode("ML4Web_API_signatureData"), {
                errCode: a.code,
                errMsg: a.message
            })
        }
    },
    convertFilesToBase64String: function(n, m) {
        try {
            if (n.length === 3) {
                m(206, g);
                return
            }
            var f = [];
            var l = [];
            for (var r = 0; r < n.length; r++) {
                if (n[r].name.indexOf(".cer") > -1 || n[r].name.indexOf(".der") > -1 || n[r].name.indexOf(".pfx") > -1 || n[r].name.indexOf(".p12") > -1) {
                    f.push(n[r])
                } else {
                    l.push(n[r])
                }
            }
            if (f.length < 1) {
                m(116, g);
                return
            }
            f.sort(function(x, e) {
                return x.name > e.name ? -1 : x.name < e.name ? 1 : 0
            });
            l.sort(function(x, e) {
                return x.name > e.name ? -1 : x.name < e.name ? 1 : 0
            });
            var k = "";
            var v = "";
            var p = "";
            var s = "";
            var b = "";
            var g = {};
            var d = 100;
            for (var r = 0; r < f.length; r++) {
                k = f[r].name.toUpperCase();
                v = (k.indexOf(".CER") > -1) || (k.indexOf(".DER") > -1);
                p = (k.indexOf(".PFX") > -1);
                s = (k.indexOf(".P12") > -1);
                b = (k.indexOf("ENV.CER") > -1 || k.indexOf("ENV.DER") > -1 || k.indexOf("KMCERT.CER") > -1 || k.indexOf("KMCERT.DER") > -1)
            }
            g.fileName = f[0].name;
            var o = "";
            var j = "";
            var q = "";
            for (var r = 0; r < l.length; r++) {
                o = l[r].name.toUpperCase();
                j = (o.indexOf(".KEY") > -1);
                q = (o.indexOf("ENV.KEY") > -1 || o.indexOf("KMPRI.KEY") > -1)
            }
            if (n.length === 2 && ((b && j) || (v && q))) {
                m(205, g);
                return
            }
            if (v && j) {
                g.type = "cert";
                var w = new FileReader();
                var c = new FileReader();
                if (b && q) {
                    var h = new FileReader();
                    var t = new FileReader()
                }
                w.readAsBinaryString = function(e) {
                    var y = "";
                    var x = this;
                    w.onload = function(C) {
                        var z = new Uint8Array(w.result);
                        var B = z.byteLength;
                        for (var A = 0; A < B; A++) {
                            y += String.fromCharCode(z[A])
                        }
                        x.content = btoa(y);
                        g.cert = x.content;
                        c.readAsBinaryString(l[0])
                    };
                    w.readAsArrayBuffer(e)
                };
                c.readAsBinaryString = function(e) {
                    var y = "";
                    var x = this;
                    c.onload = function(C) {
                        var z = new Uint8Array(c.result);
                        var B = z.byteLength;
                        for (var A = 0; A < B; A++) {
                            y += String.fromCharCode(z[A])
                        }
                        x.content = btoa(y);
                        g.key = x.content;
                        if (b && q) {
                            h.readAsBinaryString(f[1])
                        } else {
                            m(0, g)
                        }
                    };
                    c.readAsArrayBuffer(e)
                };
                if (b && q) {
                    h.readAsBinaryString = function(e) {
                        var y = "";
                        var x = this;
                        h.onload = function(C) {
                            var z = new Uint8Array(h.result);
                            var B = z.byteLength;
                            for (var A = 0; A < B; A++) {
                                y += String.fromCharCode(z[A])
                            }
                            x.content = btoa(y);
                            g.kmCert = x.content;
                            t.readAsBinaryString(l[1])
                        };
                        h.readAsArrayBuffer(e)
                    };
                    t.readAsBinaryString = function(e) {
                        var y = "";
                        var x = this;
                        t.onload = function(C) {
                            var z = new Uint8Array(t.result);
                            var B = z.byteLength;
                            for (var A = 0; A < B; A++) {
                                y += String.fromCharCode(z[A])
                            }
                            x.content = btoa(y);
                            g.kmPri = x.content;
                            m(0, g)
                        };
                        t.readAsArrayBuffer(e)
                    }
                }
                w.readAsBinaryString(f[0])
            } else {
                if (p || s) {
                    if (p) {
                        g.type = "pfx"
                    } else {
                        g.type = "p12"
                    }
                    var a = new FileReader();
                    a.readAsBinaryString = function(e) {
                        var y = "";
                        var x = this;
                        a.onload = function(C) {
                            var z = new Uint8Array(a.result);
                            var B = z.byteLength;
                            for (var A = 0; A < B; A++) {
                                y += String.fromCharCode(z[A])
                            }
                            x.content = btoa(y);
                            g.pfx = x.content;
                            m(0, g)
                        };
                        a.readAsArrayBuffer(e)
                    };
                    a.readAsBinaryString(f[0])
                } else {
                    m(116, g)
                }
            }
            return
        } catch (u) {
            m(ML4WebLog.getErrCode("ML4Web_API_changeFilesToCertAndKey"), {
                errCode: u.code,
                errMsg: u.message
            });
            return
        }
    },
    createRandomValue: function() {
        var a = new Uint32Array(1);
        window.crypto.getRandomValues(a);
        return a[0]
    },
    loadSession: function() {
        var a = ML4WebApi.sessionConfig.SESSION_KEY;
        var f = sessionStorage.getItem(a);
        if (f == null || f.length === 0) {
            return {}
        }
        try {
            var c = magicjs.base64.decode(f);
            var e = magicjs.hex.encode(c.slice(0, 32));
            var d = c.slice(32);
            c = ML4WebApi.symmDecrypt("AES256-CBC", e.slice(parseInt(e.slice(0, 1), 16), parseInt(e.slice(0, 1), 16) + 32), e.slice(parseInt(e.slice(1, 2), 16), parseInt(e.slice(1, 2), 16) + 16), d);
            return JSON.parse(c)
        } catch (b) {
            console.log(b)
        }
        return {}
    },
    generateSalt: function() {
        var b;
        try {
            b = parseInt(magicjs.generateRandomBytes(1).toHex(), 16) * 4 + 1 + 1024
        } catch (a) {
            b = Math.floor(Math.random() * 1024) + 1 + 1024
        }
        return b
    },
    generateHash: function(f, c, d) {
        var g;
        try {
            var e = magicjs.md.create(f);
            e.init();
            for (var b = 0; b < d; b++) {
                e.update(c)
            }
            g = e.digest().toHex()
        } catch (a) {
            g = ""
        }
        return g
    },
    asymmDecrypt: function(e, b, g) {
        var a;
        var f;
        var d = {
            md: "SHA1",
            scheme: "RSAES-PKCS1-v1_5"
        };
        try {
            a = magicjs.pkcs5.decrypt(e, b);
            f = a.decrypt(magicjs.base64.decode(g), d)
        } catch (c) {
            try {
                a = magicjs.priKey.create(e);
                f = a.decrypt(magicjs.base64.decode(g), d)
            } catch (c) {
                f = ""
            }
        }
        return f
    },
    symmDecrypt: function(d, b, c, g) {
        var f;
        try {
            var a = magicjs.cipher.create(false, d, b);
            a.init(c);
            a.update(g);
            f = magicjs.utf8.decode(a.finish())
        } catch (e) {
            f = ""
        }
        return f
    },
    generateKeyPair: function() {
        try {
            ML4WebApi.sessionConfig.API_E2E_KEY = magicjs.generateKeyPair("rsa", {
                bits: "1024"
            })
        } catch (a) {
            console.log("generateKeyPair error!");
            ML4WebApi.sessionConfig.API_E2E_KEY = {}
        }
    },
    getKeyPair: function() {
        return ML4WebApi.sessionConfig.API_E2E_KEY
    },
    generateSecurekey: function(d, a, c) {
        try {
            var m = ML4WebApi.asymmDecrypt(ML4WebApi.getKeyPair().privateKey.toPem(), "", d);
            var g = ML4WebApi.generateSalt();
            var b = magicjs.pkcs5.decrypt(c, m);
            var f = ML4WebApi.generateHash("sha256", a.serialNum, g);
            var k = "";
            var l;
            try {
                k = magicjs.base64.encode(b.getRandomNum())
            } catch (h) {
                k = ""
            }
            b = magicjs.pkcs5.encrypt(b, f, {
                algorithm: "aes256",
                count: "2048",
                saltSize: "8"
            });
            l = magicjs.hex.encode(magicjs.hex.encode(g.toString())).concat(b.data);
            l = ML4WebApi.symmEncrypt("AES256-CBC", a.signature.slice(0, 32), a.signature.slice(64, 80), l);
            return {
                encPriKey: l,
                randomNum: k
            }
        } catch (j) {
            return null
        }
    },
    decryptSecurekey: function(g, b) {
        try {
            var f = ML4WebApi.symmDecrypt("AES256-CBC", g.signature.slice(0, 32), g.signature.slice(64, 80), magicjs.base64.decode(b));
            var e = magicjs.hex.decode(magicjs.hex.decode(f.slice(0, 16)));
            var c = ML4WebApi.generateHash("sha256", g.serialNum, parseInt(e));
            var a;
            a = magicjs.pkcs5.decrypt(magicjs.base64.encode(f.slice(16)), c);
            return a
        } catch (d) {
            return null
        }
    },
    symmEncrypt: function(d, b, c, g) {
        var f;
        try {
            var a = magicjs.cipher.create(true, d, b);
            a.init(c);
            a.update(magicjs.utf8.encode(g));
            f = a.finish();
            f = magicjs.base64.encode(f)
        } catch (e) {
            f = ""
        }
        return f
    },
    saveToStorage: function(d) {
        var a = ML4WebApi.sessionConfig.SESSION_KEY;
        var b = JSON.stringify(d);
        var c = magicjs.hex.encode(magicjs.generateRandomBytes(32));
        b = ML4WebApi.symmEncrypt("AES256-CBC", c.slice(parseInt(c.slice(0, 1), 16), parseInt(c.slice(0, 1), 16) + 32), c.slice(parseInt(c.slice(1, 2), 16), parseInt(c.slice(1, 2), 16) + 16), b);
        b = magicjs.base64.decode(b);
        c = magicjs.hex.decode(c).concat(b);
        c = magicjs.base64.encode(c);
        sessionStorage.setItem(a, c);
        return true
    },
    saveSession: function(c, h, e) {
        if (typeof(c) == "object") {
            ML4WebApi.saveToStorage(c);
            return true
        }
        var a;
        var d = ML4WebApi.loadSession();
        if (arguments.length === 2) {
            d[c] = h;
            return ML4WebApi.saveToStorage(d)
        }
        if (typeof(d[c]) == "undefined") {
            d[c] = {}
        }
        if (typeof(h) != "undefined") {
            d[c].select_media = h
        }
        if (typeof(e.tokenname) != "undefined") {
            d[c].pkcs11_name = e.tokenname
        }
        if (typeof(e.tokenidx) != "undefined") {
            d[c].pkcs11_cert = e.tokenidx
        }
        if (typeof(e.tokenpwd) != "undefined") {
            d[c].pkcs11_pinnum = e.tokenpwd
        }
        if (typeof(e.storageCertIdx) != "undefined") {
            d[c].storageCertIdx = e.storageCertIdx
        }
        if (typeof(e.signcert) != "undefined") {
            d[c].signcert = {};
            d[c].signcert.info = ML4WebApi.getCertificateInfo(e.signcert);
            d[c].signcert.cert = e.signcert
        }
        if (typeof(e.signpri) != "undefined") {
            if (typeof(e.token) == "undefined") {
                d[c].signcert.pri = e.signpri
            } else {
                a = ML4WebApi.generateSecurekey(e.token, d[c].signcert.info, e.signpri);
                if (a != null) {
                    d[c].signcert.pri = a.encPriKey;
                    d[c].signcert.encpri = e.signpri;
                    d[c].signcert.randomNum = a.randomNum
                } else {
                    if (typeof(e.randomNum) != "undefined") {
                        d[c].signcert.randomNum = e.randomNum
                    }
                }
            }
        }
        if (typeof(e.kmcert) != "undefined") {
            d[c].kmcert = {};
            d[c].kmcert.info = ML4WebApi.getCertificateInfo(e.kmcert);
            d[c].kmcert.cert = e.kmcert
        }
        if (typeof(e.kmpri) != "undefined") {
            if (typeof(e.token) == "undefined") {
                d[c].kmcert.pri = e.kmpri
            } else {
                a = ML4WebApi.generateSecurekey(e.token, d[c].kmcert.info, e.kmpri);
                if (a != null) {
                    d[c].kmcert.pri = a.encPriKey;
                    d[c].kmcert.encpri = e.kmpri;
                    d[c].kmcert.randomNum = a.randomNum
                } else {
                    if (typeof(e.randomNum) != "undefined") {
                        d[c].kmcert.randomNum = e.randomNum
                    }
                }
            }
        }
        var j = d[c].select_media.toLowerCase();
        if (typeof(localStorage) != "undefined" && j == "web" || j == "hdd") {
            var g = d[c].signcert.info.subject.split(",");
            var b = g[0].split("=");
            var f = b[1];
            localStorage.setItem("ML4WebCertCn", magicjs.base64.encode(magicjs.utf8.encode(f)));
            localStorage.setItem("ML4WebSelectMedia", magicjs.base64.encode(j))
        }
        return ML4WebApi.saveToStorage(d)
    },
    initSession: function() {
        if (typeof(sessionStorage) == "undefined" || sessionStorage == null) {
            return false
        }
        if (typeof(magicjs) == "undefined" || typeof(ConfigObject) == "undefined") {
            return false
        }
        var a = ML4WebApi.sessionConfig.SESSION_KEY;
        sessionStorage.setItem(a, "");
        return true
    },
    deleteSession: function(c) {
        if (typeof(sessionStorage) == "undefined" || sessionStorage == null) {
            return false
        }
        if (typeof(magicjs) == "undefined" || typeof(ConfigObject) == "undefined") {
            return false
        }
        if (typeof(c) == "undefined" || typeof(c) != "string") {
            return false
        }
        try {
            var b = ML4WebApi.loadSession();
            c = ML4WebApi.prefixSession(c);
            if (b.hasOwnProperty(c) == false) {
                return false
            }
            delete b[c];
            ML4WebApi.saveSession(b)
        } catch (a) {
            return false
        }
        return true
    },
    deleteSessionAll: function() {
        if (typeof(sessionStorage) == "undefined" || sessionStorage == null) {
            return false
        }
        if (typeof(magicjs) == "undefined" || typeof(ConfigObject) == "undefined") {
            return false
        }
        try {
            var d = ML4WebApi.loadSession();
            var c = [];
            for (key in d) {
                if (key.length >= 9 && key.indexOf("SESSION_") === 0) {
                    c.push(key)
                }
            }
            for (var b = 0; b < c.length; b++) {
                delete d[c[b]]
            }
            ML4WebApi.saveSession(d)
        } catch (a) {
            return false
        }
        return true
    },
    prefixSession: function(a) {
        return "SESSION_" + a
    },
    getCertificateInfo: function(g) {
        var a = {};
        try {
            var d = magicjs.x509Cert.create(g, false);
            var h = d.extensions.length;
            a.version = d.version;
            a.serialNum = d.serialNum;
            a.issuer = d.issuer;
            a.notBefore = ML4WebApi.genTimeStamp(d.validity.notBefore.getFullYear(), d.validity.notBefore.getMonth() + 1, d.validity.notBefore.getDate(), d.validity.notBefore.getHours(), d.validity.notBefore.getMinutes(), d.validity.notBefore.getSeconds());
            a.notAfter = ML4WebApi.genTimeStamp(d.validity.notAfter.getFullYear(), d.validity.notAfter.getMonth() + 1, d.validity.notAfter.getDate(), d.validity.notAfter.getHours(), d.validity.notAfter.getMinutes(), d.validity.notAfter.getSeconds());
            a.subject = d.subject;
            a.publickey = d.pubKey.toDer().toHex();
            a.signatureAlgorithm = d.signAlg.name;
            a.signature = d.signature.toHex();
            for (var f = 0; f < h; f++) {
                if (typeof(d.extensions[f].aki) != "undefined") {
                    a.authKeyID = this.stringFormat("KeyID={0}\n", d.extensions[f].aki.keyIdentifier.toHex());
                    a.authKeyID += this.stringFormat("Certificate Issuer:\n{0}\n", d.extensions[f].aki.authorityCertIssuer);
                    a.authKeyID += this.stringFormat("Certificate SerialNumber={0}", d.extensions[f].aki.authorityCertIssuer)
                } else {
                    if (typeof(d.extensions[f].ski) != "undefined") {
                        a.subjectKeyId = d.extensions[f].ski.toHex()
                    } else {
                        if (typeof(d.extensions[f].keyUsage) != "undefined") {
                            var c = "";
                            if (typeof(d.extensions[f].keyUsage.cRLSign) != "undefined" && d.extensions[f].keyUsage.cRLSign === true) {
                                c = "cRLSign"
                            }
                            if (typeof(d.extensions[f].keyUsage.dataEncipherment) != "undefined" && d.extensions[f].keyUsage.dataEncipherment === true) {
                                if (c.length) {
                                    c += ", "
                                }
                                c += "dataEncipherment"
                            }
                            if (typeof(d.extensions[f].keyUsage.decipherOnly) != "undefined" && d.extensions[f].keyUsage.decipherOnly === true) {
                                if (c.length) {
                                    c += ", "
                                }
                                c += "decipherOnly"
                            }
                            if (typeof(d.extensions[f].keyUsage.digitalSignature) != "undefined" && d.extensions[f].keyUsage.digitalSignature === true) {
                                if (c.length) {
                                    c += ", "
                                }
                                c += "digitalSignature"
                            }
                            if (typeof(d.extensions[f].keyUsage.encipherOnly) != "undefined" && d.extensions[f].keyUsage.encipherOnly === true) {
                                if (c.length) {
                                    c += ", "
                                }
                                c += "encipherOnly"
                            }
                            if (typeof(d.extensions[f].keyUsage.keyAgreenment) != "undefined" && d.extensions[f].keyUsage.keyAgreenment === true) {
                                if (c.length) {
                                    c += ", "
                                }
                                c += "keyAgreenment"
                            }
                            if (typeof(d.extensions[f].keyUsage.keyCertSign) != "undefined" && d.extensions[f].keyUsage.keyCertSign === true) {
                                if (c.length) {
                                    c += ", "
                                }
                                c += "keyCertSign"
                            }
                            if (typeof(d.extensions[f].keyUsage.keyEncipherment) != "undefined" && d.extensions[f].keyUsage.keyEncipherment === true) {
                                if (c.length) {
                                    c += ", "
                                }
                                c += "keyEncipherment"
                            }
                            if (typeof(d.extensions[f].keyUsage.nonRepudiation) != "undefined" && d.extensions[f].keyUsage.nonRepudiation === true) {
                                if (c.length) {
                                    c += ", "
                                }
                                c += "nonRepudiation"
                            }
                            a.keyUsage = c
                        } else {
                            if (typeof(d.extensions[f].certPolicies) != "undefined") {
                                for (var b = 0; b < d.extensions[f].certPolicies.length; b++) {
                                    a.policyIdentifier = d.extensions[f].certPolicies[b].policyIdentifier;
                                    if (d.extensions[f].certPolicies[b].unotice != null && d.extensions[f].certPolicies[b].unotice.explicitText != null) {
                                        a.policyNotice = d.extensions[f].certPolicies[b].unotice.explicitText
                                    }
                                }
                            } else {
                                if (typeof(d.extensions[f].subjectAltName) != "undefined") {
                                    if (typeof(d.extensions[f].subjectAltName[0].otherName) != "undefined") {
                                        if (typeof(d.extensions[f].subjectAltName[0].otherName.realName) != "undefined") {
                                            a.realName = d.extensions[f].subjectAltName[0].otherName.realName
                                        }
                                        if (typeof(d.extensions[f].subjectAltName[0].otherName.vid) != "undefined") {
                                            a.vidHashAlgo = d.extensions[f].subjectAltName[0].otherName.vid.hashAlg;
                                            a.vidHash = d.extensions[f].subjectAltName[0].otherName.vid.value.toHex()
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (e) {
            console.log(e)
        }
        return a
    },
    getPadding: function(b, a, c) {
        c = c || "0";
        b = b + "";
        return b.length >= a ? b : new Array(a - b.length + 1).join(c) + b
    },
    genTimeStamp: function(n, h, c, e, d, b, f) {
        var a = this.getPadding(n, 4);
        var k = this.getPadding(h, 2);
        var g = this.getPadding(c, 2);
        var m = this.getPadding(e, 2);
        var o = this.getPadding(d, 2);
        var l = this.getPadding(b, 2);
        var j = typeof(f) == "undefined" ? " " : f;
        return this.stringFormat("{0}-{1}-{2}{3}{4}:{5}:{6}", a, k, g, j, m, o, l)
    },
    convertSessionInfoToCertObj: function(b) {
        var a = {};
        a.certbag = {};
        a.certbag.signcert = b.signcert.cert;
        a.certbag.signpri = "";
        a.signcert = b.signcert.cert;
        a.signpri = "";
        a.selectedStg = b.select_media;
        a.pw = "";
        a.rowData = b.signcert.info;
        return a
    },
    stringFormat: function() {
        var c = arguments[0];
        for (var b = 1; b < arguments.length; b++) {
            var a = "{" + (b - 1) + "}";
            c = c.replace(a, arguments[b])
        }
        return c
    }
};
if (typeof MessageVO === "undefined") {
    var _MessageVO = {
        loadMessage: function(a) {
            $.i18n.properties({
                name: "Messages",
                path: "js/message/",
                mode: "both",
                language: a,
                callback: function() {}
            })
        },
        applyMessage: function(a) {
            a.each(function() {
                var b = this.id.split("MSG_")[1];
                $(this).html($.i18n.prop(b))
            })
        }
    };
    if (!window.MessageVO) {
        window.MessageVO = _MessageVO
    }
}
if (typeof ML4WebLog === "undefined" || $.isEmptyObject(ML4WebLog) || ML4WebLog === null) {
    var errorCodeObject = {};
    var _ML4WebLog = {
        init: function() {
            try {
                if (arguments.length == 0) {
                    $.cachedScript("js/util/ML4Web_ErrorCode.js").done(function(d, c) {
                        new Function(d)();
                        errorCodeObject = ErrorCodeObject
                    })
                } else {
                    var a = arguments[0] + "/ML4Web_ErrorCode.js";
                    $.cachedScript(a).done(function(d, c) {
                        new Function(d)();
                        errorCodeObject = ErrorCodeObject
                    })
                }
            } catch (b) {
                return
            }
        },
        log: function(b) {
            var a = "[ML4WebLog]:: " + b;
            if (ML4WebApi.webConfig.logType == "console") {
                if (ML4WebApi.webConfig.browser == "MSIE 8") {
                    console.log("[" + ML4WebApi.webConfig.browser + "]:: " + b)
                } else {
                    console.log(a)
                }
            } else {
                if (ML4WebApi.webConfig.logType == "alert") {
                    alert(a)
                } else {
                    var c = "true";
                    if (typeof(localStorage) != "undefined") {
                        c = localStorage.getItem("ML4WebLog");
                        if (c == null) {
                            c = "false"
                        }
                        if (c == "false") {
                            return
                        }
                        if (ML4WebApi.webConfig.browser == "MSIE 8") {
                            console.log("[" + ML4WebApi.webConfig.browser + "]:: " + b)
                        } else {
                            console.log(a)
                        }
                    } else {
                        return
                    }
                }
            }
        },
        getErrCode: function(a) {
            return errorCodeObject[a]
        }
    };
    window.ML4WebLog = _ML4WebLog
}

function addDSLine() {
    if (typeof initModule !== "function") {
        return
    }
    var a = {};
    if (typeof window === "object") {
        if (typeof window.dreams === "object") {
            a = window.dreams
        } else {
            window.dreams = a
        }
    }
    initModule();
    return a
}
var dreams = addDSLine();
var DS_CERT_INFO = function() {};