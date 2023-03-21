"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.base64ToHexString = exports.base64ToString = exports.base64ToByteArray = exports.stringToHexString = exports.stringSHA256 = exports.byteArrayToBinaryString = exports.byteArrayToUint32BigEndian = exports.byteArrayToUint16BigEndian = exports.byteArrayRange = exports.stringToBase64 = exports.byteArrayToBase64 = exports.byteArrayToString = exports.hexStringToByteArray = exports.byteArrayToHexString = exports.stringToByteArray = exports.ASN1ECP256PublicKeyByteArrayToPEMString = exports.verifyECP256Signature = exports.COSEtoASN1PublicKey = exports.getCredentialAssertionData = exports.getCredentialRegistrationData = exports.getAttestation = exports.createPublicKeyCredential = exports.isPublicKeyCredentialSupported = void 0;
const js_sha256_1 = require("js-sha256");
const byteBase64 = __importStar(require("byte-base64"));
const CBOR = __importStar(require("cbor-redux"));
function isPublicKeyCredentialSupported() {
    let response = false;
    if (window) {
        if (window.PublicKeyCredential) {
            response = true;
        }
    }
    return response;
}
exports.isPublicKeyCredentialSupported = isPublicKeyCredentialSupported;
function createPublicKeyCredential(options) {
    return __awaiter(this, void 0, void 0, function* () {
        let credential = navigator.credentials.create({ publicKey: options });
        return credential;
    });
}
exports.createPublicKeyCredential = createPublicKeyCredential;
function getAttestation(options) {
    return __awaiter(this, void 0, void 0, function* () {
        let credential = navigator.credentials.get({ publicKey: options });
        return credential;
    });
}
exports.getAttestation = getAttestation;
function getCredentialRegistrationData(credential) {
    let credentialResponse = credential.response;
    const decodedAttestationObj = CBOR.decode(credentialResponse.attestationObject);
    let credentialIdLength = byteArrayToUint16BigEndian(byteArrayRange(decodedAttestationObj.authData, 53, 2));
    let credentialId = byteArrayRange(decodedAttestationObj.authData, 55, credentialIdLength);
    let credentialPublicKey = byteArrayRange(decodedAttestationObj.authData, 55 + credentialIdLength);
    let response = {
        id: credential.id,
        rawId: new Uint8Array(credential.rawId),
        clienDataJSON: new Uint8Array(credentialResponse.clientDataJSON),
        attestationObject: {
            fmt: decodedAttestationObj.fmt,
            attStmt: {
                alg: decodedAttestationObj.attStmt.alg,
                sig: decodedAttestationObj.attStmt.sig,
                x5c: decodedAttestationObj.attStmt.x5c,
            },
            authData: {
                rpIdHash: byteArrayRange(decodedAttestationObj.authData, 0, 32),
                flags: byteArrayRange(decodedAttestationObj.authData, 32, 1),
                signCount: byteArrayRange(decodedAttestationObj.authData, 33, 4),
                aaguid: byteArrayRange(decodedAttestationObj.authData, 37, 16),
                credentialIdLength: byteArrayRange(decodedAttestationObj.authData, 53, 2),
                credentialId: credentialId,
                credentialPublicKey: credentialPublicKey,
                publicKey: CBOR.decode(credentialPublicKey.buffer),
            },
        },
        type: credential.type,
    };
    return response;
}
exports.getCredentialRegistrationData = getCredentialRegistrationData;
function getCredentialAssertionData(assertion) {
    let assertionResponse = assertion.response;
    let assertionResponseAuthenticatorDataUint8Array = new Uint8Array(assertionResponse.authenticatorData);
    let rpIdHash = byteArrayRange(assertionResponseAuthenticatorDataUint8Array, 0, 32);
    let flags = byteArrayRange(assertionResponseAuthenticatorDataUint8Array, 32, 1);
    let signCount = byteArrayRange(assertionResponseAuthenticatorDataUint8Array, 33, 4);
    let clientDataHash = new Uint8Array(js_sha256_1.sha256.array(assertionResponse.clientDataJSON));
    let signatureBase = new Uint8Array([...rpIdHash, ...flags, ...signCount, ...clientDataHash]);
    let response = {
        authenticatorAttachment: 'cross-platform',
        id: assertion.id,
        rawId: new Uint8Array(assertion.rawId),
        response: {
            authenticatorData: {
                rpIdHash,
                flags,
                signCount,
            },
            clientDataJSON: new Uint8Array(assertionResponse.clientDataJSON),
            signature: new Uint8Array(assertionResponse.signature),
            userHandle: assertionResponse.userHandle,
        },
        type: assertion.type,
        signatureBase,
    };
    return response;
}
exports.getCredentialAssertionData = getCredentialAssertionData;
function COSEtoASN1PublicKey(x, y) {
    let response = new Uint8Array([...[0x04, ...x, ...y]]);
    return response;
}
exports.COSEtoASN1PublicKey = COSEtoASN1PublicKey;
function verifyECP256Signature(signature, signatureBase, ASN1PublicKey) {
    let response = false;
    let message = new Uint8Array(js_sha256_1.sha256.array(signatureBase));
    const EC = require('elliptic').ec;
    const curve = new EC('p256');
    const key = curve.keyFromPublic(ASN1PublicKey);
    response = key.verify(message, signature);
    return response;
}
exports.verifyECP256Signature = verifyECP256Signature;
function ASN1ECP256PublicKeyByteArrayToPEMString(pkBuffer) {
    let type = 'PUBLIC KEY';
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        pkBuffer = new Uint8Array([
            ...hexStringToByteArray('3059301306072a8648ce3d020106082a8648ce3d030107034200'),
            ...pkBuffer,
        ]);
    }
    let b64content = byteArrayToBase64(pkBuffer);
    let PEMKey = '';
    for (let i = 0; i < Math.ceil(b64content.length / 64); i++) {
        let start = 64 * i;
        PEMKey += b64content.substring(start, start + 64) + '\n';
    }
    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;
    return PEMKey;
}
exports.ASN1ECP256PublicKeyByteArrayToPEMString = ASN1ECP256PublicKeyByteArrayToPEMString;
function stringToByteArray(str) {
    return Uint8Array.from(str, (c) => c.charCodeAt(0));
}
exports.stringToByteArray = stringToByteArray;
function byteArrayToHexString(uint8array, space = true) {
    if (uint8array.length) {
        return Array.prototype.map
            .call(uint8array, function (byte) {
            return ('0' + (byte & 0xff).toString(16)).slice(-2);
        })
            .join(space ? ' ' : '');
    }
    return '';
}
exports.byteArrayToHexString = byteArrayToHexString;
function hexStringToByteArray(hexString) {
    let uint8array = [];
    for (let i = 0; i < hexString.length; i += 2) {
        uint8array.push(parseInt(hexString.substring(i, i + 2), 16));
    }
    return new Uint8Array(uint8array);
}
exports.hexStringToByteArray = hexStringToByteArray;
function byteArrayToString(uint8array) {
    let decoder = null;
    if (globalThis.TextDecoder) {
        decoder = new globalThis.TextDecoder();
    }
    else {
        let TextDecoder = require('util').TextDecoder;
        decoder = new TextDecoder();
    }
    if (uint8array.length) {
        return decoder.decode(uint8array);
    }
    return '';
}
exports.byteArrayToString = byteArrayToString;
function byteArrayToBase64(uint8array) {
    let response = '';
    if (uint8array) {
        response = byteBase64.bytesToBase64(uint8array);
    }
    return response;
}
exports.byteArrayToBase64 = byteArrayToBase64;
function stringToBase64(str) {
    let encoder = null;
    if (globalThis.TextEncoder) {
        encoder = new globalThis.TextEncoder();
    }
    else {
        let TextEncoder = require('util').TextEncoder;
        encoder = new TextEncoder();
    }
    return byteBase64.base64encode(str, encoder);
}
exports.stringToBase64 = stringToBase64;
function byteArrayRange(uint8array, start, length) {
    if (uint8array.length) {
        if (length > 0) {
            return uint8array.slice(start, start + length);
        }
        else {
            return uint8array.slice(start);
        }
    }
    return new Uint8Array();
}
exports.byteArrayRange = byteArrayRange;
function byteArrayToUint16BigEndian(uint8array) {
    if (uint8array.length) {
        const dataView = new DataView(new ArrayBuffer(uint8array.length));
        uint8array.forEach((value, index) => dataView.setUint8(index, value));
        return dataView.getUint16(0);
    }
    else {
        return 0;
    }
}
exports.byteArrayToUint16BigEndian = byteArrayToUint16BigEndian;
function byteArrayToUint32BigEndian(uint8array) {
    if (uint8array.length) {
        const dataView = new DataView(new ArrayBuffer(uint8array.length));
        uint8array.forEach((value, index) => dataView.setUint8(index, value));
        return dataView.getUint32(0);
    }
    return 0;
}
exports.byteArrayToUint32BigEndian = byteArrayToUint32BigEndian;
function byteArrayToBinaryString(uint8array) {
    let output = '';
    for (let i in uint8array) {
        output = output + uint8array[i].toString(2).padStart(8, '0');
    }
    return output;
}
exports.byteArrayToBinaryString = byteArrayToBinaryString;
function stringSHA256(message) {
    return (0, js_sha256_1.sha256)(message || '');
}
exports.stringSHA256 = stringSHA256;
function stringToHexString(str) {
    return byteArrayToHexString(Uint8Array.from(str, (c) => c.charCodeAt(0)));
}
exports.stringToHexString = stringToHexString;
function base64ToByteArray(base64) {
    let response = new Uint8Array();
    if (base64) {
        response = byteBase64.base64ToBytes(base64);
    }
    return response;
}
exports.base64ToByteArray = base64ToByteArray;
function base64ToString(base64) {
    return byteArrayToString(base64ToByteArray(base64));
}
exports.base64ToString = base64ToString;
function base64ToHexString(base64) {
    return byteArrayToHexString(base64ToByteArray(base64));
}
exports.base64ToHexString = base64ToHexString;
//# sourceMappingURL=index.js.map