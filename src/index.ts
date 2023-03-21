/**
 *
 * @module @esimios/webauthn
 *
 * Desarrollado con ayuda de:
 * https://itnext.io/step-by-step-building-and-publishing-an-npm-typescript-package-44fe7164964c
 * https://www.valentinog.com/blog/jest-coverage/
 * https://www.w3.org/TR/webauthn/#attestation-statement-format
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 *
 * @author: @tirsomartinezreyes
 */

import { sha256 } from 'js-sha256';
import * as byteBase64 from 'byte-base64';
import * as CBOR from 'cbor-redux';

export type CredentialRegistrationData = {
  id: string;
  rawId: Uint8Array;
  clienDataJSON: Uint8Array;
  attestationObject: {
    fmt: 'packed'; //Valid values  packed || fido-u2f || none || android-safetynet || android-key || tpm || apple
    attStmt: {
      alg: number; //COSEAlgorithmIdentifier
      sig: Uint8Array; //Signature
      x5c: Uint8Array[]; //0 -> Certificate 1 -> CA Certificate (opcional)
    };
    authData: {
      rpIdHash: Uint8Array;
      flags: Uint8Array;
      signCount: Uint8Array;
      aaguid: Uint8Array;
      credentialIdLength: Uint8Array;
      credentialId: Uint8Array;
      credentialPublicKey: Uint8Array; //CBOR Encoded
      publicKey: {
        //COSE format (decoded from CBOR)
        '1': 2; // Type: EC
        '3': -7; //Alghoritm: ES256
        '-1': 1; // Curve: P-256
        '-2': Uint8Array; // X-coordinate
        '-3': Uint8Array; // Y-coordinate
      };
    };
  };
  type: 'public-key';
};

export type CredentialAssertionData = {
  authenticatorAttachment: 'cross-platform';
  id: string;
  rawId: Uint8Array;
  response: {
    authenticatorData: {
      rpIdHash: Uint8Array;
      flags: Uint8Array;
      signCount: Uint8Array;
    };
    clientDataJSON: Uint8Array;
    signature: Uint8Array;
    userHandle: Uint8Array | null;
  };
  type: 'public-key';
  signatureBase: Uint8Array;
};

/* istanbul ignore next */
export function isPublicKeyCredentialSupported(): boolean {
  let response = false;
  if (window) {
    if (window.PublicKeyCredential) {
      response = true;
    }
  }
  return response;
}

/**
 *
 * @async
 * @param options : publicKeyCredentialCreationOptions
 * @returns Credential
 */
/* istanbul ignore next */
export async function createPublicKeyCredential(options: PublicKeyCredentialCreationOptions): Promise<Credential> {
  let credential = navigator.credentials.create({ publicKey: options });
  return credential;
}

/**
 *
 * @async
 * @param options: PulicKeyCredentialRequestOptions
 * @returns Credential
 */
/* istanbul ignore next */
export async function getAttestation(options: PublicKeyCredentialRequestOptions): Promise<globalThis.Credential> {
  let credential = navigator.credentials.get({ publicKey: options });
  return credential;
}

/**
 *
 * @param credential : PublicKeyCredential
 * @returns CredentialRegistrationData
 */
export function getCredentialRegistrationData(credential: PublicKeyCredential): CredentialRegistrationData {
  let credentialResponse = credential.response as AuthenticatorAttestationResponse;
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
  } as CredentialRegistrationData;
  return response;
}

/**
 *
 * @param assertion
 * @returns
 */
export function getCredentialAssertionData(assertion: PublicKeyCredential): CredentialAssertionData {
  let assertionResponse = assertion.response as AuthenticatorAssertionResponse;
  let assertionResponseAuthenticatorDataUint8Array = new Uint8Array(assertionResponse.authenticatorData);
  let rpIdHash = byteArrayRange(assertionResponseAuthenticatorDataUint8Array, 0, 32);
  let flags = byteArrayRange(assertionResponseAuthenticatorDataUint8Array, 32, 1);
  let signCount = byteArrayRange(assertionResponseAuthenticatorDataUint8Array, 33, 4);
  let clientDataHash = new Uint8Array(sha256.array(assertionResponse.clientDataJSON));
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
  } as CredentialAssertionData;
  return response;
}

/**
 *
 * @param x :Uint8Array
 * @param y :Uint8Array
 * @returns ASN1 public key
 */
export function COSEtoASN1PublicKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  let response = new Uint8Array([...[0x04, ...x, ...y]]);
  return response;
}

/**
 *
 * @param signature : Uint8Array
 * @param signatureBase : Uint8Array
 * @param ASN1PublicKey : Uint8Array
 * @returns boolean
 */
export function verifyECP256Signature(
  signature: Uint8Array,
  signatureBase: Uint8Array,
  ASN1PublicKey: Uint8Array,
): boolean {
  let response = false;
  let message = new Uint8Array(sha256.array(signatureBase));
  const EC = require('elliptic').ec;
  const curve = new EC('p256');
  const key = curve.keyFromPublic(ASN1PublicKey);
  response = key.verify(message, signature);
  return response;
}

/**
 *
 * @param pkBuffer :uint8Array
 * @returns string
 */
export function ASN1ECP256PublicKeyByteArrayToPEMString(pkBuffer: Uint8Array): string {
  let type = 'PUBLIC KEY';
  if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
    /*
		Se agrega cabezera de public key a raw public key
			SEQUENCE {
              SEQUENCE {
                OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256|prime256v1)
              }
              BITSTRING <raw public key>
            }
		*/
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

//=======Funciones de utilidad para transformar datos entre string, Uint8Array, hexString y base64 ======
//	stringTo - ByteArray, HexString, Base64
//	byteArrayTo - String, HexString, Base64, Uint16BigEndian, Uint32BigEndian, BinaryString
//	hexStringTo -  ByteArray
//	byteArrayRange
//	stringSHA256
//	base64To - ByteArray, HexString, String

/**
 *
 * @param str :string
 * @returns Uint8Array
 * @example stringToByteArray('Hello World') // Uint8Array(11) [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
 */
export function stringToByteArray(str: string): Uint8Array {
  return Uint8Array.from(str, (c) => c.charCodeAt(0));
}

/**
 *
 * @param uint8array: Uint8Array
 * @param space :boolean
 * @returns strin
 * @example	byteArrayToHexString(Uint8Array.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64])) // 48 65 6c 6c 6f 20 57 6f 72 6c 64
 */
export function byteArrayToHexString(uint8array: Uint8Array, space: boolean = true): string {
  if (uint8array.length) {
    return Array.prototype.map
      .call(uint8array, function (byte) {
        return ('0' + (byte & 0xff).toString(16)).slice(-2);
      })
      .join(space ? ' ' : '');
  }
  return '';
}

/**
 *
 * @param hexString :string
 * @returns Uint8Array
 * @example hexStringToByteArray('48656c6c6f20576f726c64') // Uint8Array(11) [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
 */
export function hexStringToByteArray(hexString: string): Uint8Array {
  let uint8array = [];
  for (let i = 0; i < hexString.length; i += 2) {
    uint8array.push(parseInt(hexString.substring(i, i + 2), 16));
  }
  return new Uint8Array(uint8array);
}

/**
 *
 * @param uint8array
 * @returns string
 * @example byteArrayToString(Uint8Array.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64])) // Hello World
 */
export function byteArrayToString(uint8array: Uint8Array): string {
  let decoder = null;
  if (globalThis.TextDecoder) {
    //browser
    decoder = new globalThis.TextDecoder();
  } else {
    //NodeJS
    let TextDecoder = require('util').TextDecoder;
    decoder = new TextDecoder();
  }

  if (uint8array.length) {
    return decoder.decode(uint8array);
  }
  return '';
}

/**
 *
 * @param uint8array : Uint8Array
 * @returns string
 * @example byteArrayToBase64(Uint8Array.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09])) // AAECAwQFBgcICQ==
 */
export function byteArrayToBase64(uint8array: Uint8Array): string {
  let response = '';
  if (uint8array) {
    response = byteBase64.bytesToBase64(uint8array);
  }
  return response;
}

/**
 *
 * @param str:string
 * @returns string
 * @example stringToBase64('Hello World') // SGVsbG8gV29ybGQ=
 * @example stringToBase64('Hello World!') // SGVsbG8gV29ybGQh
 * @example stringToBase64('Hello World!!') // SGVsbG8gV29ybGQhIQ==
 */
export function stringToBase64(str: string): string {
  let encoder = null;
  if (globalThis.TextEncoder) {
    //browser
    encoder = new globalThis.TextEncoder();
  } else {
    //NodeJS
    let TextEncoder = require('util').TextEncoder;
    encoder = new TextEncoder();
  }
  return byteBase64.base64encode(str, encoder);
}

/**
 *
 * @param uint8array:Uint8Array
 * @param start:number
 * @param length:number
 * @returns Uint8Array
 * @example byteArrayRange(Uint8Array.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]), 0, 5) // Uint8Array(5) [0, 1, 2, 3, 4]
 * @example byteArrayRange(Uint8Array.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]), 5, 5) // Uint8Array(5) [5, 6, 7, 8, 9]
 * @example byteArrayRange(Uint8Array.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]), 5) // Uint8Array(5) [5, 6, 7, 8, 9]
 */
export function byteArrayRange(uint8array: Uint8Array, start: number, length?: number): Uint8Array {
  if (uint8array.length) {
    if (length > 0) {
      return uint8array.slice(start, start + length);
    } else {
      return uint8array.slice(start);
    }
  }
  return new Uint8Array();
}

/**
 *
 * @param uint8array : Uint8Array
 * @returns number
 * @example byteArrayToUint16BigEndian(Uint8Array.from([0x00, 0x00])) // 0
 * @example byteArrayToUint16BigEndian(Uint8Array.from([0x00, 0x01])) // 1
 * @example byteArrayToUint16BigEndian(Uint8Array.from([0x01, 0x00])) // 256
 * @example byteArrayToUint16BigEndian(Uint8Array.from([0xFF, 0xFF])) // 65535
 */
export function byteArrayToUint16BigEndian(uint8array: Uint8Array): number {
  if (uint8array.length) {
    const dataView = new DataView(new ArrayBuffer(uint8array.length));
    uint8array.forEach((value, index) => dataView.setUint8(index, value));
    return dataView.getUint16(0);
  } else {
    return 0;
  }
}

/**
 *
 * @param uint8array:Uint8Array
 * @returns number
 * @example byteArrayToUint32BigEndian(Uint8Array.from([0x00, 0x00, 0x00, 0x00])) // 0
 * @example byteArrayToUint32BigEndian(Uint8Array.from([0x00, 0x00, 0x00, 0x01])) // 1
 * @example byteArrayToUint32BigEndian(Uint8Array.from([0x00, 0x00, 0x01, 0x00])) // 256
 * @example byteArrayToUint32BigEndian(Uint8Array.from([0x00, 0x01, 0x00, 0x00])) // 65536
 * @example byteArrayToUint32BigEndian(Uint8Array.from([0xFF, 0xFF, 0xFF, 0xFF])) // 4294967295
 */
export function byteArrayToUint32BigEndian(uint8array: Uint8Array): number {
  if (uint8array.length) {
    const dataView = new DataView(new ArrayBuffer(uint8array.length));
    uint8array.forEach((value, index) => dataView.setUint8(index, value));
    return dataView.getUint32(0);
  }
  return 0;
}

/**
 *
 * @param uint8array:Uint8Array
 * @returns string
 * @example byteArrayToBinaryString(Uint8Array.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64])) // "0100100001100101011011000110110001101111001000000101011101101111011100100110110001100100"
 */
export function byteArrayToBinaryString(uint8array: Uint8Array): string {
  let output = '';
  for (let i in uint8array) {
    output = output + uint8array[i].toString(2).padStart(8, '0');
  }
  return output;
}

/**
 *
 * @param message:string|Uint8Array
 * @returns string
 * @example stringSHA256("Hello World") // "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
 * @example stringSHA256(Uint8Array.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64])) // "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
 * @example stringSHA256(Uint8Array.from([72,101,108,108,111,32,87,111,114,108,100])) // "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
 */
export function stringSHA256(message: string | Uint8Array): string {
  return sha256(message || '');
}

/**
 *
 * @param str:string
 * @returns string
 * @example stringToHexString("Hello World") // "48 65 6c 6c 6f 20 57 6f 72 6c 64"
 */
export function stringToHexString(str: string): string {
  return byteArrayToHexString(Uint8Array.from(str, (c) => c.charCodeAt(0)));
}

/**
 *
 * @param base64: string
 * @returns Uint8Array
 * @example base64TobyteArray('AAECAwQFBgcICQ==') //[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
 */
export function base64ToByteArray(base64: string): Uint8Array {
  let response = new Uint8Array();
  if (base64) {
    response = byteBase64.base64ToBytes(base64);
  }
  return response;
}

/**
 *
 * @param base64:string
 * @returns string
 * @example base64ToString('SGVsbG8gV29ybGQ=') //'Hello World'
 * @example base64ToString('SGVsbG8gV29ybGQh') //'Hello World!'
 * @example base64ToString('SGVsbG8gV29ybGQhIQ==') //'Hello World!!'
 */
export function base64ToString(base64: string): string {
  return byteArrayToString(base64ToByteArray(base64));
}

/**
 * @param base64:string
 * @returns string
 * @example base64ToHexString('SGVsbG8gV29ybGQ=') //'48656c6c6f20576f726c64'
 * @example base64ToHexString('SGVsbG8gV29ybGQh') //'48656c6c6f20576f726c6421'
 * @example base64ToHexString('SGVsbG8gV29ybGQhIQ==') //'48656c6c6f20576f726c642121'
 *
 */
export function base64ToHexString(base64: string): string {
  return byteArrayToHexString(base64ToByteArray(base64));
}
