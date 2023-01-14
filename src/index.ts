/**
 *
 * Desarrollado con ayuda de:
 * https://itnext.io/step-by-step-building-and-publishing-an-npm-typescript-package-44fe7164964c
 * https://www.valentinog.com/blog/jest-coverage/
 */

import { sha256 } from 'js-sha256';
import * as byteBase64 from 'byte-base64';
import * as CBOR from 'cbor-redux';


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
 * @param options : publicKeyCredentialCreationOptions
 * @returns Credential
 */
/* istanbul ignore next */
export async function createPublicKeyCredential(
  options: PublicKeyCredentialCreationOptions,
): Promise<Credential> {
  let credential = navigator.credentials.create({ publicKey: options });
  return credential;
}

/**
 * 
 * @param options: PulicKeyCredentialRequestOptions
 * @returns Credential
 */
/* istanbul ignore next */
export async function getAttestation( options: PublicKeyCredentialRequestOptions): Promise<globalThis.Credential> {
	let credential = navigator.credentials.get({ publicKey: options });
	return credential;
}



export type CredentialRegistrationData = {
	id:string,
	rawId:Uint8Array,
	clienDataJSON: string,
	attestationObject: any,
	type:string
}

export function getCredentialRegistrationData(credential:PublicKeyCredential):CredentialRegistrationData{
	let credentialResponse  = credential.response as AuthenticatorAttestationResponse;
	const decodedAttestationObj = CBOR.decode(credentialResponse.attestationObject);
	
	let credentialIdLength = byteArrayToUint16BigEndian(byteArrayRange(decodedAttestationObj.authData, 53, 2))
	let credentialId = byteArrayRange(decodedAttestationObj.authData,55, credentialIdLength)
	let credentialPublicKey = byteArrayRange(decodedAttestationObj.authData,55+credentialIdLength)

	let response = {
		id:credential.id,
		rawId:credential.rawId,
		clienDataJSON: byteArrayToString(new Uint8Array(credentialResponse.clientDataJSON)),
		attestationObject: {
			fmt: decodedAttestationObj.fmt,
			attStmt:{
				alg: decodedAttestationObj.attStmt.alg,
				sig: decodedAttestationObj.attStmt.sig,
				x5c:decodedAttestationObj.attStmt.x5c,	
			},
			authData:{
				rpIdHash: byteArrayRange(decodedAttestationObj.authData, 0, 32),
				flags: decodedAttestationObj.authData[32],
				signCount: byteArrayRange(decodedAttestationObj.authData, 33, 4),
				aaguid: byteArrayRange(decodedAttestationObj.authData, 37, 16),
				credentialIdLength:byteArrayRange(decodedAttestationObj.authData, 53, 2),
				credentialId:credentialId,
				credentialPublicKey:credentialPublicKey,
				publicKey:CBOR.decode(credentialPublicKey.buffer)
			}
		},
		type:credential.type
	} as CredentialRegistrationData
	return response;
}




/**
 * 
 * @param pkBuffer :uint8Array
 * @returns string
 * @example 
 */
export function ASN1ECP256PublicKeyByteArrayToPEMString(pkBuffer: Uint8Array): string {
  let type;
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
    type = 'PUBLIC KEY';
  } else {
    type = 'CERTIFICATE';
  }
  let b64cert = byteArrayToBase64(pkBuffer);
  let PEMKey = '';
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
    let start = 64 * i;
    PEMKey += b64cert.substring(start, start+64) + '\n';
  }

  PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;
  return PEMKey;
}

//Funciones de utilidad para transformar datos entre string, Uint8Array, hexString y base64
//	stringTo - ByteArray, HexString, Base64
//	byteArrayTo - String, HexString, Base64, Uint16BigEndian, Uint32BigEndian, BinaryString
//	hexStringTo -  ByteArray
//	byteArrayRange
//	stringSHA256

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
  var uint8array = [];
  for (var i = 0; i < hexString.length; i += 2) {
    uint8array.push(parseInt(hexString.substring(i, i+2), 16));
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
  for (var i in uint8array) {
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
