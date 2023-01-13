/**
 *
 * Desarrollado con ayuda de:
 * https://itnext.io/step-by-step-building-and-publishing-an-npm-typescript-package-44fe7164964c
 * https://www.valentinog.com/blog/jest-coverage/
 */

import { sha256 } from 'js-sha256';
import * as byteBase64 from "byte-base64";

type publicKeyCredentialCreationOptions = {
  challenge: Uint8Array;
  rp: {
    name: string;
    id: string;
  },
  user: {
    id: Uint8Array,
    name: string,
    displayName: string
  },
  pubKeyCredParams: [{ alg: -7, type: "public-key" }],
  authenticatorSelection: {
    authenticatorAttachment: "cross-platform",
    userVerification: "required",
    requireResidentKey: boolean
  }
  timeout: number,
  attestation: "direct",
  attestatinFormats: ["packed"]
}


function isPublicKeyCredentialSupported(): boolean {
  let response = false;
  if (window) {
    if (window.PublicKeyCredential) {
      response = true;
    }
  }
  return response;
}

async function createPublicKeyCredential(options: publicKeyCredentialCreationOptions): Promise<globalThis.Credential> {
  let credential = navigator.credentials.create({ publicKey: options })
  return credential
}

function stringToByteArray(str:string):Uint8Array {
  return Uint8Array.from(str, c => c.charCodeAt(0))
}

function byteArrayToHexString(uint8array:Uint8Array, space:boolean = true) {
  if (uint8array) {
      return Array.prototype.map.call(uint8array, function (byte) {
          return ('0' + (byte & 0xFF).toString(16)).slice(-2);
      }).join((space ? ' ' : ''));
  }
  return ''
}

function hexStringToByteArray(hexString:string):Uint8Array {
  var uint8array = [];
  for (var i = 0; i < hexString.length; i += 2) {
      uint8array.push(parseInt(hexString.substr(i, 2), 16));
  }
  return new Uint8Array(uint8array);
}

function byteArrayToString(uint8array:Uint8Array) {
  if (typeof uint8array == 'object' && uint8array.length) {
      return new TextDecoder().decode(uint8array);
  }
  return ""
}

function byteArrayToBase64(uint8array:Uint8Array):string {
  if (uint8array) {
      return byteBase64.bytesToBase64(uint8array)
  }
}

function stringToBase64(str:string):string {
  return byteBase64.base64encode(str)
}

function byteArrayRange(uint8array:Uint8Array, start:number, length:number) {
  if (typeof uint8array == 'object' && uint8array.length) {
      if (length > 0) {
          return uint8array.slice(start, start + length)
      } else {
          return uint8array.slice(start)
      }
  }
  return new Uint8Array()
}

function byteArrayToUint32BigEndian(uint8array:Uint8Array):number {
  if (uint8array.length) {
      const dataView = new DataView(new ArrayBuffer(uint8array.length));
      uint8array.forEach((value, index) => dataView.setUint8(index, value));
      return dataView.getUint32(0)
  }
  return 0
}

function byteArrayToUint16(uint8array:Uint8Array):number {
  if (uint8array.length) {
      const dataView = new DataView(new ArrayBuffer(uint8array.length));
      uint8array.forEach((value, index) => dataView.setUint8(index, value));
      return dataView.getUint16();
  }
}

function byteArrayToBinaryString(uint8array:Uint8Array):string {
  let output=""
  for(var i in uint8array){
      output = output + uint8array[i].toString(2).padStart(8,"0")
  }
  return output
}



function stringSHA256(message:string):string {
  if(message.length){
      return sha256(message)
  }
  return ''
}




function stringToHexString(str:string):string {
  return byteArrayToHexString(Uint8Array.from(str, c => c.charCodeAt(0)))
}




export { isPublicKeyCredentialSupported, createPublicKeyCredential, publicKeyCredentialCreationOptions  };
