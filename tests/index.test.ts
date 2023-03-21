import { 
  isPublicKeyCredentialSupported,
  byteArrayToBinaryString, 
  byteArrayToUint16BigEndian,
  byteArrayToUint32BigEndian,
  byteArrayToBase64,
  byteArrayToString,
  byteArrayToHexString,
  byteArrayRange,
  stringToBase64,
  stringToHexString,
  stringToByteArray,
  hexStringToByteArray,
  stringSHA256,
  base64ToByteArray,
  base64ToString,
  base64ToHexString,
  ASN1ECP256PublicKeyByteArrayToPEMString,
  getCredentialRegistrationData,
  CredentialRegistrationData,
  getCredentialAssertionData,
  CredentialAssertionData,
  verifyECP256Signature,
  COSEtoASN1PublicKey
} from '../src/index';

import {createOptions,createdCredential, requestOptions, assertion } from "../__mocks__/publicKeyCredential"
import { number, string } from 'yargs';

//isPublicKeyCredentialSupported
test('isPublicKeyCredentialSupported', () => {
  expect(isPublicKeyCredentialSupported()).toBe(false)
})


//byteArrayToBinaryString
test('byteArrayToBinaryString with Uint8Array from Hex', () => {
  expect(byteArrayToBinaryString(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64]))).toBe("0100100001100101011011000110110001101111001000000101011101101111011100100110110001100100")
})

test('byteArrayToBinaryString with Uint8Array', () => {
  expect(byteArrayToBinaryString(new Uint8Array([72,101,108,108,111,32,87,111,114,108,100]))).toBe("0100100001100101011011000110110001101111001000000101011101101111011100100110110001100100")
})



//byteArrayToBase64
test('byteArrayToBase64', () => {
  expect(byteArrayToBase64(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]))).toBe("AAECAwQFBgcICQ==")
})

test('byteArrayToBase64: Hello World', () => {
  expect(byteArrayToBase64(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64]))).toBe("SGVsbG8gV29ybGQ=")
})



//byteArrayToString
test('byteArrayToString: Hello World', () => {
  expect(byteArrayToString(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64]))).toBe("Hello World")
})

test('byteArrayToString: <empty>', () => {
  expect(byteArrayToString(new Uint8Array([]))).toBe("")
})




//byteArrayToUint16BigEndian
test('byteArrayToUint16BigEndian with Uint8Array from Hex -> 0', () => {
  expect(byteArrayToUint16BigEndian(new Uint8Array([0x00, 0x00]))).toBe(0)
})

test('byteArrayToUint16BigEndian with Uint8Array -> 1', () => {
  expect(byteArrayToUint16BigEndian(new Uint8Array([0x00, 0x01]))).toBe(1)
})

test('byteArrayToUint16BigEndian with Uint8Array -> 1', () => {
  expect(byteArrayToUint16BigEndian(new Uint8Array([0xFF, 0xFF]))).toBe(65535)
})

test('byteArrayToUint16BigEndian with Uint8Array <empty>', () => {
  expect(byteArrayToUint16BigEndian(new Uint8Array([]))).toBe(0)
})




//byteArrayToUint32BigEndian
test('byteArrayToUint32BigEndian with Uint8Array from Hex -> 0', () => {
  expect(byteArrayToUint32BigEndian(new Uint8Array([0x00, 0x00, 0x00, 0x00]))).toBe(0)
})

test('byteArrayToUint32BigEndian with Uint8Array -> 1', () => {
  expect(byteArrayToUint32BigEndian(new Uint8Array([0x00, 0x00, 0x00, 0x01]))).toBe(1)
})

test('byteArrayToUint32BigEndian with Uint8Array -> 1', () => {
  expect(byteArrayToUint32BigEndian(new Uint8Array([0x00, 0x00, 0xFF, 0xFF]))).toBe(65535)
})

test('byteArrayToUint32BigEndian with Uint8Array from Hex -> 65536', () => {
  expect(byteArrayToUint32BigEndian(new Uint8Array([0x00, 0x01, 0x00, 0x00]))).toBe(65536)
})

test('byteArrayToUint32BigEndian with Uint8Array from Hex -> 4294967295', () => {
  expect(byteArrayToUint32BigEndian(new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]))).toBe(4294967295)
})

test('byteArrayToUint32BigEndian with Uint8Array <empty>', () => {
  expect(byteArrayToUint32BigEndian(new Uint8Array([]))).toBe(0)
})



//byteArrayRange
test('byteArrayRange with Uint8Array from Hex from 0 , 5 elements', () => {
  expect(byteArrayRange(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]), 0, 5)).toStrictEqual(new Uint8Array([0,1,2,3,4]))
})

test('byteArrayRange with Uint8Array from Hex from 1, 3 elements ', () => {
  expect(byteArrayRange(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]), 1, 3)).toStrictEqual(new Uint8Array([1,2,3]))
})

test('byteArrayRange with Uint8Array from Hex from 2, 5 elements', () => {
  expect(byteArrayRange(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]), 2, 5)).toStrictEqual(new Uint8Array([2,3,4,5,6]))
})

test('byteArrayRange with Uint8Array from Hex from 5 all remain elements', () => {
  expect(byteArrayRange(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]),5)).toStrictEqual(new Uint8Array([5,6,7,8,9]))
})

test('byteArrayRange with Uint8Array <empty>', () => {
  expect(byteArrayRange(new Uint8Array([]),5)).toStrictEqual(new Uint8Array([]))
})



//byteArrayToHexString
test('byteArrayToHexString', () => {
  expect(byteArrayToHexString(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64]))).toBe("48 65 6c 6c 6f 20 57 6f 72 6c 64")
})

test('byteArrayToHexString no spaces', () => {
  expect(byteArrayToHexString(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64]),false)).toBe("48656c6c6f20576f726c64")
})

test('byteArrayToHexString<empty>', () => {
  expect(byteArrayToHexString(new Uint8Array([]),false)).toBe("")
})





//stringToBase64
test('stringToBase64 Hello World',()=>{
  expect(stringToBase64("Hello World")).toBe("SGVsbG8gV29ybGQ=")
})

test('stringToBase64 Hello World!',()=>{
  expect(stringToBase64("Hello World!")).toBe("SGVsbG8gV29ybGQh")
})

test('stringToBase64 Hello World!!"',()=>{
  expect(stringToBase64("Hello World!!")).toBe("SGVsbG8gV29ybGQhIQ==")
})



//stringToHexString
test('stringToHexString',()=>{
  expect(stringToHexString("Hello World")).toBe("48 65 6c 6c 6f 20 57 6f 72 6c 64")
})



//stringSHA256
test('stringSHA256 with string',()=>{
  expect(stringSHA256("Hello World")).toBe("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e")
})

test('stringSHA256 with Uint8Array from Hex',()=>{
  expect(stringSHA256(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64]))).toBe("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e")
})

test('stringSHA256 with Uint8Array',()=>{
  expect(stringSHA256(new Uint8Array([72,101,108,108,111,32,87,111,114,108,100]))).toBe("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e")
})

test('stringSHA256 with <empty Uint8Array>',()=>{
  expect(stringSHA256(new Uint8Array([]))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
})

test('stringSHA256 with <empty string>',()=>{
  expect(stringSHA256('')).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
})


//stringToByteArray
test('stringToByteArray with Hello World',()=>{
  expect(stringToByteArray("Hello World")).toStrictEqual(new Uint8Array([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]))
})




//hexStringToByteArray
test('hexStringToByteArray with string',()=>{
  expect(hexStringToByteArray("48656c6c6f20576f726c64")).toStrictEqual(new Uint8Array([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]))
})


//ASN1ECP256PublicKeyByteArrayToPEMString
//https://developers.yubico.com/PIV/Guides/Generating_keys_using_OpenSSL.html

test('ASN1ECP256PublicKeyByteArrayToPEMString ',()=>{
  expect(ASN1ECP256PublicKeyByteArrayToPEMString(hexStringToByteArray("3059301306072a8648ce3d020106082a8648ce3d03010703420004c30866f2155c3d8b890c7a60913572088e3903a0e4f2a5f41b70072349bc8fca48e4e464b90479853442ec165dc1b0b2deb97f95fb05d090a4eec35f603a684c")))
  .toBe(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwwhm8hVcPYuJDHpgkTVyCI45A6Dk
8qX0G3AHI0m8j8pI5ORkuQR5hTRC7BZdwbCy3rl/lfsF0JCk7sNfYDpoTA==
-----END PUBLIC KEY-----
`)
expect(ASN1ECP256PublicKeyByteArrayToPEMString(new Uint8Array([...[0x04,],...[2,1,144,47,16,24,147,220,231,124,38,238,214,140,205,57,11,51,200,183,6,63,124,229,69,127,177,153,168,107,206,231],...[83,135,6,163,48,165,242,230,144,180,55,212,47,154,149,54,255,81,249,54,127,199,101,47,94,202,33,253,248,77,205,239]])))
.toBe(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAgGQLxAYk9znfCbu1ozNOQszyLcG
P3zlRX+xmahrzudThwajMKXy5pC0N9QvmpU2/1H5Nn/HZS9eyiH9+E3N7w==
-----END PUBLIC KEY-----
`)

})

//base64ToByteArray
test('base64ToByteArray',()=>{
  expect(base64ToByteArray("AAECAwQFBgcICQ=="))
  .toStrictEqual(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]))

  expect(base64ToByteArray("SGVsbG8gV29ybGQ="))
  .toStrictEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64]))
})


//base64ToString
test('base64ToString',()=>{
  expect(base64ToString("SGVsbG8gV29ybGQ=")).toBe("Hello World")
  expect(base64ToString("SGVsbG8gV29ybGQh")).toBe("Hello World!")
  expect(base64ToString("SGVsbG8gV29ybGQhIQ==")).toBe("Hello World!!")
})

//base64ToHexString
test('base64ToHexString',()=>{
  expect(base64ToHexString("SGVsbG8gV29ybGQ=")).toBe("48656c6c6f20576f726c64")
  expect(base64ToHexString("SGVsbG8gV29ybGQh")).toBe("48656c6c6f20576f726c6421")
  expect(base64ToHexString("SGVsbG8gV29ybGQhIQ==")).toBe("48656c6c6f20576f726c642121")
})


//getCredentialRegistrationData
let credentialRegistrationData:CredentialRegistrationData = getCredentialRegistrationData(createdCredential)
test('getCredentialRegistrationData',()=>{
  expect(credentialRegistrationData.type).toBe('public-key')
  expect(typeof credentialRegistrationData.id).toBe('string')
  expect(credentialRegistrationData.rawId).toBeInstanceOf(Uint8Array)
  expect(credentialRegistrationData.clienDataJSON).toBeInstanceOf(Uint8Array)
  expect(credentialRegistrationData.attestationObject.fmt).toBe("packed")
  expect(credentialRegistrationData.attestationObject.attStmt).toBeInstanceOf(Object)
  expect(credentialRegistrationData.attestationObject.authData).toBeInstanceOf(Object)
  expect(credentialRegistrationData.attestationObject.authData.rpIdHash).toBeInstanceOf(Uint8Array)
  expect(credentialRegistrationData.attestationObject.authData.flags).toBeInstanceOf(Uint8Array)
  expect(credentialRegistrationData.attestationObject.authData.credentialId).toBeInstanceOf(Uint8Array)
  expect(credentialRegistrationData.attestationObject.authData.credentialPublicKey).toBeInstanceOf(Uint8Array)
  expect(credentialRegistrationData.attestationObject.authData.publicKey).toBeInstanceOf(Object)
  expect(credentialRegistrationData.attestationObject.authData.publicKey["1"]).toBe(2)
  expect(credentialRegistrationData.attestationObject.authData.publicKey["3"]).toBe(-7)
  expect(credentialRegistrationData.attestationObject.authData.publicKey["-1"]).toBe(1)
  expect(credentialRegistrationData.attestationObject.authData.publicKey["-2"]).toBeInstanceOf(Uint8Array)
  expect(credentialRegistrationData.attestationObject.authData.publicKey["-3"]).toBeInstanceOf(Uint8Array)
})

//getCredentialAssertionData
let credentialAssertionData:CredentialAssertionData = getCredentialAssertionData(assertion)
test('getCredentialAssertionData',()=>{
  expect(credentialAssertionData.authenticatorAttachment).toBe('cross-platform')
  expect(credentialAssertionData.type).toBe('public-key')
  expect(typeof credentialAssertionData.id).toBe('string')
  expect(credentialAssertionData.rawId).toBeInstanceOf(Uint8Array)
  expect(credentialAssertionData.signatureBase).toBeInstanceOf(Uint8Array)
  expect(credentialAssertionData.response.clientDataJSON).toBeInstanceOf(Uint8Array)
  expect(credentialAssertionData.response.signature).toBeInstanceOf(Uint8Array)
  expect(credentialAssertionData.response.authenticatorData).toBeInstanceOf(Object)
  expect(credentialAssertionData.response.authenticatorData.rpIdHash).toBeInstanceOf(Uint8Array)
  expect(credentialAssertionData.response.authenticatorData.flags).toBeInstanceOf(Uint8Array)
  expect(credentialAssertionData.response.authenticatorData.signCount).toBeInstanceOf(Uint8Array)
})

//COSEtoASN1PublicKey
test('COSEtoASN1PublicKey',()=>{
  expect(COSEtoASN1PublicKey(credentialRegistrationData.attestationObject.authData.publicKey["-2"],credentialRegistrationData.attestationObject.authData.publicKey["-3"])).toStrictEqual(new Uint8Array([...[0x04,],...[2,1,144,47,16,24,147,220,231,124,38,238,214,140,205,57,11,51,200,183,6,63,124,229,69,127,177,153,168,107,206,231],...[83,135,6,163,48,165,242,230,144,180,55,212,47,154,149,54,255,81,249,54,127,199,101,47,94,202,33,253,248,77,205,239]]))
})


//verifyECP256Signature
test('verifyECP256Signature',()=>{
  //CORRECTOS
  let publicKey = COSEtoASN1PublicKey(credentialRegistrationData.attestationObject.authData.publicKey["-2"],credentialRegistrationData.attestationObject.authData.publicKey["-3"])
  expect(verifyECP256Signature(credentialAssertionData.response.signature, credentialAssertionData.signatureBase, publicKey)).toBe(true)

  //INCORRECTOS
  let invalidPublicKey = new Uint8Array([...publicKey])
  let invalidSignature = new Uint8Array([...credentialAssertionData.response.signature])
  let invalidSignatureBase = new Uint8Array([...credentialAssertionData.signatureBase])
  invalidPublicKey[1] = 0xFF
  invalidSignature[10] = 0xFF
  invalidSignatureBase[1] = 0xFF
  expect(verifyECP256Signature(invalidSignature, invalidSignatureBase, invalidPublicKey)).toBe(false)
  expect(verifyECP256Signature(invalidSignature, invalidSignatureBase, publicKey)).toBe(false)
  expect(verifyECP256Signature(invalidSignature, credentialAssertionData.signatureBase, invalidPublicKey)).toBe(false)
  expect(verifyECP256Signature(invalidSignature, credentialAssertionData.signatureBase, publicKey)).toBe(false)
  expect(verifyECP256Signature(credentialAssertionData.response.signature, invalidSignatureBase, invalidPublicKey)).toBe(false)
  expect(verifyECP256Signature(credentialAssertionData.response.signature, invalidSignatureBase, publicKey)).toBe(false)
  expect(verifyECP256Signature(credentialAssertionData.response.signature, credentialAssertionData.signatureBase, invalidPublicKey)).toBe(false)
})
