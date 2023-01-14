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
  ASN1ECP256PublicKeyByteArrayToPEMString,
  getCredentialRegistrationData,
  CredentialRegistrationData} from '../src/index';

import {createOptions,createdCredential, requestOptions, assertion } from "../__mocks__/publicKeyCredential"

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

test('byteArrayRange with Uint8Array from Hex from 5 all remaint elements', () => {
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
  .toBe(`-----BEGIN CERTIFICATE-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwwhm8hVcPYuJDHpgkTVyCI45A6Dk
8qX0G3AHI0m8j8pI5ORkuQR5hTRC7BZdwbCy3rl/lfsF0JCk7sNfYDpoTA==
-----END CERTIFICATE-----
`)
})




//PublicKeyCredential
let credentialRegistrationData = getCredentialRegistrationData(createdCredential)
console.log(credentialRegistrationData)

