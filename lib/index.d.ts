import * as byteBase64 from 'byte-base64';
import * as cbor from 'cbor-redux';
import { BinaryReader, CborSimpleDecoder } from './CborSimpleDecoder';
export type CredentialRegistrationData = {
    id: string;
    rawId: Uint8Array;
    clienDataJSON: Uint8Array;
    attestationObject: {
        fmt: 'packed';
        attStmt: {
            alg: number;
            sig: Uint8Array;
            x5c: Uint8Array[];
        };
        authData: {
            rpIdHash: Uint8Array;
            flags: Uint8Array;
            signCount: Uint8Array;
            aaguid: Uint8Array;
            credentialIdLength: Uint8Array;
            credentialId: Uint8Array;
            credentialPublicKey: Uint8Array;
            publicKey: {
                '1': 2;
                '3': -7;
                '-1': 1;
                '-2': Uint8Array;
                '-3': Uint8Array;
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
export declare function isPublicKeyCredentialSupported(): boolean;
export declare function createPublicKeyCredential(options: PublicKeyCredentialCreationOptions): Promise<Credential>;
export declare function getAssertion(options: PublicKeyCredentialRequestOptions): Promise<globalThis.Credential>;
export declare function getCredentialRegistrationData(credential: PublicKeyCredential): CredentialRegistrationData;
export declare function getCredentialAssertionData(assertion: PublicKeyCredential): CredentialAssertionData;
export declare function COSEtoASN1PublicKey(x: Uint8Array, y: Uint8Array): Uint8Array;
export declare function verifyECP256Signature(signature: Uint8Array, signatureBase: Uint8Array, ASN1PublicKey: Uint8Array): boolean;
export declare function ASN1ECP256PublicKeyByteArrayToPEMString(pkBuffer: Uint8Array): string;
export declare function stringToByteArray(str: string): Uint8Array;
export declare function byteArrayToHexString(uint8array: Uint8Array, space?: boolean): string;
export declare function hexStringToByteArray(hexString: string): Uint8Array;
export declare function byteArrayToString(uint8array: Uint8Array): string;
export declare function byteArrayToBase64(uint8array: Uint8Array): string;
export declare function stringToBase64(str: string): string;
export declare function byteArrayRange(uint8array: Uint8Array, start: number, length?: number): Uint8Array;
export declare function byteArrayToUint16BigEndian(uint8array: Uint8Array): number;
export declare function byteArrayToUint32BigEndian(uint8array: Uint8Array): number;
export declare function byteArrayToBinaryString(uint8array: Uint8Array): string;
export declare function stringSHA256(message: string | Uint8Array): string;
export declare function stringToHexString(str: string): string;
export declare function base64ToByteArray(base64: string): Uint8Array;
export declare function base64ToString(base64: string): string;
export declare function base64ToHexString(base64: string, separator?: boolean): string;
export declare function isBase64Url(base64: string): boolean;
export declare function base64UrlToBase64(base64url: string): string;
export declare function base64ToBase64url(base64: string): string;
export declare const SHA256: import("js-sha256").Hash;
export declare const CBOR: typeof cbor;
export declare const BINARY_READER: typeof BinaryReader;
export declare const CBOR_SIMPLE_DECODER: typeof CborSimpleDecoder;
export declare const BYTE_BASE64: typeof byteBase64;
