export type publicKeyCredentialCreationOptions = {
    challenge: Uint8Array;
    rp: {
        name: string;
        id: string;
    };
    user: {
        id: Uint8Array;
        name: string;
        displayName: string;
    };
    pubKeyCredParams: [{
        alg: -7;
        type: 'public-key';
    }];
    authenticatorSelection: {
        authenticatorAttachment: 'cross-platform';
        userVerification: 'required';
        requireResidentKey: boolean;
    };
    timeout: number;
    attestation: 'direct';
    attestatinFormats: ['packed'];
};
export declare function isPublicKeyCredentialSupported(): boolean;
export declare function createPublicKeyCredential(options: publicKeyCredentialCreationOptions): Promise<globalThis.Credential>;
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
