export class BinaryReader {
    constructor(buffer: any);
    view: DataView;
    offset: number;
    get readerOffset(): number;
    get buffer(): ArrayBuffer;
    get byteOffset(): number;
    get byteLength(): number;
    readUInt8(): number;
    readUInt16(): number;
    readUInt32(): number;
    readUInt64(): number;
    readBytes(length: any): ArrayBuffer;
}
export class CborSimpleDecoder {
    static readHeader(reader: any): Header;
    static readObject(reader: any): any;
}
declare class Header {
    constructor(h: any);
    major: number;
    information: number;
    length: number;
}
export {};
