"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CborSimpleDecoder = exports.BinaryReader = void 0;
const PositiveInteger = 0;
const NegativeInteger = 1;
const ByteString = 2;
const TextString = 3;
const Array = 4;
const Map = 5;
class BinaryReader {
    constructor(buffer) {
        if (!(buffer instanceof ArrayBuffer))
            throw new TypeError();
        this.view = new DataView(buffer);
        this.offset = 0;
    }
    get readerOffset() {
        return this.offset;
    }
    get buffer() {
        return this.view.buffer;
    }
    get byteOffset() {
        return this.view.byteOffset;
    }
    get byteLength() {
        return this.view.byteLength;
    }
    readUInt8() {
        const value = this.view.getUint8(this.offset);
        this.offset += 1;
        return value;
    }
    readUInt16() {
        const value = this.view.getUint16(this.offset);
        this.offset += 2;
        return value;
    }
    readUInt32() {
        const value = this.view.getUint32(this.offset);
        this.offset += 4;
        return value;
    }
    readUInt64() {
        const value = this.view.getBigUint64(this.offset);
        this.offset += 8;
        return Number(value);
    }
    readBytes(length) {
        const value = this.view.buffer.slice(this.offset, this.offset + length);
        this.offset += length;
        return value;
    }
}
exports.BinaryReader = BinaryReader;
class Header {
    constructor(h) {
        this.major = 0;
        this.information = 0;
        this.length = 0;
        this.major = (h >> 5) & 0x7;
        this.information = h & 0x1f;
    }
}
class CborSimpleDecoder {
    static readHeader(reader) {
        if (!(reader instanceof BinaryReader))
            throw new TypeError();
        const h = reader.readUInt8();
        const header = new Header(h);
        if (header.information >= 0 && header.information <= 23) {
            header.length = header.information;
        }
        else if (header.information == 24) {
            header.length = reader.readUInt8();
        }
        else if (header.information == 25) {
            header.length = reader.readUInt16();
        }
        else if (header.information == 26) {
            header.length = reader.readUInt32();
        }
        else if (header.information == 27) {
            header.length = reader.readUInt64();
        }
        else {
            throw new Error(`not implemented: major=${header.major} information=${header.information}`);
        }
        return header;
    }
    static readObject(reader) {
        if (!(reader instanceof BinaryReader))
            throw new TypeError();
        const header = CborSimpleDecoder.readHeader(reader);
        switch (header.major) {
            case PositiveInteger:
                return header.length;
            case NegativeInteger:
                return -1 - header.length;
            case ByteString:
                return reader.readBytes(header.length);
            case TextString:
                let utf = null;
                if (globalThis.TextDecoder) {
                    utf = new globalThis.TextDecoder();
                }
                else {
                    let TextDecoder = require('util').TextDecoder;
                    utf = new TextDecoder();
                }
                return utf.decode(reader.readBytes(header.length));
            case Array:
                const array = [];
                for (let i = 0; i < header.length; i++) {
                    const obj = CborSimpleDecoder.readObject(reader);
                    array.push(obj);
                }
                return array;
            case Map:
                const map = {};
                for (let i = 0; i < header.length; i++) {
                    const key = CborSimpleDecoder.readObject(reader);
                    const value = CborSimpleDecoder.readObject(reader);
                    map[key] = value;
                }
                return map;
            default:
                throw new Error(`not implemented: major=${header.major} information=${header.information}`);
        }
    }
}
exports.CborSimpleDecoder = CborSimpleDecoder;
//# sourceMappingURL=CborSimpleDecoder.js.map