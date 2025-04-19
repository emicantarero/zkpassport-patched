"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AggregateError = exports.PromisePool = void 0;
exports.loadModule = loadModule;
exports.toBigIntLE = toBigIntLE;
exports.toBigIntBE = toBigIntBE;
exports.toBufferLE = toBufferLE;
exports.toBufferBE = toBufferBE;
exports.toHex = toHex;
exports.fromHex = fromHex;
exports.strip0x = strip0x;
exports.fromBytesToBigInt = fromBytesToBigInt;
exports.fromArrayBufferToBigInt = fromArrayBufferToBigInt;
exports.rightPadArrayWithZeros = rightPadArrayWithZeros;
exports.leftPadArrayWithZeros = leftPadArrayWithZeros;
exports.getBitSize = getBitSize;
exports.getOffsetInArray = getOffsetInArray;
exports.bigintToBytes = bigintToBytes;
exports.bigintToNumber = bigintToNumber;
exports.assert = assert;
exports.packBeBytesIntoField = packBeBytesIntoField;
exports.packBeBytesIntoFields = packBeBytesIntoFields;
async function loadModule(module) {
    try {
        return require(module);
    }
    catch {
        return undefined;
    }
}
/**
 * Convert a little-endian buffer into a BigInt.
 * @param buf - The little-endian buffer to convert.
 * @returns A BigInt with the little-endian representation of buf.
 */
function toBigIntLE(buf) {
    const reversed = buf;
    reversed.reverse();
    const hex = reversed.toString("hex");
    if (hex.length === 0) {
        return BigInt(0);
    }
    return BigInt(`0x${hex}`);
}
/**
 * Convert a big-endian buffer into a BigInt.
 * @param buf - The big-endian buffer to convert.
 * @returns A BigInt with the big-endian representation of buf.
 */
function toBigIntBE(buf) {
    const hex = buf.toString("hex");
    if (hex.length === 0) {
        return BigInt(0);
    }
    return BigInt(`0x${hex}`);
}
/**
 * Convert a BigInt to a little-endian buffer.
 * @param num - The BigInt to convert.
 * @param width - The number of bytes that the resulting buffer should be.
 * @returns A little-endian buffer representation of num.
 */
function toBufferLE(num, width) {
    if (num < BigInt(0)) {
        throw new Error(`Cannot convert negative bigint ${num.toString()} to buffer with toBufferLE.`);
    }
    const hex = num.toString(16);
    const buffer = Buffer.from(hex.padStart(width * 2, "0").slice(0, width * 2), "hex");
    buffer.reverse();
    return buffer;
}
/**
 * Convert a BigInt to a big-endian buffer.
 * @param num - The BigInt to convert.
 * @param width - The number of bytes that the resulting buffer should be.
 * @returns A big-endian buffer representation of num.
 */
function toBufferBE(num, width) {
    if (num < BigInt(0)) {
        throw new Error(`Cannot convert negative bigint ${num.toString()} to buffer with toBufferBE.`);
    }
    const hex = num.toString(16);
    const buffer = Buffer.from(hex.padStart(width * 2, "0").slice(0, width * 2), "hex");
    if (buffer.length > width) {
        throw new Error(`Number ${num.toString(16)} does not fit in ${width}`);
    }
    return buffer;
}
/**
 * Converts a BigInt to its hex representation.
 * @param num - The BigInt to convert.
 * @param padTo32 - Whether to pad the resulting string to 32 bytes.
 * @returns An even-length 0x-prefixed string.
 */
function toHex(num, padTo32 = false) {
    const str = num.toString(16);
    const targetLen = str.length % 2 === 0 ? str.length : str.length + 1;
    const paddedStr = str.padStart(padTo32 ? 64 : targetLen, "0");
    return `0x${paddedStr}`;
}
/**
 * Converts a hex string to a buffer. Throws if input is not a valid hex string.
 * @param value - The hex string to convert. May be 0x prefixed or not.
 * @returns A buffer.
 */
function fromHex(value) {
    const hexRegex = /^(0x)?[0-9a-fA-F]*$/;
    if (!hexRegex.test(value) || value.length % 2 !== 0) {
        throw new Error(`Invalid hex string: ${value}`);
    }
    return Buffer.from(value.replace(/^0x/i, ""), "hex");
}
/**
 * Strips the '0x' prefix from a hexadecimal string.
 * @param input - The input string.
 * @returns The input string without the '0x' prefix.
 */
function strip0x(input) {
    return input.startsWith("0x") ? input.slice(2) : input;
}
function fromBytesToBigInt(bytes) {
    return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}
function fromArrayBufferToBigInt(buffer) {
    return BigInt("0x" + Buffer.from(buffer).toString("hex"));
}
function rightPadArrayWithZeros(array, length) {
    return array.concat(Array(length - array.length).fill(0));
}
function leftPadArrayWithZeros(array, length) {
    return Array(length - array.length)
        .fill(0)
        .concat(array);
}
function getBitSize(number) {
    return number.toString(2).length;
}
function getOffsetInArray(array, arrayToFind, startPosition = 0) {
    for (let i = startPosition; i < array.length; i++) {
        if (array.slice(i, i + arrayToFind.length).every((val, index) => val === arrayToFind[index])) {
            return i;
        }
    }
    return -1;
}
function bigintToBytes(value) {
    const hexString = value.toString(16).padStart(2, "0");
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.slice(i, i + 2), 16));
    }
    return bytes;
}
function bigintToNumber(value) {
    return Number(value);
}
function assert(truthy, errorMsg) {
    if (!truthy) {
        throw new Error(errorMsg);
    }
}
function packBeBytesIntoField(x, maxFieldSize) {
    let result = BigInt(0);
    for (let i = 0; i < maxFieldSize; i++) {
        result *= BigInt(256);
        result += BigInt(x[i]);
    }
    return result;
}
/**
 * Packs bytes into field elements using big-endian encoding, matching the Noir pack_be_bytes_into_fields function
 * Note: A 254 bit field can hold up to 31 bytes
 */
function packBeBytesIntoFields(bytes, maxChunkSize) {
    if (bytes.length === 0)
        return [];
    const totalFields = Math.ceil(bytes.length / maxChunkSize);
    const result = new Array(totalFields);
    // Calculate size of first chunk (might be smaller than maxChunkSize)
    const firstChunkSize = bytes.length % maxChunkSize || maxChunkSize;
    let byteIndex = 0;
    for (let fieldIndex = totalFields - 1; fieldIndex >= 0; fieldIndex--) {
        const chunkSize = fieldIndex === totalFields - 1 ? firstChunkSize : maxChunkSize;
        let value = 0n;
        for (let i = 0; i < chunkSize; i++) {
            value = (value << 8n) | BigInt(bytes[byteIndex++]);
        }
        const hex = value.toString(16);
        result[fieldIndex] = "0x" + (hex.length % 2 ? "0" : "") + hex;
    }
    return result;
}
var promise_pool_1 = require("./promise-pool");
Object.defineProperty(exports, "PromisePool", { enumerable: true, get: function () { return promise_pool_1.PromisePool; } });
Object.defineProperty(exports, "AggregateError", { enumerable: true, get: function () { return promise_pool_1.AggregateError; } });
