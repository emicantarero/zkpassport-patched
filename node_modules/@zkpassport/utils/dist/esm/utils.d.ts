export declare function loadModule(module: string): Promise<any>;
/**
 * Convert a little-endian buffer into a BigInt.
 * @param buf - The little-endian buffer to convert.
 * @returns A BigInt with the little-endian representation of buf.
 */
export declare function toBigIntLE(buf: Buffer): bigint;
/**
 * Convert a big-endian buffer into a BigInt.
 * @param buf - The big-endian buffer to convert.
 * @returns A BigInt with the big-endian representation of buf.
 */
export declare function toBigIntBE(buf: Buffer): bigint;
/**
 * Convert a BigInt to a little-endian buffer.
 * @param num - The BigInt to convert.
 * @param width - The number of bytes that the resulting buffer should be.
 * @returns A little-endian buffer representation of num.
 */
export declare function toBufferLE(num: bigint, width: number): Buffer;
/**
 * Convert a BigInt to a big-endian buffer.
 * @param num - The BigInt to convert.
 * @param width - The number of bytes that the resulting buffer should be.
 * @returns A big-endian buffer representation of num.
 */
export declare function toBufferBE(num: bigint, width: number): Buffer;
/**
 * Converts a BigInt to its hex representation.
 * @param num - The BigInt to convert.
 * @param padTo32 - Whether to pad the resulting string to 32 bytes.
 * @returns An even-length 0x-prefixed string.
 */
export declare function toHex(num: bigint, padTo32?: boolean): `0x${string}`;
/**
 * Converts a hex string to a buffer. Throws if input is not a valid hex string.
 * @param value - The hex string to convert. May be 0x prefixed or not.
 * @returns A buffer.
 */
export declare function fromHex(value: string): Buffer;
/**
 * Strips the '0x' prefix from a hexadecimal string.
 * @param input - The input string.
 * @returns The input string without the '0x' prefix.
 */
export declare function strip0x(input: string): string;
export declare function fromBytesToBigInt(bytes: number[]): bigint;
export declare function fromArrayBufferToBigInt(buffer: ArrayBuffer): bigint;
export declare function rightPadArrayWithZeros(array: number[], length: number): number[];
export declare function leftPadArrayWithZeros(array: number[], length: number): number[];
export declare function getBitSize(number: number | string | bigint): number;
export declare function getOffsetInArray(array: any[], arrayToFind: any[], startPosition?: number): number;
export declare function bigintToBytes(value: bigint): number[];
export declare function bigintToNumber(value: bigint): number;
export declare function assert(truthy: boolean, errorMsg: string): void;
export declare function packBeBytesIntoField(x: Uint8Array, maxFieldSize: number): bigint;
/**
 * Packs bytes into field elements using big-endian encoding, matching the Noir pack_be_bytes_into_fields function
 * Note: A 254 bit field can hold up to 31 bytes
 */
export declare function packBeBytesIntoFields(bytes: Uint8Array, maxChunkSize: number): string[];
export { PromisePool, AggregateError } from "./promise-pool";
