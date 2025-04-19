declare global {
    interface BigIntConstructor {
        (value: Binary): bigint;
    }
}
export type BinaryInput = bigint | Buffer | Uint8Array | number[] | string | number | ArrayBufferLike;
export type HexString = string & {
    readonly __hex: unique symbol;
};
export declare class Binary {
    private readonly bytes;
    constructor(data: BinaryInput);
    private static convertToBytes;
    private static isHexString;
    static from(data: BinaryInput): Binary;
    static fromHex(hex: string): Binary;
    static fromBuffer(buffer: Buffer): Binary;
    static fromBase64(base64: string): Binary;
    static empty(): Binary;
    static zero(length: number): Binary;
    toBigInt(): bigint;
    toUInt8Array(): Uint8Array;
    toNumberArray(): number[];
    toHex(): HexString | string;
    toBuffer(): Buffer;
    toString(encoding?: BufferEncoding): string;
    toBase64(): string;
    toJSON(): string;
    [Symbol.toPrimitive](hint: string): string | number | bigint;
    valueOf(): bigint;
    get length(): number;
    [Symbol.iterator](): Iterator<number>;
    equals(other: Binary): boolean;
    slice(start?: number, end?: number): Binary;
    concat(other: Binary): Binary;
    compare(other: Binary): number;
    xor(other: Binary): Binary;
    and(other: Binary): Binary;
    or(other: Binary): Binary;
    not(): Binary;
    padStart(length: number, fillByte?: number): Binary;
    padEnd(length: number, fillByte?: number): Binary;
}
