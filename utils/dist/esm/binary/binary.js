export class Binary {
    constructor(data) {
        this.bytes = Binary.convertToBytes(data);
    }
    static convertToBytes(data) {
        if (typeof data === "bigint" || typeof data === "number") {
            const hex = data.toString(16);
            const paddedHex = hex.padStart(Math.ceil(hex.length / 2) * 2, "0");
            return new Uint8Array(paddedHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []);
        }
        if (data instanceof Uint8Array) {
            return new Uint8Array(data);
        }
        if (Buffer.isBuffer(data)) {
            return new Uint8Array(data);
        }
        if (Array.isArray(data)) {
            if (!data.every((n) => typeof n === "number" && n >= 0 && n <= 255)) {
                throw new Error("Invalid byte array: values must be between 0 and 255");
            }
            return new Uint8Array(data);
        }
        if (data instanceof ArrayBuffer) {
            return new Uint8Array(data);
        }
        if (typeof data === "string") {
            if (Binary.isHexString(data)) {
                const hex = data.startsWith("0x") ? data.slice(2) : data;
                const paddedHex = hex.padStart(Math.ceil(hex.length / 2) * 2, "0");
                return new Uint8Array(paddedHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []);
            }
            try {
                // Try parsing as numeric string first
                const bigInt = BigInt(data);
                return Binary.convertToBytes(bigInt);
            }
            catch {
                // Fall back to ASCII if not numeric
                return new Uint8Array(Buffer.from(data, "ascii"));
            }
        }
        throw new Error("Unsupported data type");
    }
    static isHexString(value) {
        const hex = value.startsWith("0x") ? value.slice(2) : value;
        return /^[0-9a-fA-F]*$/.test(hex);
    }
    // Factory methods
    static from(data) {
        return new Binary(data);
    }
    static fromHex(hex) {
        if (!Binary.isHexString(hex)) {
            throw new Error("Invalid hex string");
        }
        return new Binary(hex.startsWith("0x") ? hex : "0x" + hex);
    }
    static fromBuffer(buffer) {
        return new Binary(buffer);
    }
    static fromBase64(base64) {
        const binary = atob(base64);
        return new Binary(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
    }
    static empty() {
        return new Binary(new Uint8Array(0));
    }
    static zero(length) {
        return new Binary(new Uint8Array(length));
    }
    // Conversion methods
    toBigInt() {
        return BigInt("0x" + this.toHex().slice(2));
    }
    toUInt8Array() {
        return new Uint8Array(this.bytes);
    }
    toNumberArray() {
        return Array.from(this.bytes);
    }
    toHex() {
        return ("0x" +
            Array.from(this.bytes)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join(""));
    }
    toBuffer() {
        return Buffer.from(this.bytes);
    }
    toString(encoding = "hex") {
        if (encoding === "hex") {
            return this.toHex().slice(2);
        }
        return Buffer.from(this.bytes).toString(encoding);
    }
    toBase64() {
        return btoa(String.fromCharCode(...this.bytes));
    }
    toJSON() {
        return this.toHex();
    }
    [Symbol.for("nodejs.util.inspect.custom")]() {
        return `Binary(${this.toHex()})`;
    }
    [Symbol.toPrimitive](hint) {
        switch (hint) {
            case "number":
                return Number(this.toBigInt());
            case "string":
                return `Binary(${this.toHex()})`;
            default:
                return this.toBigInt();
        }
    }
    valueOf() {
        return this.toBigInt();
    }
    get length() {
        return this.bytes.length;
    }
    // Iterator
    *[Symbol.iterator]() {
        yield* this.bytes;
    }
    // Utility methods
    equals(other) {
        if (this.length !== other.length)
            return false;
        return this.bytes.every((byte, i) => byte === other.bytes[i]);
    }
    slice(start, end) {
        return new Binary(this.bytes.slice(start, end));
    }
    // concat(other: Binary): Binary {
    //   const result = new Uint8Array(this.length + other.length)
    //   result.set(this.bytes)
    //   result.set(other.bytes, this.length)
    //   return new Binary(result)
    // }
    concat(other) {
        return new Binary([...this.toNumberArray(), ...other.toNumberArray()]);
    }
    // Add operator overload
    [Symbol.for("+")](other) {
        return this.concat(other);
    }
    compare(other) {
        const minLength = Math.min(this.length, other.length);
        for (let i = 0; i < minLength; i++) {
            const diff = this.bytes[i] - other.bytes[i];
            if (diff !== 0)
                return diff;
        }
        return this.length - other.length;
    }
    // Bitwise operations
    xor(other) {
        if (this.length !== other.length) {
            throw new Error("Binary instances must be of equal length for XOR operation");
        }
        const result = new Uint8Array(this.length);
        for (let i = 0; i < this.length; i++) {
            result[i] = this.bytes[i] ^ other.bytes[i];
        }
        return new Binary(result);
    }
    and(other) {
        if (this.length !== other.length) {
            throw new Error("Binary instances must be of equal length for AND operation");
        }
        const result = new Uint8Array(this.length);
        for (let i = 0; i < this.length; i++) {
            result[i] = this.bytes[i] & other.bytes[i];
        }
        return new Binary(result);
    }
    or(other) {
        if (this.length !== other.length) {
            throw new Error("Binary instances must be of equal length for OR operation");
        }
        const result = new Uint8Array(this.length);
        for (let i = 0; i < this.length; i++) {
            result[i] = this.bytes[i] | other.bytes[i];
        }
        return new Binary(result);
    }
    not() {
        const result = new Uint8Array(this.length);
        for (let i = 0; i < this.length; i++) {
            result[i] = ~this.bytes[i] & 0xff;
        }
        return new Binary(result);
    }
    // Padding methods
    padStart(length, fillByte = 0) {
        if (this.length >= length)
            return this;
        const result = new Uint8Array(length);
        result.fill(fillByte, 0, length - this.length);
        result.set(this.bytes, length - this.length);
        return new Binary(result);
    }
    padEnd(length, fillByte = 0) {
        if (this.length >= length)
            return this;
        const result = new Uint8Array(length);
        result.set(this.bytes);
        result.fill(fillByte, this.length);
        return new Binary(result);
    }
}
