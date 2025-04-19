"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.F1Field = void 0;
class F1Field {
    constructor(prime) {
        this.zero = BigInt(0);
        this.one = BigInt(1);
        this.prime = prime;
    }
    e(x) {
        if (typeof x === "bigint") {
            return x % this.prime;
        }
        else {
            return BigInt(x) % this.prime;
        }
    }
    add(x, y) {
        return (x + y) % this.prime;
    }
    sub(x, y) {
        return (this.prime + x - y) % this.prime;
    }
    mul(x, y) {
        return (x * y) % this.prime;
    }
    square(x) {
        return (x * x) % this.prime;
    }
    div(x, y) {
        return (x / y) % this.prime;
    }
}
exports.F1Field = F1Field;
