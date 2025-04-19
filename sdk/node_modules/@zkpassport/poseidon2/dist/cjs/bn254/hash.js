"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.permute = exports.F = void 0;
exports.hashToField = hashToField;
const instance_js_1 = require("./instance.js");
exports.F = (0, instance_js_1.getPoseidon2BN254)().primeField;
exports.permute = (0, instance_js_1.getPoseidon2BN254)().permute.bind((0, instance_js_1.getPoseidon2BN254)());
var Mode;
(function (Mode) {
    Mode[Mode["ABSORB"] = 0] = "ABSORB";
    Mode[Mode["SQUEEZE"] = 1] = "SQUEEZE";
})(Mode || (Mode = {}));
class FieldSponge {
    constructor(domainIv = 0n) {
        this.rate = (0, instance_js_1.getPoseidon2BN254)().getT() - 1;
        this.t = (0, instance_js_1.getPoseidon2BN254)().getT();
        this.state = new Array(this.t).fill(0n);
        this.state[this.rate] = domainIv;
        this.cache = new Array(this.rate).fill(0n);
        this.cacheSize = 0;
        this.mode = Mode.ABSORB;
    }
    performDuplex() {
        // Zero-pad the cache
        for (let i = this.cacheSize; i < this.rate; i++) {
            this.cache[i] = 0n;
        }
        // Add cache into sponge state
        for (let i = 0; i < this.rate; i++) {
            this.state[i] = exports.F.add(this.state[i], this.cache[i]);
        }
        this.state = (0, exports.permute)(this.state);
        // Return rate number of elements from state
        return this.state.slice(0, this.rate);
    }
    absorb(input) {
        if (this.mode === Mode.ABSORB && this.cacheSize === this.rate) {
            this.performDuplex();
            this.cache[0] = input;
            this.cacheSize = 1;
        }
        else if (this.mode === Mode.ABSORB && this.cacheSize < this.rate) {
            this.cache[this.cacheSize] = input;
            this.cacheSize += 1;
        }
        else if (this.mode === Mode.SQUEEZE) {
            this.cache[0] = input;
            this.cacheSize = 1;
            this.mode = Mode.ABSORB;
        }
    }
    squeeze() {
        if (this.mode === Mode.SQUEEZE && this.cacheSize === 0) {
            this.mode = Mode.ABSORB;
            this.cacheSize = 0;
        }
        if (this.mode === Mode.ABSORB) {
            const newOutputElements = this.performDuplex();
            this.mode = Mode.SQUEEZE;
            for (let i = 0; i < this.rate; i++) {
                this.cache[i] = newOutputElements[i];
            }
            this.cacheSize = this.rate;
        }
        const result = this.cache[0];
        for (let i = 1; i < this.cacheSize; i++) {
            this.cache[i - 1] = this.cache[i];
        }
        this.cacheSize -= 1;
        this.cache[this.cacheSize] = 0n;
        return result;
    }
    static hashInternal(input, outLen, isVariableLength) {
        const iv = (BigInt(input.length) << BigInt(64n)) + BigInt(outLen - 1);
        const sponge = new FieldSponge(iv);
        for (let i = 0; i < input.length; i++) {
            sponge.absorb(input[i]);
        }
        if (isVariableLength) {
            sponge.absorb(1n);
        }
        const output = [];
        for (let i = 0; i < outLen; i++) {
            output.push(sponge.squeeze());
        }
        return output;
    }
    static hashFixedLength(input, outLen = 1) {
        return this.hashInternal(input, outLen, false);
    }
    static hashVariableLength(input, outLen = 1) {
        return this.hashInternal(input, outLen, true);
    }
}
function hashToField(input) {
    return FieldSponge.hashFixedLength(input)[0];
}
