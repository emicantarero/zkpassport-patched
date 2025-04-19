"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AsyncIMT = void 0;
exports.computeMerkleProof = computeMerkleProof;
const binary_1 = require("../binary");
const poseidon2_1 = require("@zkpassport/poseidon2");
const async_imt_1 = require("./async-imt");
Object.defineProperty(exports, "AsyncIMT", { enumerable: true, get: function () { return async_imt_1.AsyncIMT; } });
async function poseidon2(values) {
    return (0, poseidon2_1.poseidon2HashAsync)(values.map((v) => BigInt(v)));
}
async function computeMerkleProof(leaves, index, height) {
    if (index < 0 || index >= leaves.length)
        throw new Error("Invalid index");
    const zeroValue = 0;
    const arity = 2;
    const tree = new async_imt_1.AsyncIMT(poseidon2, height, arity);
    await tree.initialize(zeroValue, leaves.map((leaf) => leaf.toBigInt()));
    const proof = tree.createProof(index);
    return {
        root: binary_1.Binary.from(BigInt(proof.root)).toHex(),
        index: proof.leafIndex,
        path: proof.siblings.flatMap((v) => binary_1.Binary.from(BigInt(v)).toHex()),
    };
}
