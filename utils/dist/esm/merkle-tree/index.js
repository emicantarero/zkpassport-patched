import { Binary } from "../binary/index.js";
import { poseidon2HashAsync } from "@zkpassport/poseidon2";
import { AsyncIMT } from "./async-imt.js";
async function poseidon2(values) {
    return poseidon2HashAsync(values.map((v) => BigInt(v)));
}
export async function computeMerkleProof(leaves, index, height) {
    if (index < 0 || index >= leaves.length)
        throw new Error("Invalid index");
    const zeroValue = 0;
    const arity = 2;
    const tree = new AsyncIMT(poseidon2, height, arity);
    await tree.initialize(zeroValue, leaves.map((leaf) => leaf.toBigInt()));
    const proof = tree.createProof(index);
    return {
        root: Binary.from(BigInt(proof.root)).toHex(),
        index: proof.leafIndex,
        path: proof.siblings.flatMap((v) => Binary.from(BigInt(v)).toHex()),
    };
}
export { AsyncIMT };
