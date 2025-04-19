"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getCommitmentInFromIntegrityProof = getCommitmentInFromIntegrityProof;
exports.getCommitmentOutFromIntegrityProof = getCommitmentOutFromIntegrityProof;
exports.getCurrentDateFromIntegrityProof = getCurrentDateFromIntegrityProof;
exports.getIntegrityProofPublicInputCount = getIntegrityProofPublicInputCount;
const __1 = require("..");
function getCommitmentInFromIntegrityProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 2]);
}
function getCommitmentOutFromIntegrityProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 1]);
}
function getCurrentDateFromIntegrityProof(proofData) {
    const dateBytes = proofData.publicInputs
        .slice(0, 8)
        .map((x) => Number(x) - 48)
        .map((x) => x.toString());
    const date = (0, __1.convertDateBytesToDate)(dateBytes.join(""));
    return date;
}
/**
 * Get the number of public inputs for the integrity proof.
 * @returns The number of public inputs.
 */
function getIntegrityProofPublicInputCount() {
    return 10;
}
