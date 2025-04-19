"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getCommitmentInFromIDDataProof = getCommitmentInFromIDDataProof;
exports.getCommitmentOutFromIDDataProof = getCommitmentOutFromIDDataProof;
exports.getIDDataProofPublicInputCount = getIDDataProofPublicInputCount;
function getCommitmentInFromIDDataProof(proofData) {
    return BigInt(proofData.publicInputs[0]);
}
function getCommitmentOutFromIDDataProof(proofData) {
    return BigInt(proofData.publicInputs[1]);
}
/**
 * Get the number of public inputs for the ID data proof.
 * @returns The number of public inputs.
 */
function getIDDataProofPublicInputCount() {
    return 2;
}
