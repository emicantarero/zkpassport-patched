"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMerkleRootFromDSCProof = getMerkleRootFromDSCProof;
exports.getCommitmentFromDSCProof = getCommitmentFromDSCProof;
exports.getDSCProofPublicInputCount = getDSCProofPublicInputCount;
function getMerkleRootFromDSCProof(proofData) {
    return BigInt(proofData.publicInputs[0]);
}
function getCommitmentFromDSCProof(proofData) {
    return BigInt(proofData.publicInputs[1]);
}
/**
 * Get the number of public inputs for the DSC proof.
 * @returns The number of public inputs.
 */
function getDSCProofPublicInputCount() {
    return 2;
}
