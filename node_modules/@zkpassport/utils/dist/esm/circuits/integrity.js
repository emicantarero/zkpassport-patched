import { convertDateBytesToDate } from "../index.js";
export function getCommitmentInFromIntegrityProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 2]);
}
export function getCommitmentOutFromIntegrityProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 1]);
}
export function getCurrentDateFromIntegrityProof(proofData) {
    const dateBytes = proofData.publicInputs
        .slice(0, 8)
        .map((x) => Number(x) - 48)
        .map((x) => x.toString());
    const date = convertDateBytesToDate(dateBytes.join(""));
    return date;
}
/**
 * Get the number of public inputs for the integrity proof.
 * @returns The number of public inputs.
 */
export function getIntegrityProofPublicInputCount() {
    return 10;
}
