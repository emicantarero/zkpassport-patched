import { ProofData } from "..";
export declare function getCommitmentInFromIDDataProof(proofData: ProofData): bigint;
export declare function getCommitmentOutFromIDDataProof(proofData: ProofData): bigint;
/**
 * Get the number of public inputs for the ID data proof.
 * @returns The number of public inputs.
 */
export declare function getIDDataProofPublicInputCount(): number;
