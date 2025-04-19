import { ProofData } from "..";
export declare function getCommitmentInFromIntegrityProof(proofData: ProofData): bigint;
export declare function getCommitmentOutFromIntegrityProof(proofData: ProofData): bigint;
export declare function getCurrentDateFromIntegrityProof(proofData: ProofData): Date;
/**
 * Get the number of public inputs for the integrity proof.
 * @returns The number of public inputs.
 */
export declare function getIntegrityProofPublicInputCount(): number;
