import { ProofData } from "..";
export declare function getMerkleRootFromDSCProof(proofData: ProofData): bigint;
export declare function getCommitmentFromDSCProof(proofData: ProofData): bigint;
/**
 * Get the number of public inputs for the DSC proof.
 * @returns The number of public inputs.
 */
export declare function getDSCProofPublicInputCount(): number;
