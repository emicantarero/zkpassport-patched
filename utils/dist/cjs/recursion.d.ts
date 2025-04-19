import { ProofData } from ".";
export type OuterCircuitProof = {
    proof: string[];
    publicInputs: string[];
    vkey: string[];
    keyHash: string;
};
export declare function getOuterCircuitInputs(cscToDscProof: OuterCircuitProof, dscToIdDataProof: OuterCircuitProof, integrityCheckProof: OuterCircuitProof, disclosureProofs: OuterCircuitProof[]): {
    certificate_registry_root: string;
    current_date: string;
    service_scope: string;
    service_subscope: string;
    param_commitments: string[];
    scoped_nullifier: string;
    csc_to_dsc_proof: {
        vkey: string[];
        proof: string[];
        public_inputs: string[];
        key_hash: string;
    };
    dsc_to_id_data_proof: {
        vkey: string[];
        proof: string[];
        public_inputs: string[];
        key_hash: string;
    };
    integrity_check_proof: {
        vkey: string[];
        proof: string[];
        public_inputs: string[];
        key_hash: string;
    };
    disclosure_proofs: {
        vkey: string[];
        proof: string[];
        public_inputs: string[];
        key_hash: string;
    }[];
};
export declare function getCertificateRegistryRootFromOuterProof(proofData: ProofData): bigint;
export declare function getCurrentDateFromOuterProof(proofData: ProofData): Date;
/**
 * Get the service scope from the outer circuit proof.
 * @param proofData - The proof data.
 * @returns The service scope.
 */
export declare function getScopeFromOuterProof(proofData: ProofData): bigint;
/**
 * Get the service subscope from the outer circuit proof.
 * @param proofData - The proof data.
 * @returns The service subscope.
 */
export declare function getSubscopeFromOuterProof(proofData: ProofData): bigint;
/**
 * Get the scoped nullifier from the outer circuit proof.
 * @param proofData - The proof data.
 * @returns The scoped nullifier.
 */
export declare function getNullifierFromOuterProof(proofData: ProofData): bigint;
/**
 * Get the param commitments from the outer circuit proof.
 * @param proofData - The proof data.
 * @returns The param commitments.
 */
export declare function getParamCommitmentsFromOuterProof(proofData: ProofData): bigint[];
