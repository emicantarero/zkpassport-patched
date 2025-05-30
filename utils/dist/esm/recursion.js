import { convertDateBytesToDate, getFormattedDate } from "./index.js";
export function getOuterCircuitInputs(cscToDscProof, dscToIdDataProof, integrityCheckProof, disclosureProofs) {
    const certificateRegistryRoot = cscToDscProof.publicInputs[0];
    const dateBytes = integrityCheckProof.publicInputs
        .slice(0, 8)
        .map((x) => Number(x) - 48)
        .map((x) => x.toString());
    const currentDate = convertDateBytesToDate(dateBytes.join(""));
    const scope = disclosureProofs[0].publicInputs[1];
    const subscope = disclosureProofs[0].publicInputs[2];
    const nullifier = disclosureProofs[0].publicInputs[4];
    const paramCommitments = disclosureProofs.map((proof) => proof.publicInputs[3]);
    return {
        certificate_registry_root: certificateRegistryRoot,
        current_date: getFormattedDate(currentDate),
        service_scope: scope,
        service_subscope: subscope,
        param_commitments: paramCommitments,
        scoped_nullifier: nullifier,
        csc_to_dsc_proof: {
            vkey: cscToDscProof.vkey,
            proof: cscToDscProof.proof,
            // Remove the certificate registry root from the public inputs
            public_inputs: cscToDscProof.publicInputs.slice(1),
            key_hash: cscToDscProof.keyHash,
        },
        dsc_to_id_data_proof: {
            vkey: dscToIdDataProof.vkey,
            proof: dscToIdDataProof.proof,
            public_inputs: dscToIdDataProof.publicInputs,
            key_hash: dscToIdDataProof.keyHash,
        },
        integrity_check_proof: {
            vkey: integrityCheckProof.vkey,
            proof: integrityCheckProof.proof,
            // Only keep the commitments from the public inputs
            public_inputs: integrityCheckProof.publicInputs.slice(-2),
            key_hash: integrityCheckProof.keyHash,
        },
        disclosure_proofs: disclosureProofs.map((proof) => ({
            vkey: proof.vkey,
            proof: proof.proof,
            // Only keep the commitment in from the public inputs
            // all the rest are passed directly as public inputs to the outer circuit
            public_inputs: proof.publicInputs.slice(0, 1),
            key_hash: proof.keyHash,
        })),
    };
}
export function getCertificateRegistryRootFromOuterProof(proofData) {
    return BigInt(proofData.publicInputs[0]);
}
export function getCurrentDateFromOuterProof(proofData) {
    const dateBytes = proofData.publicInputs
        .slice(1, 9)
        .map((x) => Number(x) - 48)
        .map((x) => x.toString());
    const date = convertDateBytesToDate(dateBytes.join(""));
    return date;
}
/**
 * Get the service scope from the outer circuit proof.
 * @param proofData - The proof data.
 * @returns The service scope.
 */
export function getScopeFromOuterProof(proofData) {
    return BigInt(proofData.publicInputs[9]);
}
/**
 * Get the service subscope from the outer circuit proof.
 * @param proofData - The proof data.
 * @returns The service subscope.
 */
export function getSubscopeFromOuterProof(proofData) {
    return BigInt(proofData.publicInputs[10]);
}
/**
 * Get the scoped nullifier from the outer circuit proof.
 * @param proofData - The proof data.
 * @returns The scoped nullifier.
 */
export function getNullifierFromOuterProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 1]);
}
/**
 * Get the param commitments from the outer circuit proof.
 * @param proofData - The proof data.
 * @returns The param commitments.
 */
export function getParamCommitmentsFromOuterProof(proofData) {
    return proofData.publicInputs.slice(11, proofData.publicInputs.length - 1).map(BigInt);
}
