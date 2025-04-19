import { packBeBytesIntoField } from "../utils.js";
import { poseidon2HashAsync } from "@zkpassport/poseidon2";
import { sha256 } from "@noble/hashes/sha256";
import { ProofType } from "./index.js";
export function getMinAgeFromCommittedInputs(committedInputs) {
    return committedInputs.minAge;
}
export function getMaxAgeFromCommittedInputs(committedInputs) {
    return committedInputs.maxAge;
}
/**
 * Get the number of public inputs for the age proof.
 * @returns The number of public inputs.
 */
export function getAgeProofPublicInputCount() {
    return 5;
}
/**
 * Get the parameter commitment for the age proof.
 * @param currentDate - The current date (YYYYMMDD)
 * @param minAge - The minimum age.
 * @param maxAge - The maximum age.
 * @returns The parameter commitment.
 */
export async function getAgeParameterCommitment(currentDate, minAge, maxAge) {
    const ageParameterCommitment = await poseidon2HashAsync([
        BigInt(ProofType.AGE),
        ...Array.from(new TextEncoder().encode(currentDate)).map((x) => BigInt(x)),
        BigInt(minAge),
        BigInt(maxAge),
    ]);
    return ageParameterCommitment;
}
/**
 * Get the EVM parameter commitment for the age proof.
 * @param currentDate - The current date (YYYYMMDD)
 * @param minAge - The minimum age.
 * @param maxAge - The maximum age.
 * @returns The parameter commitment.
 */
export async function getAgeEVMParameterCommitment(currentDate, minAge, maxAge) {
    const hash = sha256(new Uint8Array([
        ProofType.AGE,
        ...Array.from(new TextEncoder().encode(currentDate)).map((x) => Number(x)),
        minAge,
        maxAge,
    ]));
    const hashBigInt = packBeBytesIntoField(hash, 31);
    return hashBigInt;
}
