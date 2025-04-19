"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMinAgeFromCommittedInputs = getMinAgeFromCommittedInputs;
exports.getMaxAgeFromCommittedInputs = getMaxAgeFromCommittedInputs;
exports.getAgeProofPublicInputCount = getAgeProofPublicInputCount;
exports.getAgeParameterCommitment = getAgeParameterCommitment;
exports.getAgeEVMParameterCommitment = getAgeEVMParameterCommitment;
const utils_1 = require("../utils");
const poseidon2_1 = require("@zkpassport/poseidon2");
const sha256_1 = require("@noble/hashes/sha256");
const _1 = require(".");
function getMinAgeFromCommittedInputs(committedInputs) {
    return committedInputs.minAge;
}
function getMaxAgeFromCommittedInputs(committedInputs) {
    return committedInputs.maxAge;
}
/**
 * Get the number of public inputs for the age proof.
 * @returns The number of public inputs.
 */
function getAgeProofPublicInputCount() {
    return 5;
}
/**
 * Get the parameter commitment for the age proof.
 * @param currentDate - The current date (YYYYMMDD)
 * @param minAge - The minimum age.
 * @param maxAge - The maximum age.
 * @returns The parameter commitment.
 */
async function getAgeParameterCommitment(currentDate, minAge, maxAge) {
    const ageParameterCommitment = await (0, poseidon2_1.poseidon2HashAsync)([
        BigInt(_1.ProofType.AGE),
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
async function getAgeEVMParameterCommitment(currentDate, minAge, maxAge) {
    const hash = (0, sha256_1.sha256)(new Uint8Array([
        _1.ProofType.AGE,
        ...Array.from(new TextEncoder().encode(currentDate)).map((x) => Number(x)),
        minAge,
        maxAge,
    ]));
    const hashBigInt = (0, utils_1.packBeBytesIntoField)(hash, 31);
    return hashBigInt;
}
