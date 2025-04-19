"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.convertDateBytesToDate = convertDateBytesToDate;
exports.getMinDateFromCommittedInputs = getMinDateFromCommittedInputs;
exports.getMaxDateFromCommittedInputs = getMaxDateFromCommittedInputs;
exports.getDateProofPublicInputCount = getDateProofPublicInputCount;
exports.getDateParameterCommitment = getDateParameterCommitment;
exports.getDateEVMParameterCommitment = getDateEVMParameterCommitment;
const sha256_1 = require("@noble/hashes/sha256");
const poseidon2_1 = require("@zkpassport/poseidon2");
const utils_1 = require("../utils");
/**
 * Convert a date string to a Date object
 * @param strDate - The date string to convert (YYYYMMDD)
 * @returns The Date object
 */
function convertDateBytesToDate(strDate) {
    const year = Number(strDate.slice(0, 4));
    const month = Number(strDate.slice(4, 6));
    const day = Number(strDate.slice(6, 8));
    return new Date(year, month - 1, day);
}
function getMinDateFromCommittedInputs(committedInputs) {
    return convertDateBytesToDate(committedInputs.minDate);
}
function getMaxDateFromCommittedInputs(committedInputs) {
    return convertDateBytesToDate(committedInputs.maxDate);
}
/**
 * Get the number of public inputs for the date proof.
 * @returns The number of public inputs.
 */
function getDateProofPublicInputCount() {
    return 5;
}
/**
 * Get the parameter commitment for the date proof (birthdate and expiry date alike).
 * @param proofType - The proof type.
 * @param currentDate - The current date (YYYYMMDD)
 * @param minDate - The minimum date (YYYYMMDD)
 * @param maxDate - The maximum date (YYYYMMDD)
 * @returns The parameter commitment.
 */
async function getDateParameterCommitment(proofType, currentDate, minDate = "11111111", maxDate = "11111111") {
    const birthdateParameterCommitment = await (0, poseidon2_1.poseidon2HashAsync)([
        BigInt(proofType),
        ...Array.from(new TextEncoder().encode(currentDate)).map((x) => BigInt(x)),
        ...Array.from(new TextEncoder().encode(minDate)).map((x) => BigInt(x)),
        ...Array.from(new TextEncoder().encode(maxDate)).map((x) => BigInt(x)),
    ]);
    return birthdateParameterCommitment;
}
/**
 * Get the EVM parameter commitment for the date proof (birthdate and expiry date alike).
 * @param proofType - The proof type.
 * @param currentDate - The current date (YYYYMMDD)
 * @param minDate - The minimum date (YYYYMMDD)
 * @param maxDate - The maximum date (YYYYMMDD)
 * @returns The parameter commitment.
 */
async function getDateEVMParameterCommitment(proofType, currentDate, minDate = "11111111", maxDate = "11111111") {
    const hash = (0, sha256_1.sha256)(new Uint8Array([
        proofType,
        ...Array.from(new TextEncoder().encode(currentDate)).map((x) => Number(x)),
        ...Array.from(new TextEncoder().encode(minDate)).map((x) => Number(x)),
        ...Array.from(new TextEncoder().encode(maxDate)).map((x) => Number(x)),
    ]));
    const hashBigInt = (0, utils_1.packBeBytesIntoField)(hash, 31);
    return hashBigInt;
}
