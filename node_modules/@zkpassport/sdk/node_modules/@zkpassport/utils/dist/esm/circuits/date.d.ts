import { DateCommittedInputs } from "../types";
import { ProofType } from ".";
/**
 * Convert a date string to a Date object
 * @param strDate - The date string to convert (YYYYMMDD)
 * @returns The Date object
 */
export declare function convertDateBytesToDate(strDate: string): Date;
export declare function getMinDateFromCommittedInputs(committedInputs: DateCommittedInputs): Date;
export declare function getMaxDateFromCommittedInputs(committedInputs: DateCommittedInputs): Date;
/**
 * Get the number of public inputs for the date proof.
 * @returns The number of public inputs.
 */
export declare function getDateProofPublicInputCount(): number;
/**
 * Get the parameter commitment for the date proof (birthdate and expiry date alike).
 * @param proofType - The proof type.
 * @param currentDate - The current date (YYYYMMDD)
 * @param minDate - The minimum date (YYYYMMDD)
 * @param maxDate - The maximum date (YYYYMMDD)
 * @returns The parameter commitment.
 */
export declare function getDateParameterCommitment(proofType: ProofType, currentDate: string, minDate?: string, maxDate?: string): Promise<bigint>;
/**
 * Get the EVM parameter commitment for the date proof (birthdate and expiry date alike).
 * @param proofType - The proof type.
 * @param currentDate - The current date (YYYYMMDD)
 * @param minDate - The minimum date (YYYYMMDD)
 * @param maxDate - The maximum date (YYYYMMDD)
 * @returns The parameter commitment.
 */
export declare function getDateEVMParameterCommitment(proofType: ProofType, currentDate: string, minDate?: string, maxDate?: string): Promise<bigint>;
