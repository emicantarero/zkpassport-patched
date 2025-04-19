import { AgeCommittedInputs } from "../types";
export declare function getMinAgeFromCommittedInputs(committedInputs: AgeCommittedInputs): number;
export declare function getMaxAgeFromCommittedInputs(committedInputs: AgeCommittedInputs): number;
/**
 * Get the number of public inputs for the age proof.
 * @returns The number of public inputs.
 */
export declare function getAgeProofPublicInputCount(): number;
/**
 * Get the parameter commitment for the age proof.
 * @param currentDate - The current date (YYYYMMDD)
 * @param minAge - The minimum age.
 * @param maxAge - The maximum age.
 * @returns The parameter commitment.
 */
export declare function getAgeParameterCommitment(currentDate: string, minAge: number, maxAge: number): Promise<bigint>;
/**
 * Get the EVM parameter commitment for the age proof.
 * @param currentDate - The current date (YYYYMMDD)
 * @param minAge - The minimum age.
 * @param maxAge - The maximum age.
 * @returns The parameter commitment.
 */
export declare function getAgeEVMParameterCommitment(currentDate: string, minAge: number, maxAge: number): Promise<bigint>;
