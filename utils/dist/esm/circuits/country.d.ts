import { Alpha3Code } from "i18n-iso-countries";
import { CountryCommittedInputs } from "../types";
import { ProofType } from ".";
export declare function getCountryWeightedSum(country: Alpha3Code): number;
export declare function getCountryFromWeightedSum(weightedSum: number): Alpha3Code;
export declare function getCountryListFromCommittedInputs(committedInputs: CountryCommittedInputs): Alpha3Code[];
/**
 * Get the number of public inputs for the country exclusion proof.
 * @returns The number of public inputs.
 */
export declare function getCountryExclusionProofPublicInputCount(): number;
/**
 * Get the number of public inputs for the country inclusion proof.
 * @returns The number of public inputs.
 */
export declare function getCountryInclusionProofPublicInputCount(): number;
/**
 * Get the parameter commitment for the country proof (inclusion and exclusion alike).
 * @param proofType - The proof type.
 * @param countries - The list of countries.
 * @param sorted - Whether the countries are sorted.
 * @returns The parameter commitment.
 */
export declare function getCountryParameterCommitment(proofType: ProofType, countries: Alpha3Code[], sorted?: boolean): Promise<bigint>;
/**
 * Get the EVM parameter commitment for the country proof (inclusion and exclusion alike).
 * @param proofType - The proof type.
 * @param countries - The list of countries.
 * @param sorted - Whether the countries are sorted.
 * @returns The parameter commitment.
 */
export declare function getCountryEVMParameterCommitment(proofType: ProofType, countries: Alpha3Code[], sorted?: boolean): Promise<bigint>;
