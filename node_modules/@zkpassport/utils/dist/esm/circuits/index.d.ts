import { Binary } from "../binary";
import { AgeCommittedInputs, Certificate, DateCommittedInputs, DisclosureCircuitName, PackagedCircuit } from "../types";
export interface ProofData {
    publicInputs: string[];
    proof: string[];
}
export declare function calculatePrivateNullifier(dg1: Binary, sodSig: Binary): Promise<Binary>;
export declare function hashSaltCountryTbs(salt: bigint, country: string, tbs: Binary, maxTbsLength: number): Promise<Binary>;
export declare function hashSaltCountrySignedAttrDg1PrivateNullifier(salt: bigint, country: string, paddedSignedAttr: Binary, signedAttrSize: bigint, dg1: Binary, privateNullifier: bigint): Promise<Binary>;
export declare function hashSaltDg1PrivateNullifier(salt: bigint, dg1: Binary, privateNullifier: bigint): Promise<Binary>;
export declare function getCertificateLeafHash(cert: Certificate, options?: {
    registry_id?: number;
    cert_type?: number;
}): Promise<string>;
export declare function getNullifierFromDisclosureProof(proofData: ProofData): bigint;
export declare function getParameterCommitmentFromDisclosureProof(proofData: ProofData): bigint;
export declare function getServiceSubScopeFromDisclosureProof(proofData: ProofData): bigint;
export declare function getServiceScopeFromDisclosureProof(proofData: ProofData): bigint;
export declare function getCommitmentInFromDisclosureProof(proofData: ProofData): bigint;
export declare function getHostedPackagedCircuitByNameAndHash(name: string, vkeyHash: string): Promise<PackagedCircuit>;
export declare function getHostedPackagedCircuitByVkeyHash(vkeyHash: string): Promise<PackagedCircuit>;
export declare function getHostedPackagedCircuitByName(version: `${number}.${number}.${number}`, name: string): Promise<PackagedCircuit>;
/**
 * Get the number of public inputs for a circuit.
 * @param circuitName - The name of the circuit.
 * @returns The number of public inputs.
 */
export declare function getNumberOfPublicInputs(circuitName: string): number;
export declare function getCommittedInputCount(circuitName: DisclosureCircuitName): 11 | 25 | 181 | 601 | 201;
export declare function getFormattedDate(date: Date): string;
export declare function getDateBytes(date: Date): Binary;
export declare function getCurrentDateFromCommittedInputs(committedInputs: DateCommittedInputs | AgeCommittedInputs): Date;
export declare const DEFAULT_DATE_VALUE: Date;
export declare enum ProofType {
    DISCLOSE = 0,
    AGE = 1,
    BIRTHDATE = 2,
    EXPIRY_DATE = 3,
    NATIONALITY_INCLUSION = 4,
    NATIONALITY_EXCLUSION = 5,
    ISSUING_COUNTRY_INCLUSION = 6,
    ISSUING_COUNTRY_EXCLUSION = 7
}
export { DisclosedData, createDisclosedDataRaw, formatName, parseDocumentType, getDisclosedBytesFromMrzAndMask, getDiscloseParameterCommitment, getDiscloseEVMParameterCommitment, } from "./disclose";
export * from "./country";
export * from "./age";
export * from "./date";
export * from "./integrity";
export * from "./id-data";
export * from "./dsc";
export * from "./vkey";
