import { ProofData } from ".";
interface DisclosedDataRaw {
    issuingCountry: Uint8Array;
    nationality: Uint8Array;
    documentType: Uint8Array;
    documentNumber: Uint8Array;
    dateOfExpiry: Uint8Array;
    dateOfBirth: Uint8Array;
    name: Uint8Array;
    gender: Uint8Array;
}
/**
 * Get rid of the chevrons and replace them with spaces
 * Also remove all other non roman characters and replace
 * characters with diacritics with their base character
 * @param name
 */
export declare function formatName(name: string): string;
export declare function parseDocumentType(documentType: string): string;
export declare function getDisclosedBytesFromMrzAndMask(mrz: string, mask: number[]): number[];
export declare class DisclosedData {
    readonly issuingCountry: string;
    readonly nationality: string;
    readonly documentType: string;
    readonly documentNumber: string;
    readonly dateOfExpiry: Date;
    readonly dateOfBirth: Date;
    readonly name: string;
    readonly firstName: string;
    readonly lastName: string;
    readonly gender: string;
    constructor(data: {
        issuingCountry: string;
        nationality: string;
        documentType: string;
        documentNumber: string;
        dateOfExpiry: Date;
        dateOfBirth: Date;
        name: string;
        firstName: string;
        lastName: string;
        gender: string;
    });
    static fromDisclosedBytes(disclosedBytes: number[], idType: "passport" | "id_card"): DisclosedData;
    static fromFlagsProof(proof: ProofData): DisclosedData;
    static fromBytesProof(proof: ProofData, idType: "passport" | "id_card"): DisclosedData;
}
export declare function parseDate(bytes: Uint8Array): Date;
export declare function createDisclosedDataRaw(data: {
    issuingCountry: Uint8Array | string;
    nationality: Uint8Array | string;
    documentType: Uint8Array | string;
    documentNumber: Uint8Array | string;
    dateOfExpiry: Uint8Array | string | Date;
    dateOfBirth: Uint8Array | string | Date;
    name: Uint8Array | string;
    gender: Uint8Array | string;
}): DisclosedDataRaw;
/**
 * Get the number of public inputs for the disclose bytes proof.
 * @returns The number of public inputs.
 */
export declare function getDiscloseBytesProofPublicInputCount(): number;
/**
 * Get the number of public inputs for the disclose flags proof.
 * @returns The number of public inputs.
 */
export declare function getDiscloseFlagsProofPublicInputCount(): number;
/**
 * Get the parameter commitment for the disclose proof.
 * @param discloseMask - The disclose mask.
 * @param disclosedBytes - The disclosed bytes.
 * @returns The parameter commitment.
 */
export declare function getDiscloseParameterCommitment(discloseMask: number[], disclosedBytes: number[]): Promise<bigint>;
/**
 * Get the EVM parameter commitment for the disclose proof.
 * @param discloseMask - The disclose mask.
 * @param disclosedBytes - The disclosed bytes.
 * @returns The parameter commitment.
 */
export declare function getDiscloseEVMParameterCommitment(discloseMask: number[], disclosedBytes: number[]): Promise<bigint>;
export {};
