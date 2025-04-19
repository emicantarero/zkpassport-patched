/**
 * Convert a proof in hex format to an array of fields.
 * @param proof - The proof to convert.
 * @returns An array of fields.
 */
export declare function proofToFields(proof: Buffer, startIndex?: number): string[];
/**
 * Get the number of public inputs from a proof.
 * @param proofAsFields - The proof as an array of fields.
 * @returns The number of public inputs.
 */
export declare function getNumberOfPublicInputsFromProof(proofAsFields: string[]): number;
/**
 * Get the public inputs from a proof.
 * @param proofAsFields - The proof as an array of fields.
 * @param publicInputsNumber - The number of public inputs.
 * @returns The public inputs.
 */
export declare function getPublicInputs(proofAsFields: string[], publicInputsNumber: number): string[];
/**
 * Get the proof without the public inputs.
 * @param proofAsFields - The proof as an array of fields.
 * @param publicInputsNumber - The number of public inputs.
 * @returns The proof without the public inputs.
 */
export declare function getProofWithoutPublicInputs(proofAsFields: string[], publicInputsNumber: number): string[];
/**
 * Get the proof data from a proof.
 * @param proof - The proof to get the data from.
 * @param publicInputsNumber - The number of public inputs.
 * @param proofStartIndex - The start index of the proof (i.e. how many bytes to skip at the start when parsing it)
 * @returns The proof data.
 */
export declare function getProofData(proof: string, publicInputsNumber: number, proofStartIndex?: number): {
    proof: string[];
    publicInputs: string[];
};
