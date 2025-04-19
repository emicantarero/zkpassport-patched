/**
 * Generates an RSA key pair.
 * @param keySize - The size of the key in bits (default is 2048).
 * @returns An object containing the private and public keys.
 * @throws Error if crypto is not available
 */
export declare function generateRSAKeyPair(keySize?: number): {
    privateKey: string;
    publicKey: Buffer;
};
export declare function getRSAPublicKeyParams(publicKey: Buffer): {
    modulus: bigint;
    exponent: number;
};
/**
 * Signs data using the provided private key.
 * @param privateKey - The private key to sign the data.
 * @param data - The data to be signed.
 * @param hashAlgorithm - The hashing algorithm to use (default is 'SHA256').
 * @returns The binary signature as a Buffer.
 * @throws Error if crypto is not available
 */
export declare function signData(privateKey: string | Buffer, data: string | Buffer, hashAlgorithm?: string): Buffer;
/**
 * Verifies a signature against the provided data and public key.
 * @param publicKey - The public key to verify the signature.
 * @param data - The original data that was signed.
 * @param signature - The signature to verify.
 * @param hashAlgorithm - The hashing algorithm to use (default is 'SHA256').
 * @returns true if the signature is valid, false otherwise.
 * @throws Error if crypto is not available
 */
export declare function verifySignature(publicKey: string, data: string, signature: Buffer, hashAlgorithm?: string): boolean;
