// Conditionally import crypto in Node.js environment
if (typeof window === "undefined") {
    try {
        const nodeCrypto = require("crypto");
        crypto = nodeCrypto;
    }
    catch { }
}
import { AsnParser } from "@peculiar/asn1-schema";
import { RSAPublicKey } from "@peculiar/asn1-rsa";
import { fromArrayBufferToBigInt } from "./utils.js";
/**
 * Generates an RSA key pair.
 * @param keySize - The size of the key in bits (default is 2048).
 * @returns An object containing the private and public keys.
 * @throws Error if crypto is not available
 */
export function generateRSAKeyPair(keySize = 2048) {
    if (!crypto) {
        throw new Error("Crypto functionality is not available in this environment");
    }
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: keySize, // Key size in bits
        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
        },
        publicKeyEncoding: {
            type: "pkcs1",
            format: "der",
        },
    });
    return { privateKey, publicKey: publicKey };
}
export function getRSAPublicKeyParams(publicKey) {
    const parsedKey = AsnParser.parse(publicKey, RSAPublicKey);
    return {
        modulus: fromArrayBufferToBigInt(parsedKey.modulus),
        exponent: Number(fromArrayBufferToBigInt(parsedKey.publicExponent)),
    };
}
/**
 * Signs data using the provided private key.
 * @param privateKey - The private key to sign the data.
 * @param data - The data to be signed.
 * @param hashAlgorithm - The hashing algorithm to use (default is 'SHA256').
 * @returns The binary signature as a Buffer.
 * @throws Error if crypto is not available
 */
export function signData(privateKey, data, hashAlgorithm = "RSA-SHA256") {
    if (!crypto) {
        throw new Error("Crypto functionality is not available in this environment");
    }
    const sign = crypto.createSign(hashAlgorithm);
    sign.update(data);
    const signature = sign.sign(privateKey);
    return signature;
}
/**
 * Verifies a signature against the provided data and public key.
 * @param publicKey - The public key to verify the signature.
 * @param data - The original data that was signed.
 * @param signature - The signature to verify.
 * @param hashAlgorithm - The hashing algorithm to use (default is 'SHA256').
 * @returns true if the signature is valid, false otherwise.
 * @throws Error if crypto is not available
 */
export function verifySignature(publicKey, data, signature, hashAlgorithm = "SHA256") {
    if (!crypto) {
        throw new Error("Crypto functionality is not available in this environment");
    }
    const verify = crypto.createVerify(hashAlgorithm);
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature);
}
