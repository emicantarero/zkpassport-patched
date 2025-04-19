"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateRSAKeyPair = generateRSAKeyPair;
exports.getRSAPublicKeyParams = getRSAPublicKeyParams;
exports.signData = signData;
exports.verifySignature = verifySignature;
// Conditionally import crypto in Node.js environment
if (typeof window === "undefined") {
    try {
        const nodeCrypto = require("crypto");
        crypto = nodeCrypto;
    }
    catch { }
}
const asn1_schema_1 = require("@peculiar/asn1-schema");
const asn1_rsa_1 = require("@peculiar/asn1-rsa");
const utils_1 = require("./utils");
/**
 * Generates an RSA key pair.
 * @param keySize - The size of the key in bits (default is 2048).
 * @returns An object containing the private and public keys.
 * @throws Error if crypto is not available
 */
function generateRSAKeyPair(keySize = 2048) {
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
function getRSAPublicKeyParams(publicKey) {
    const parsedKey = asn1_schema_1.AsnParser.parse(publicKey, asn1_rsa_1.RSAPublicKey);
    return {
        modulus: (0, utils_1.fromArrayBufferToBigInt)(parsedKey.modulus),
        exponent: Number((0, utils_1.fromArrayBufferToBigInt)(parsedKey.publicExponent)),
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
function signData(privateKey, data, hashAlgorithm = "RSA-SHA256") {
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
function verifySignature(publicKey, data, signature, hashAlgorithm = "SHA256") {
    if (!crypto) {
        throw new Error("Crypto functionality is not available in this environment");
    }
    const verify = crypto.createVerify(hashAlgorithm);
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature);
}
