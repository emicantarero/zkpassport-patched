"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateECDHKeyPair = generateECDHKeyPair;
exports.getSharedSecret = getSharedSecret;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
const aes_1 = require("@noble/ciphers/aes");
const utils_1 = require("@noble/ciphers/utils");
async function sha256Truncate(topic) {
    const encoder = new TextEncoder();
    const data = encoder.encode(topic);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const fullHashArray = new Uint8Array(hashBuffer);
    const truncatedHashArray = fullHashArray.slice(0, 12);
    return truncatedHashArray;
}
async function generateECDHKeyPair() {
    const secp256k1 = await Promise.resolve().then(() => __importStar(require("@noble/secp256k1")));
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.getPublicKey(privKey);
    return {
        privateKey: privKey,
        publicKey: pubKey,
    };
}
async function getSharedSecret(privateKey, publicKey) {
    const secp256k1 = await Promise.resolve().then(() => __importStar(require("@noble/secp256k1")));
    const sharedSecret = secp256k1.getSharedSecret(privateKey, publicKey);
    return sharedSecret.slice(0, 32);
}
async function encrypt(message, sharedSecret, topic) {
    // Nonce must be 12 bytes
    const nonce = await sha256Truncate(topic);
    const aes = (0, aes_1.gcm)(sharedSecret, nonce);
    const data = (0, utils_1.utf8ToBytes)(message);
    const ciphertext = aes.encrypt(data);
    return ciphertext;
}
async function decrypt(ciphertext, sharedSecret, topic) {
    // Nonce must be 12 bytes
    const nonce = await sha256Truncate(topic);
    const aes = (0, aes_1.gcm)(sharedSecret, nonce);
    const data = aes.decrypt(ciphertext);
    const dataString = new TextDecoder().decode(data);
    return dataString;
}
