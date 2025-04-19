import { gcm } from "@noble/ciphers/aes";
import { utf8ToBytes } from "@noble/ciphers/utils";
async function sha256Truncate(topic) {
    const encoder = new TextEncoder();
    const data = encoder.encode(topic);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const fullHashArray = new Uint8Array(hashBuffer);
    const truncatedHashArray = fullHashArray.slice(0, 12);
    return truncatedHashArray;
}
export async function generateECDHKeyPair() {
    const secp256k1 = await import("@noble/secp256k1");
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.getPublicKey(privKey);
    return {
        privateKey: privKey,
        publicKey: pubKey,
    };
}
export async function getSharedSecret(privateKey, publicKey) {
    const secp256k1 = await import("@noble/secp256k1");
    const sharedSecret = secp256k1.getSharedSecret(privateKey, publicKey);
    return sharedSecret.slice(0, 32);
}
export async function encrypt(message, sharedSecret, topic) {
    // Nonce must be 12 bytes
    const nonce = await sha256Truncate(topic);
    const aes = gcm(sharedSecret, nonce);
    const data = utf8ToBytes(message);
    const ciphertext = aes.encrypt(data);
    return ciphertext;
}
export async function decrypt(ciphertext, sharedSecret, topic) {
    // Nonce must be 12 bytes
    const nonce = await sha256Truncate(topic);
    const aes = gcm(sharedSecret, nonce);
    const data = aes.decrypt(ciphertext);
    const dataString = new TextDecoder().decode(data);
    return dataString;
}
