export declare function generateECDHKeyPair(): Promise<{
    privateKey: import("@noble/secp256k1").Bytes;
    publicKey: import("@noble/secp256k1").Bytes;
}>;
export declare function getSharedSecret(privateKey: string, publicKey: string): Promise<Uint8Array<ArrayBuffer>>;
export declare function encrypt(message: string, sharedSecret: Uint8Array, topic: string): Promise<Uint8Array<ArrayBufferLike>>;
export declare function decrypt(ciphertext: Uint8Array, sharedSecret: Uint8Array, topic: string): Promise<string>;
