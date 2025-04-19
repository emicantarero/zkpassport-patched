import { randomBytes } from "crypto";
import { encrypt } from "./encryption.js";
import { noLogger as logger } from "./logger.js";
export function createJsonRpcRequest(method, params) {
    return {
        jsonrpc: "2.0",
        id: randomBytes(16).toString("hex"),
        method,
        params,
    };
}
export async function createEncryptedJsonRpcRequest(method, params, sharedSecret, topic) {
    const encryptedMessage = await encrypt(JSON.stringify({ method, params: params || {} }), sharedSecret, topic);
    return createJsonRpcRequest("encryptedMessage", {
        payload: Buffer.from(encryptedMessage).toString("base64"),
    });
}
export async function sendEncryptedJsonRpcRequest(method, params, sharedSecret, topic, wsClient) {
    try {
        const message = { method, params: params || {} };
        const encryptedMessage = await encrypt(JSON.stringify(message), sharedSecret, topic);
        const request = createJsonRpcRequest("encryptedMessage", {
            payload: Buffer.from(encryptedMessage).toString("base64"),
        });
        logger.debug("Sending encrypted message (original):", message);
        logger.debug("Sending encrypted message (encrypted):", request);
        wsClient.send(JSON.stringify(request));
        return true;
    }
    catch (error) {
        logger.error("Error sending encrypted message:", error);
        return false;
    }
}
export function createJsonRpcResponse(id, result) {
    return {
        jsonrpc: "2.0",
        id,
        result,
    };
}
