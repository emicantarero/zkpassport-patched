"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createJsonRpcRequest = createJsonRpcRequest;
exports.createEncryptedJsonRpcRequest = createEncryptedJsonRpcRequest;
exports.sendEncryptedJsonRpcRequest = sendEncryptedJsonRpcRequest;
exports.createJsonRpcResponse = createJsonRpcResponse;
const crypto_1 = require("crypto");
const encryption_1 = require("./encryption");
const logger_1 = require("./logger");
function createJsonRpcRequest(method, params) {
    return {
        jsonrpc: "2.0",
        id: (0, crypto_1.randomBytes)(16).toString("hex"),
        method,
        params,
    };
}
async function createEncryptedJsonRpcRequest(method, params, sharedSecret, topic) {
    const encryptedMessage = await (0, encryption_1.encrypt)(JSON.stringify({ method, params: params || {} }), sharedSecret, topic);
    return createJsonRpcRequest("encryptedMessage", {
        payload: Buffer.from(encryptedMessage).toString("base64"),
    });
}
async function sendEncryptedJsonRpcRequest(method, params, sharedSecret, topic, wsClient) {
    try {
        const message = { method, params: params || {} };
        const encryptedMessage = await (0, encryption_1.encrypt)(JSON.stringify(message), sharedSecret, topic);
        const request = createJsonRpcRequest("encryptedMessage", {
            payload: Buffer.from(encryptedMessage).toString("base64"),
        });
        logger_1.noLogger.debug("Sending encrypted message (original):", message);
        logger_1.noLogger.debug("Sending encrypted message (encrypted):", request);
        wsClient.send(JSON.stringify(request));
        return true;
    }
    catch (error) {
        logger_1.noLogger.error("Error sending encrypted message:", error);
        return false;
    }
}
function createJsonRpcResponse(id, result) {
    return {
        jsonrpc: "2.0",
        id,
        result,
    };
}
