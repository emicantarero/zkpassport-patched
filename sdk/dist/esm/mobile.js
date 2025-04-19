import { bytesToHex } from "@noble/ciphers/utils";
import { getWebSocketClient } from "./websocket";
import { sendEncryptedJsonRpcRequest } from "./json-rpc";
import { decrypt, generateECDHKeyPair, getSharedSecret } from "./encryption";
import { noLogger as logger } from "./logger";
export class ZkPassportProver {
    constructor() {
        this.topicToKeyPair = {};
        this.topicToWebSocketClient = {};
        this.topicToRemoteDomainVerified = {};
        this.topicToSharedSecret = {};
        this.topicToRemotePublicKey = {};
        this.onDomainVerifiedCallbacks = {};
        this.onBridgeConnectCallbacks = {};
        this.onWebsiteDomainVerifyFailureCallbacks = {};
    }
    /**
     * @notice Handle an encrypted message.
     * @param request The request.
     * @param outerRequest The outer request.
     */
    async handleEncryptedMessage(topic, request, outerRequest) {
        logger.debug("Received encrypted message:", request);
        if (request.method === "hello") {
            logger.info(`Successfully verified origin domain name: ${outerRequest.origin}`);
            this.topicToRemoteDomainVerified[topic] = true;
            await Promise.all(this.onDomainVerifiedCallbacks[topic].map((callback) => callback()));
        }
        else if (request.method === "closed_page") {
            // TODO: Implement
        }
    }
    /**
     * @notice Scan a credentirequest QR code.
     * @returns
     */
    async scan(url, { keyPairOverride, } = {}) {
        const parsedUrl = new URL(url);
        const domain = parsedUrl.searchParams.get("d");
        const topic = parsedUrl.searchParams.get("t");
        const pubkeyHex = parsedUrl.searchParams.get("p");
        if (!domain || !topic || !pubkeyHex) {
            throw new Error("Invalid URL: missing required parameters");
        }
        const pubkey = new Uint8Array(Buffer.from(pubkeyHex, "hex"));
        this.domain = domain;
        const keyPair = keyPairOverride || (await generateECDHKeyPair());
        this.topicToKeyPair[topic] = {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
        };
        this.topicToRemotePublicKey[topic] = pubkey;
        this.topicToSharedSecret[topic] = await getSharedSecret(bytesToHex(keyPair.privateKey), bytesToHex(pubkey));
        this.topicToRemoteDomainVerified[topic] = false;
        this.onDomainVerifiedCallbacks[topic] = [];
        this.onBridgeConnectCallbacks[topic] = [];
        // Set up WebSocket connection
        const wsClient = getWebSocketClient(`wss://bridge.zkpassport.id?topic=${topic}&pubkey=${bytesToHex(keyPair.publicKey)}`);
        this.topicToWebSocketClient[topic] = wsClient;
        wsClient.onopen = async () => {
            logger.info("[mobile] WebSocket connection established");
            await Promise.all(this.onBridgeConnectCallbacks[topic].map((callback) => callback()));
            // Server sends handshake automatically (when it sees a pubkey in websocket URI)
            // wsClient.send(
            //   JSON.stringify(
            //     createJsonRpcRequest('handshake', {
            //       pubkey: bytesToHex(keyPair.publicKey),
            //     }),
            //   ),
            // )
        };
        wsClient.addEventListener("message", async (event) => {
            logger.info("[mobile] Received message:", event.data);
            try {
                const data = JSON.parse(event.data);
                const originDomain = data.origin ? new URL(data.origin).hostname : undefined;
                // Origin domain must match domain in QR code
                if (originDomain !== this.domain) {
                    logger.warn(`[mobile] Origin does not match domain in QR code. Expected ${this.domain} but got ${originDomain}`);
                    return;
                }
                if (data.method === "encryptedMessage") {
                    // Decode the payload from base64 to Uint8Array
                    const payload = new Uint8Array(atob(data.params.payload)
                        .split("")
                        .map((c) => c.charCodeAt(0)));
                    try {
                        // Decrypt the payload using the shared secret
                        const decrypted = await decrypt(payload, this.topicToSharedSecret[topic], topic);
                        const decryptedJson = JSON.parse(decrypted);
                        await this.handleEncryptedMessage(topic, decryptedJson, data);
                    }
                    catch (error) {
                        logger.error("[mobile] Error decrypting message:", error);
                    }
                }
            }
            catch (error) {
                logger.error("[mobile] Error:", error);
            }
        });
        wsClient.onerror = (error) => {
            logger.error("[mobile] WebSocket error:", error);
        };
        return {
            domain: this.domain,
            requestId: topic,
            isBridgeConnected: () => this.topicToWebSocketClient[topic].readyState === WebSocket.OPEN,
            isDomainVerified: () => this.topicToRemoteDomainVerified[topic] === true,
            onDomainVerified: (callback) => this.onDomainVerifiedCallbacks[topic].push(callback),
            onBridgeConnect: (callback) => this.onBridgeConnectCallbacks[topic].push(callback),
            notifyReject: async () => {
                await sendEncryptedJsonRpcRequest("reject", null, this.topicToSharedSecret[topic], topic, this.topicToWebSocketClient[topic]);
            },
            notifyAccept: async () => {
                await sendEncryptedJsonRpcRequest("accept", null, this.topicToSharedSecret[topic], topic, this.topicToWebSocketClient[topic]);
            },
            notifyDone: async (proof) => {
                await sendEncryptedJsonRpcRequest("done", { proof }, this.topicToSharedSecret[topic], topic, this.topicToWebSocketClient[topic]);
            },
            notifyError: async (error) => {
                await sendEncryptedJsonRpcRequest("error", { error }, this.topicToSharedSecret[topic], topic, this.topicToWebSocketClient[topic]);
            },
        };
    }
}
