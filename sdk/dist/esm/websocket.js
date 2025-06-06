export function getWebSocketClient(url, origin) {
    if (typeof window !== "undefined" && window.WebSocket) {
        // Browser environment
        return new WebSocket(url);
    }
    else {
        // Node.js environment
        const WebSocket = require("ws");
        return new WebSocket(url, {
            headers: {
                Origin: origin || "nodejs",
            },
        });
    }
}
