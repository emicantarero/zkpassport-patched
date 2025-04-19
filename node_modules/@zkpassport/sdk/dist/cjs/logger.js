"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.noLogger = exports.customLogger = void 0;
exports.customLogger = {
    debug: (message, ...args) => console.debug(message, ...args),
    info: (message, ...args) => console.info(message, ...args),
    warn: (message, ...args) => console.warn(message, ...args),
    error: (message, ...args) => console.error(message, ...args),
};
exports.noLogger = {
    debug: (..._) => { },
    info: (..._) => { },
    warn: (..._) => { },
    error: (..._) => { },
};
