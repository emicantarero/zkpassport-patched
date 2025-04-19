export const customLogger = {
    debug: (message, ...args) => console.debug(message, ...args),
    info: (message, ...args) => console.info(message, ...args),
    warn: (message, ...args) => console.warn(message, ...args),
    error: (message, ...args) => console.error(message, ...args),
};
export const noLogger = {
    debug: (..._) => { },
    info: (..._) => { },
    warn: (..._) => { },
    error: (..._) => { },
};
