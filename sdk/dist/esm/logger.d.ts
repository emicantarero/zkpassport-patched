export declare const customLogger: {
    debug: (message: string, ...args: any[]) => void;
    info: (message: string, ...args: any[]) => void;
    warn: (message: string, ...args: any[]) => void;
    error: (message: string, ...args: any[]) => void;
};
export declare const noLogger: {
    debug: (..._: any[]) => void;
    info: (..._: any[]) => void;
    warn: (..._: any[]) => void;
    error: (..._: any[]) => void;
};
