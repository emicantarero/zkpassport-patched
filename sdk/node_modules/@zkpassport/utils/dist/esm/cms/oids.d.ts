type OidMapping = {
    [key: string]: {
        d: string;
        c: string;
        w?: boolean;
    };
};
export declare const oids: OidMapping;
export declare function getOIDName(oid: string): string;
export declare function getHashAlgorithmName(oid: string): string;
export declare function getSignatureAlgorithmName(oid: string): string;
export declare function decodeOID(bytes: number[]): string;
export {};
