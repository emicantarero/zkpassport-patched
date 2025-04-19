import { Binary } from "../binary";
import type { DigestAlgorithm, SignatureAlgorithm } from "../cms/types";
export declare class DataGroupHashValues {
    values: {
        [key: number]: Binary;
    };
    constructor(values: {
        [key: number]: Binary;
    });
}
export type SODSignedData = {
    version: number;
    digestAlgorithms: DigestAlgorithm[];
    encapContentInfo: {
        eContentType: string;
        eContent: {
            version: number;
            hashAlgorithm: DigestAlgorithm;
            dataGroupHashValues: DataGroupHashValues;
            bytes: Binary;
        };
    };
    signerInfo: {
        version: number;
        signedAttrs: {
            contentType: string;
            messageDigest: Binary;
            signingTime?: Date;
            bytes: Binary;
        };
        digestAlgorithm: DigestAlgorithm;
        signatureAlgorithm: {
            name: SignatureAlgorithm;
            parameters?: Binary;
        };
        signature: Binary;
        sid: {
            issuerAndSerialNumber?: {
                issuer: string;
                serialNumber: Binary;
            };
            subjectKeyIdentifier?: string;
        };
    };
    certificate: {
        tbs: {
            version: number;
            serialNumber: Binary;
            signatureAlgorithm: {
                name: SignatureAlgorithm;
                parameters?: Binary;
            };
            issuer: string;
            validity: {
                notBefore: Date;
                notAfter: Date;
            };
            subject: string;
            subjectPublicKeyInfo: {
                signatureAlgorithm: {
                    name: SignatureAlgorithm;
                    parameters?: Binary;
                };
                subjectPublicKey: Binary;
            };
            extensions: Map<string, {
                critical?: boolean;
                value: Binary;
            }>;
            issuerUniqueID?: Binary;
            subjectUniqueID?: Binary;
            bytes: Binary;
        };
        signatureAlgorithm: {
            name: SignatureAlgorithm;
            parameters?: Binary;
        };
        signature: Binary;
    };
    bytes: Binary;
};
export declare class SOD implements SODSignedData {
    version: number;
    digestAlgorithms: DigestAlgorithm[];
    encapContentInfo: {
        eContentType: string;
        eContent: {
            version: number;
            hashAlgorithm: DigestAlgorithm;
            dataGroupHashValues: DataGroupHashValues;
            bytes: Binary;
        };
    };
    signerInfo: {
        version: number;
        signedAttrs: {
            contentType: string;
            messageDigest: Binary;
            signingTime?: Date;
            bytes: Binary;
        };
        digestAlgorithm: DigestAlgorithm;
        signatureAlgorithm: {
            name: SignatureAlgorithm;
            parameters?: Binary;
        };
        signature: Binary;
        sid: {
            issuerAndSerialNumber?: {
                issuer: string;
                serialNumber: Binary;
            };
            subjectKeyIdentifier?: string;
        };
    };
    certificate: {
        tbs: {
            version: number;
            serialNumber: Binary;
            signatureAlgorithm: {
                name: SignatureAlgorithm;
                parameters?: Binary;
            };
            issuer: string;
            validity: {
                notBefore: Date;
                notAfter: Date;
            };
            subject: string;
            subjectPublicKeyInfo: {
                signatureAlgorithm: {
                    name: SignatureAlgorithm;
                    parameters?: Binary;
                };
                subjectPublicKey: Binary;
            };
            extensions: Map<string, {
                critical?: boolean;
                value: Binary;
            }>;
            issuerUniqueID?: Binary;
            subjectUniqueID?: Binary;
            bytes: Binary;
        };
        signatureAlgorithm: {
            name: SignatureAlgorithm;
            parameters?: Binary;
        };
        signature: Binary;
    };
    bytes: Binary;
    constructor(sod: SODSignedData);
    static fromDER(der: Binary): SOD;
}
