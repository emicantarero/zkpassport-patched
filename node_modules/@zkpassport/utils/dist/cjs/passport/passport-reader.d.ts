import { SignedData } from "@peculiar/asn1-cms";
import { TBSCertificate } from "@peculiar/asn1-x509";
import { Binary } from "../binary";
import type { DigestAlgorithm } from "../cms/types";
import { PassportViewModel } from "../types";
import { SOD } from "./sod";
export declare class PassportReader {
    dg1?: Binary;
    sod?: SOD;
    getPassportViewModel(): PassportViewModel;
    loadPassport(dg1: Binary, sod: Binary): void;
}
export declare function getSODContent(passport: PassportViewModel): SignedData;
export declare function getEContentHashAlgorithm(passport: PassportViewModel): string;
export declare function getEContent(passport: PassportViewModel): number[];
export declare function getSignedAttributesHashingAlgorithm(passport: PassportViewModel): string;
export declare function getSODCMSVersion(passport: PassportViewModel): string;
export declare function extractTBS(passport: PassportViewModel): TBSCertificate | null;
export declare function getSodSignatureAlgorithmType(passport: PassportViewModel): "RSA" | "ECDSA" | "";
export declare function getSodSignatureHashAlgorithm(passport: PassportViewModel): DigestAlgorithm | undefined;
export declare function getDSCSignatureAlgorithmType(passport: PassportViewModel): "RSA" | "ECDSA" | "";
export declare function getDSCSignatureHashAlgorithm(passport: PassportViewModel): DigestAlgorithm | undefined;
