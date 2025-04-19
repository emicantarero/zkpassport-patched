import { ECParameters } from "@peculiar/asn1-ecc";
import { AlgorithmIdentifier, SubjectPublicKeyInfo, Certificate as X509Certificate } from "@peculiar/asn1-x509";
import type { DigestAlgorithm } from "./types";
import { CurveName } from "@/types";
export declare function getAbbreviatedCurveName(ecParams: ECParameters): string;
export declare function getCurveName(ecParams: ECParameters): CurveName;
export declare function getAuthorityKeyId(cert: X509Certificate): string | undefined;
export declare function getSubjectKeyId(cert: X509Certificate): string | undefined;
export declare function getPrivateKeyUsagePeriod(cert: X509Certificate): {
    not_before?: number;
    not_after?: number;
} | undefined;
export declare function getECDSAInfo(subjectPublicKeyInfo: SubjectPublicKeyInfo): {
    curve: CurveName;
    publicKey: Uint8Array;
    keySize: number;
};
export declare function getRSAPSSParams(signatureAlgorithm: AlgorithmIdentifier): {
    hashAlgorithm: DigestAlgorithm;
    saltLength: number;
    maskGenAlgorithm: string;
};
export declare function getRSAInfo(subjectPublicKeyInfo: SubjectPublicKeyInfo): {
    modulus: bigint;
    exponent: bigint;
    type: "pkcs" | "pss";
};
export declare function getSigningKeyType(cert: X509Certificate): string;
export declare function getSignatureAlgorithmType(signatureAlgorithm: string): "RSA" | "ECDSA" | "";
export declare function getBitSizeFromCurve(curve: string): number;
export declare function getCertificateIssuer(cert: X509Certificate): string | undefined;
export declare function getCertificateSubject(cert: X509Certificate): string | undefined;
export declare function getCertificateIssuerCountry(cert: X509Certificate): string | undefined;
export declare function formatAbbreviatedDN(issuer: any[]): string;
export declare function derToPem(der: Uint8Array): string;
export declare const CURVE_TO_KEYSIZE: Record<CurveName, number>;
export declare function getKeySizeFromCurve(curve: CurveName): number;
