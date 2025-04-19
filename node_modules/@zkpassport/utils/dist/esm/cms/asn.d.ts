import { Attribute, DigestAlgorithmIdentifier } from "@peculiar/asn1-cms";
import { AsnArray } from "@peculiar/asn1-schema";
import { Certificate as X509Certificate } from "@peculiar/asn1-x509";
export { Attribute, ContentInfo, DigestAlgorithmIdentifier, EncapsulatedContent, SignedData, SignerIdentifier, SignerInfo, } from "@peculiar/asn1-cms";
export { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
export { SubjectPublicKeyInfo, Certificate as X509Certificate, Time } from "@peculiar/asn1-x509";
export { ECParameters } from "@peculiar/asn1-ecc";
/**
 * ```asn
 * AttributeSet ::= SET OF Attribute
 * ```
 */
export declare class AttributeSet extends AsnArray<Attribute> {
    constructor(items?: Attribute[]);
}
/**
 * ```asn
 * DataGroupNumber ::= INTEGER
 * ```
 */
export declare enum DataGroupNumber {
    dataGroup1 = 1,
    dataGroup2 = 2,
    dataGroup3 = 3,
    dataGroup4 = 4,
    dataGroup5 = 5,
    dataGroup6 = 6,
    dataGroup7 = 7,
    dataGroup8 = 8,
    dataGroup9 = 9,
    dataGroup10 = 10,
    dataGroup11 = 11,
    dataGroup12 = 12,
    dataGroup13 = 13,
    dataGroup14 = 14,
    dataGroup15 = 15,
    dataGroup16 = 16
}
/**
 * ```asn
 * DataGroupHash ::= SEQUENCE {
 *  dataGroupNumber DataGroupNumber,
 *  dataGroupHashValue OCTET STRING }
 * ```
 */
export declare class DataGroupHash {
    number: DataGroupNumber;
    hash: ArrayBuffer;
    constructor(params?: Partial<DataGroupHash>);
}
/**
 * ```asn
 * LDSSecurityObjectVersion ::= INTEGER  { v0(0), v1(1) }
 * ```
 */
export declare enum LDSSecurityObjectVersion {
    v0 = 0,
    v1 = 1,
    v2 = 2
}
/**
 * ```asn
 * LDSVersionInfo ::= SEQUENCE {
 *  ldsVersion PrintableString,
 *  unicodeVersion PrintableString }
 * ```
 */
export declare class LDSVersionInfo {
    ldsVersion: string;
    unicodeVersion: string;
    constructor(params?: Partial<LDSVersionInfo>);
}
/**
 * ```asn
 * LDSSecurityObjectIdentifier ::= OBJECT IDENTIFIER
 * ```
 */
export declare class LDSSecurityObjectIdentifier {
    value: string;
    constructor(value?: string);
}
/**
 * This is for parsing the ASN of signedData.encapContentInfo.eContent
 *
 * ```asn
 * LDSSecurityObject ::= SEQUENCE {
 *  version LDSSecurityObjectVersion,
 *  hashAlgorithm DigestAlgorithmIdentifier,
 *  dataGroupHashValues SEQUENCE SIZE (2..ub-DataGroups) OF DataGroupHash,
 *  ldsVersionInfo LDSVersionInfo OPTIONAL -- If present, version MUST be V1
 * }
 * ```
 */
export declare class LDSSecurityObject {
    version: LDSSecurityObjectVersion;
    hashAlgorithm: DigestAlgorithmIdentifier;
    dataGroups: DataGroupHash[];
    versionInfo?: LDSVersionInfo;
    constructor(params?: Partial<LDSSecurityObject>);
}
/**
 * ICAO Master List structure
 *
 * ```asn
 * MasterList ::= SEQUENCE {
 *   version INTEGER,
 *   certificates SET OF Certificate
 * }
 * ```
 */
export declare class MasterList {
    version: number;
    certificates: X509Certificate[];
    constructor(params?: Partial<MasterList>);
}
export declare const id_ldsSecurityObject = "2.23.136.1.1.1";
export declare const id_sha256 = "2.16.840.1.101.3.4.2.1";
export declare const id_icao_cscaMasterList = "2.23.136.1.1.2";
export declare const id_signingTime = "1.2.840.113549.1.9.5";
