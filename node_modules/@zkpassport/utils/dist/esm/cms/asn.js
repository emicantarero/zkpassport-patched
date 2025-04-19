var AttributeSet_1;
import { __decorate } from "tslib";
import { Attribute, DigestAlgorithmIdentifier } from "@peculiar/asn1-cms";
import { AsnArray, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema";
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
let AttributeSet = AttributeSet_1 = class AttributeSet extends AsnArray {
    constructor(items) {
        super(items);
        Object.setPrototypeOf(this, AttributeSet_1.prototype);
    }
};
AttributeSet = AttributeSet_1 = __decorate([
    AsnType({ type: AsnTypeTypes.Set, itemType: Attribute })
], AttributeSet);
export { AttributeSet };
/**
 * ```asn
 * DataGroupNumber ::= INTEGER
 * ```
 */
export var DataGroupNumber;
(function (DataGroupNumber) {
    DataGroupNumber[DataGroupNumber["dataGroup1"] = 1] = "dataGroup1";
    DataGroupNumber[DataGroupNumber["dataGroup2"] = 2] = "dataGroup2";
    DataGroupNumber[DataGroupNumber["dataGroup3"] = 3] = "dataGroup3";
    DataGroupNumber[DataGroupNumber["dataGroup4"] = 4] = "dataGroup4";
    DataGroupNumber[DataGroupNumber["dataGroup5"] = 5] = "dataGroup5";
    DataGroupNumber[DataGroupNumber["dataGroup6"] = 6] = "dataGroup6";
    DataGroupNumber[DataGroupNumber["dataGroup7"] = 7] = "dataGroup7";
    DataGroupNumber[DataGroupNumber["dataGroup8"] = 8] = "dataGroup8";
    DataGroupNumber[DataGroupNumber["dataGroup9"] = 9] = "dataGroup9";
    DataGroupNumber[DataGroupNumber["dataGroup10"] = 10] = "dataGroup10";
    DataGroupNumber[DataGroupNumber["dataGroup11"] = 11] = "dataGroup11";
    DataGroupNumber[DataGroupNumber["dataGroup12"] = 12] = "dataGroup12";
    DataGroupNumber[DataGroupNumber["dataGroup13"] = 13] = "dataGroup13";
    DataGroupNumber[DataGroupNumber["dataGroup14"] = 14] = "dataGroup14";
    DataGroupNumber[DataGroupNumber["dataGroup15"] = 15] = "dataGroup15";
    DataGroupNumber[DataGroupNumber["dataGroup16"] = 16] = "dataGroup16";
})(DataGroupNumber || (DataGroupNumber = {}));
/**
 * ```asn
 * DataGroupHash ::= SEQUENCE {
 *  dataGroupNumber DataGroupNumber,
 *  dataGroupHashValue OCTET STRING }
 * ```
 */
export class DataGroupHash {
    constructor(params = {}) {
        this.number = DataGroupNumber.dataGroup1;
        this.hash = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], DataGroupHash.prototype, "number", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.OctetString })
], DataGroupHash.prototype, "hash", void 0);
/**
 * ```asn
 * LDSSecurityObjectVersion ::= INTEGER  { v0(0), v1(1) }
 * ```
 */
export var LDSSecurityObjectVersion;
(function (LDSSecurityObjectVersion) {
    LDSSecurityObjectVersion[LDSSecurityObjectVersion["v0"] = 0] = "v0";
    LDSSecurityObjectVersion[LDSSecurityObjectVersion["v1"] = 1] = "v1";
    LDSSecurityObjectVersion[LDSSecurityObjectVersion["v2"] = 2] = "v2";
})(LDSSecurityObjectVersion || (LDSSecurityObjectVersion = {}));
/**
 * ```asn
 * LDSVersionInfo ::= SEQUENCE {
 *  ldsVersion PrintableString,
 *  unicodeVersion PrintableString }
 * ```
 */
export class LDSVersionInfo {
    constructor(params = {}) {
        this.ldsVersion = "";
        this.unicodeVersion = "";
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.PrintableString })
], LDSVersionInfo.prototype, "ldsVersion", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.PrintableString })
], LDSVersionInfo.prototype, "unicodeVersion", void 0);
/**
 * ```asn
 * LDSSecurityObjectIdentifier ::= OBJECT IDENTIFIER
 * ```
 */
let LDSSecurityObjectIdentifier = class LDSSecurityObjectIdentifier {
    constructor(value) {
        this.value = "";
        if (value) {
            if (typeof value === "string") {
                this.value = value;
            }
            else {
                Object.assign(this, value);
            }
        }
    }
};
__decorate([
    AsnProp({ type: AsnPropTypes.ObjectIdentifier })
], LDSSecurityObjectIdentifier.prototype, "value", void 0);
LDSSecurityObjectIdentifier = __decorate([
    AsnType({ type: AsnTypeTypes.Choice })
], LDSSecurityObjectIdentifier);
export { LDSSecurityObjectIdentifier };
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
export class LDSSecurityObject {
    constructor(params = {}) {
        this.version = LDSSecurityObjectVersion.v1;
        this.hashAlgorithm = new DigestAlgorithmIdentifier();
        this.dataGroups = [];
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], LDSSecurityObject.prototype, "version", void 0);
__decorate([
    AsnProp({ type: DigestAlgorithmIdentifier })
], LDSSecurityObject.prototype, "hashAlgorithm", void 0);
__decorate([
    AsnProp({ type: DataGroupHash, repeated: "sequence" })
], LDSSecurityObject.prototype, "dataGroups", void 0);
__decorate([
    AsnProp({ type: LDSVersionInfo, optional: true })
], LDSSecurityObject.prototype, "versionInfo", void 0);
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
let MasterList = class MasterList {
    constructor(params = {}) {
        this.version = 0;
        this.certificates = [];
        Object.assign(this, params);
    }
};
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], MasterList.prototype, "version", void 0);
__decorate([
    AsnProp({ type: X509Certificate, repeated: "set" })
], MasterList.prototype, "certificates", void 0);
MasterList = __decorate([
    AsnType({ type: AsnTypeTypes.Sequence })
], MasterList);
export { MasterList };
export const id_ldsSecurityObject = "2.23.136.1.1.1";
export const id_sha256 = "2.16.840.1.101.3.4.2.1";
export const id_icao_cscaMasterList = "2.23.136.1.1.2";
export const id_signingTime = "1.2.840.113549.1.9.5";
