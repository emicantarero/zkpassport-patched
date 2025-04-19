"use strict";
var AttributeSet_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.id_signingTime = exports.id_icao_cscaMasterList = exports.id_sha256 = exports.id_ldsSecurityObject = exports.MasterList = exports.LDSSecurityObject = exports.LDSSecurityObjectIdentifier = exports.LDSVersionInfo = exports.LDSSecurityObjectVersion = exports.DataGroupHash = exports.DataGroupNumber = exports.AttributeSet = exports.ECParameters = exports.Time = exports.X509Certificate = exports.SubjectPublicKeyInfo = exports.AsnSerializer = exports.AsnParser = exports.SignerInfo = exports.SignerIdentifier = exports.SignedData = exports.EncapsulatedContent = exports.DigestAlgorithmIdentifier = exports.ContentInfo = exports.Attribute = void 0;
const tslib_1 = require("tslib");
const asn1_cms_1 = require("@peculiar/asn1-cms");
const asn1_schema_1 = require("@peculiar/asn1-schema");
const asn1_x509_1 = require("@peculiar/asn1-x509");
var asn1_cms_2 = require("@peculiar/asn1-cms");
Object.defineProperty(exports, "Attribute", { enumerable: true, get: function () { return asn1_cms_2.Attribute; } });
Object.defineProperty(exports, "ContentInfo", { enumerable: true, get: function () { return asn1_cms_2.ContentInfo; } });
Object.defineProperty(exports, "DigestAlgorithmIdentifier", { enumerable: true, get: function () { return asn1_cms_2.DigestAlgorithmIdentifier; } });
Object.defineProperty(exports, "EncapsulatedContent", { enumerable: true, get: function () { return asn1_cms_2.EncapsulatedContent; } });
Object.defineProperty(exports, "SignedData", { enumerable: true, get: function () { return asn1_cms_2.SignedData; } });
Object.defineProperty(exports, "SignerIdentifier", { enumerable: true, get: function () { return asn1_cms_2.SignerIdentifier; } });
Object.defineProperty(exports, "SignerInfo", { enumerable: true, get: function () { return asn1_cms_2.SignerInfo; } });
var asn1_schema_2 = require("@peculiar/asn1-schema");
Object.defineProperty(exports, "AsnParser", { enumerable: true, get: function () { return asn1_schema_2.AsnParser; } });
Object.defineProperty(exports, "AsnSerializer", { enumerable: true, get: function () { return asn1_schema_2.AsnSerializer; } });
var asn1_x509_2 = require("@peculiar/asn1-x509");
Object.defineProperty(exports, "SubjectPublicKeyInfo", { enumerable: true, get: function () { return asn1_x509_2.SubjectPublicKeyInfo; } });
Object.defineProperty(exports, "X509Certificate", { enumerable: true, get: function () { return asn1_x509_2.Certificate; } });
Object.defineProperty(exports, "Time", { enumerable: true, get: function () { return asn1_x509_2.Time; } });
var asn1_ecc_1 = require("@peculiar/asn1-ecc");
Object.defineProperty(exports, "ECParameters", { enumerable: true, get: function () { return asn1_ecc_1.ECParameters; } });
/**
 * ```asn
 * AttributeSet ::= SET OF Attribute
 * ```
 */
let AttributeSet = AttributeSet_1 = class AttributeSet extends asn1_schema_1.AsnArray {
    constructor(items) {
        super(items);
        Object.setPrototypeOf(this, AttributeSet_1.prototype);
    }
};
exports.AttributeSet = AttributeSet;
exports.AttributeSet = AttributeSet = AttributeSet_1 = tslib_1.__decorate([
    (0, asn1_schema_1.AsnType)({ type: asn1_schema_1.AsnTypeTypes.Set, itemType: asn1_cms_1.Attribute })
], AttributeSet);
/**
 * ```asn
 * DataGroupNumber ::= INTEGER
 * ```
 */
var DataGroupNumber;
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
})(DataGroupNumber || (exports.DataGroupNumber = DataGroupNumber = {}));
/**
 * ```asn
 * DataGroupHash ::= SEQUENCE {
 *  dataGroupNumber DataGroupNumber,
 *  dataGroupHashValue OCTET STRING }
 * ```
 */
class DataGroupHash {
    constructor(params = {}) {
        this.number = DataGroupNumber.dataGroup1;
        this.hash = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
exports.DataGroupHash = DataGroupHash;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.Integer })
], DataGroupHash.prototype, "number", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.OctetString })
], DataGroupHash.prototype, "hash", void 0);
/**
 * ```asn
 * LDSSecurityObjectVersion ::= INTEGER  { v0(0), v1(1) }
 * ```
 */
var LDSSecurityObjectVersion;
(function (LDSSecurityObjectVersion) {
    LDSSecurityObjectVersion[LDSSecurityObjectVersion["v0"] = 0] = "v0";
    LDSSecurityObjectVersion[LDSSecurityObjectVersion["v1"] = 1] = "v1";
    LDSSecurityObjectVersion[LDSSecurityObjectVersion["v2"] = 2] = "v2";
})(LDSSecurityObjectVersion || (exports.LDSSecurityObjectVersion = LDSSecurityObjectVersion = {}));
/**
 * ```asn
 * LDSVersionInfo ::= SEQUENCE {
 *  ldsVersion PrintableString,
 *  unicodeVersion PrintableString }
 * ```
 */
class LDSVersionInfo {
    constructor(params = {}) {
        this.ldsVersion = "";
        this.unicodeVersion = "";
        Object.assign(this, params);
    }
}
exports.LDSVersionInfo = LDSVersionInfo;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.PrintableString })
], LDSVersionInfo.prototype, "ldsVersion", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.PrintableString })
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
exports.LDSSecurityObjectIdentifier = LDSSecurityObjectIdentifier;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.ObjectIdentifier })
], LDSSecurityObjectIdentifier.prototype, "value", void 0);
exports.LDSSecurityObjectIdentifier = LDSSecurityObjectIdentifier = tslib_1.__decorate([
    (0, asn1_schema_1.AsnType)({ type: asn1_schema_1.AsnTypeTypes.Choice })
], LDSSecurityObjectIdentifier);
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
class LDSSecurityObject {
    constructor(params = {}) {
        this.version = LDSSecurityObjectVersion.v1;
        this.hashAlgorithm = new asn1_cms_1.DigestAlgorithmIdentifier();
        this.dataGroups = [];
        Object.assign(this, params);
    }
}
exports.LDSSecurityObject = LDSSecurityObject;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.Integer })
], LDSSecurityObject.prototype, "version", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_cms_1.DigestAlgorithmIdentifier })
], LDSSecurityObject.prototype, "hashAlgorithm", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: DataGroupHash, repeated: "sequence" })
], LDSSecurityObject.prototype, "dataGroups", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: LDSVersionInfo, optional: true })
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
exports.MasterList = MasterList;
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_schema_1.AsnPropTypes.Integer })
], MasterList.prototype, "version", void 0);
tslib_1.__decorate([
    (0, asn1_schema_1.AsnProp)({ type: asn1_x509_1.Certificate, repeated: "set" })
], MasterList.prototype, "certificates", void 0);
exports.MasterList = MasterList = tslib_1.__decorate([
    (0, asn1_schema_1.AsnType)({ type: asn1_schema_1.AsnTypeTypes.Sequence })
], MasterList);
exports.id_ldsSecurityObject = "2.23.136.1.1.1";
exports.id_sha256 = "2.16.840.1.101.3.4.2.1";
exports.id_icao_cscaMasterList = "2.23.136.1.1.2";
exports.id_signingTime = "1.2.840.113549.1.9.5";
