"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PassportReader = void 0;
exports.getSODContent = getSODContent;
exports.getEContentHashAlgorithm = getEContentHashAlgorithm;
exports.getEContent = getEContent;
exports.getSignedAttributesHashingAlgorithm = getSignedAttributesHashingAlgorithm;
exports.getSODCMSVersion = getSODCMSVersion;
exports.extractTBS = extractTBS;
exports.getSodSignatureAlgorithmType = getSodSignatureAlgorithmType;
exports.getSodSignatureHashAlgorithm = getSodSignatureHashAlgorithm;
exports.getDSCSignatureAlgorithmType = getDSCSignatureAlgorithmType;
exports.getDSCSignatureHashAlgorithm = getDSCSignatureHashAlgorithm;
const asn1_cms_1 = require("@peculiar/asn1-cms");
const asn1_schema_1 = require("@peculiar/asn1-schema");
const constants_1 = require("../cms/constants");
const oids_1 = require("../cms/oids");
const sod_1 = require("./sod");
class PassportReader {
    getPassportViewModel() {
        if (this.dg1 === undefined || this.sod === undefined) {
            throw new Error("PassportReader not initialized");
        }
        const isIDCard = this.dg1.length === 95;
        const mrz = this.dg1.slice(5).toString("ascii");
        // TODO: Implement the remaining properties
        return {
            appVersion: "",
            mrz: mrz,
            name: mrz.slice(isIDCard ? 60 : 5, isIDCard ? 90 : 44),
            dateOfBirth: mrz.slice(isIDCard ? 30 : 57, isIDCard ? 36 : 63),
            nationality: mrz.slice(isIDCard ? 45 : 54, isIDCard ? 48 : 57),
            gender: mrz.slice(isIDCard ? 37 : 64, isIDCard ? 38 : 65),
            passportNumber: mrz.slice(isIDCard ? 5 : 44, isIDCard ? 14 : 53),
            passportExpiry: mrz.slice(isIDCard ? 38 : 65, isIDCard ? 44 : 71),
            firstName: "",
            lastName: "",
            fullName: mrz.slice(isIDCard ? 60 : 5, isIDCard ? 90 : 44),
            photo: "",
            originalPhoto: "",
            chipAuthSupported: false,
            chipAuthSuccess: false,
            chipAuthFailed: false,
            LDSVersion: "",
            // TODO: Add support for other data groups
            dataGroups: Object.entries(this.sod.encapContentInfo.eContent.dataGroupHashValues.values).map(([key, value]) => ({
                groupNumber: Number(key),
                name: "DG" + key,
                hash: value.toNumberArray(),
                value: key === "1" ? this.dg1?.toNumberArray() ?? [] : [],
            })),
            dataGroupsHashAlgorithm: this.sod.encapContentInfo.eContent.hashAlgorithm,
            sod: this.sod,
            sodVersion: this.sod.version.toString(),
            signedAttributes: this.sod.signerInfo.signedAttrs.bytes.toNumberArray(),
            signedAttributesHashAlgorithm: this.sod.signerInfo.digestAlgorithm,
            eContent: this.sod.encapContentInfo.eContent.bytes.toNumberArray(),
            eContentHash: this.sod.signerInfo.signedAttrs.messageDigest.toHex(),
            eContentHashAlgorithm: this.sod.signerInfo.digestAlgorithm,
            tbsCertificate: this.sod.certificate.tbs.bytes.toNumberArray(),
            dscSignatureAlgorithm: this.sod.certificate.signatureAlgorithm.name,
            dscSignature: this.sod.certificate.signature.toNumberArray(),
            sodSignature: this.sod.signerInfo.signature.toNumberArray(),
            sodSignatureAlgorithm: this.sod.signerInfo.signatureAlgorithm.name,
        };
    }
    loadPassport(dg1, sod) {
        this.sod = sod_1.SOD.fromDER(sod);
        this.dg1 = dg1;
    }
}
exports.PassportReader = PassportReader;
function getSODContent(passport) {
    const cert = asn1_schema_1.AsnParser.parse(passport.sod.bytes.toBuffer(), asn1_cms_1.ContentInfo);
    const signedData = asn1_schema_1.AsnParser.parse(cert.content, asn1_cms_1.SignedData);
    return signedData;
}
function getEContentHashAlgorithm(passport) {
    const eContent = getEContent(passport);
    const oidOffset = 9;
    const oidLength = eContent[oidOffset + 1];
    const oidBytes = eContent.slice(oidOffset, oidOffset + oidLength + 2);
    return constants_1.HASH_OIDS[(0, oids_1.decodeOID)(oidBytes)] ?? "";
}
function getEContent(passport) {
    const signedData = getSODContent(passport);
    return Array.from(new Uint8Array(signedData.encapContentInfo.eContent?.single?.buffer ?? new ArrayBuffer(0)));
}
function getSignedAttributesHashingAlgorithm(passport) {
    const signedData = getSODContent(passport);
    return constants_1.HASH_OIDS[signedData.digestAlgorithms[0].algorithm] ?? "";
}
function getSODCMSVersion(passport) {
    const signedData = getSODContent(passport);
    return signedData.version.toString();
}
function extractTBS(passport) {
    const signedData = getSODContent(passport);
    const tbsCertificate = signedData.certificates
        ? signedData.certificates[0]?.certificate?.tbsCertificate
        : null;
    return tbsCertificate ?? null;
}
function getSodSignatureAlgorithmType(passport) {
    if (passport.sodSignatureAlgorithm?.toLowerCase().includes("rsa")) {
        return "RSA";
    }
    else if (passport.sodSignatureAlgorithm?.toLowerCase().includes("ecdsa")) {
        return "ECDSA";
    }
    return "";
}
function getSodSignatureHashAlgorithm(passport) {
    if (passport.sodSignatureAlgorithm?.toLowerCase().includes("sha256")) {
        return "SHA256";
    }
    else if (passport.sodSignatureAlgorithm?.toLowerCase().includes("sha384")) {
        return "SHA384";
    }
    else if (passport.sodSignatureAlgorithm?.toLowerCase().includes("sha512")) {
        return "SHA512";
    }
}
function getDSCSignatureAlgorithmType(passport) {
    if (passport.dscSignatureAlgorithm?.toLowerCase().includes("rsa")) {
        return "RSA";
    }
    else if (passport.dscSignatureAlgorithm?.toLowerCase().includes("ecdsa")) {
        return "ECDSA";
    }
    return "";
}
function getDSCSignatureHashAlgorithm(passport) {
    if (passport.dscSignatureAlgorithm?.toLowerCase().includes("sha256")) {
        return "SHA256";
    }
    else if (passport.dscSignatureAlgorithm?.toLowerCase().includes("sha384")) {
        return "SHA384";
    }
    else if (passport.dscSignatureAlgorithm?.toLowerCase().includes("sha512")) {
        return "SHA512";
    }
}
