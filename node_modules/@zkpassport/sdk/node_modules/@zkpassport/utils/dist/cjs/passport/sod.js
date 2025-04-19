"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SOD = exports.DataGroupHashValues = void 0;
const asn1_cms_1 = require("@peculiar/asn1-cms");
const asn1_schema_1 = require("@peculiar/asn1-schema");
const binary_1 = require("../binary");
const asn_1 = require("../cms/asn");
const oids_1 = require("../cms/oids");
class DataGroupHashValues {
    constructor(values) {
        this.values = values;
    }
    [Symbol.for("nodejs.util.inspect.custom")]() {
        return new Map(Object.entries(this.values).map(([key, value]) => [Number(key), value]));
    }
}
exports.DataGroupHashValues = DataGroupHashValues;
function formatDN(issuer) {
    return issuer
        .map((i) => i
        .map((j) => `${(0, oids_1.getOIDName)(j.type)}=${j.value.toString()}`)
        .join(", "))
        .join(", ");
}
class SOD {
    constructor(sod) {
        this.version = sod.version;
        this.digestAlgorithms = sod.digestAlgorithms;
        this.encapContentInfo = sod.encapContentInfo;
        this.signerInfo = sod.signerInfo;
        this.certificate = sod.certificate;
        this.bytes = sod.bytes;
        this.encapContentInfo = sod.encapContentInfo;
        this.signerInfo = sod.signerInfo;
        this.certificate = sod.certificate;
    }
    static fromDER(der) {
        der = der.slice(0, 2).equals(binary_1.Binary.from([119, 130])) ? der.slice(4) : der;
        const contentInfo = asn1_schema_1.AsnParser.parse(der.toUInt8Array(), asn1_cms_1.ContentInfo);
        const signedData = asn1_schema_1.AsnParser.parse(contentInfo.content, asn1_cms_1.SignedData);
        if (!signedData.encapContentInfo?.eContent?.single)
            throw new Error("No eContent found");
        const eContent = asn1_schema_1.AsnConvert.parse(signedData.encapContentInfo?.eContent?.single, asn_1.LDSSecurityObject);
        const certificates = signedData.certificates;
        const cert = certificates?.[0]?.certificate;
        if (!cert)
            throw new Error("No DSC certificate found");
        if ((certificates?.length ?? 0) > 1)
            console.warn("Warning: Found multiple DSC certificates");
        const tbs = cert?.tbsCertificate;
        if (!tbs)
            throw new Error("No TBS found in DSC certificate");
        const signerInfo = signedData.signerInfos[0];
        if (signedData.signerInfos.length > 1)
            console.warn("Warning: Found multiple SignerInfos");
        if (!signerInfo.signedAttrs)
            throw new Error("No signedAttrs found");
        const signedAttrsMap = new Map(signerInfo.signedAttrs.map((v) => [(0, oids_1.getOIDName)(v.attrType), binary_1.Binary.from(v.attrValues[0])]));
        // Reconstruct signed attributes using AttributeSet to get the correct bytes that are signed
        const reconstructedSignedAttrs = new asn_1.AttributeSet(signerInfo.signedAttrs.map((v) => v));
        const messageDigest = signedAttrsMap.get("messageDigest");
        if (!messageDigest)
            throw new Error("No signedAttrs.messageDigest found");
        const signingTimeAttr = signedAttrsMap.get("signingTime");
        const signingTime = signingTimeAttr
            ? asn1_schema_1.AsnParser.parse(signingTimeAttr.toUInt8Array(), asn_1.Time).getTime()
            : undefined;
        const signedAttrs = {
            bytes: binary_1.Binary.from(asn1_schema_1.AsnSerializer.serialize(reconstructedSignedAttrs)),
            contentType: (0, oids_1.getOIDName)((0, oids_1.decodeOID)(signedAttrsMap.get("contentType").toNumberArray())),
            messageDigest,
            ...(signingTime && { signingTime }),
        };
        return new SOD({
            bytes: der,
            version: signedData.version,
            digestAlgorithms: signedData.digestAlgorithms.map((v) => (0, oids_1.getHashAlgorithmName)(v.algorithm)),
            encapContentInfo: {
                eContentType: (0, oids_1.getOIDName)(signedData.encapContentInfo.eContentType),
                eContent: {
                    bytes: binary_1.Binary.from(signedData.encapContentInfo.eContent.single.buffer),
                    version: eContent.version,
                    hashAlgorithm: (0, oids_1.getHashAlgorithmName)(eContent.hashAlgorithm.algorithm),
                    dataGroupHashValues: new DataGroupHashValues(Object.fromEntries(eContent.dataGroups.map((v) => [v.number, binary_1.Binary.from(v.hash)]))),
                },
            },
            signerInfo: {
                version: signerInfo.version,
                signedAttrs: signedAttrs,
                digestAlgorithm: (0, oids_1.getHashAlgorithmName)(signerInfo.digestAlgorithm.algorithm),
                signatureAlgorithm: {
                    name: (0, oids_1.getOIDName)(signerInfo.signatureAlgorithm.algorithm),
                    parameters: signerInfo.signatureAlgorithm.parameters
                        ? binary_1.Binary.from(signerInfo.signatureAlgorithm.parameters)
                        : undefined,
                },
                signature: binary_1.Binary.from(signerInfo.signature.buffer),
                sid: {
                    issuerAndSerialNumber: signerInfo.sid.issuerAndSerialNumber
                        ? {
                            issuer: formatDN(signerInfo.sid.issuerAndSerialNumber.issuer),
                            serialNumber: binary_1.Binary.from(signerInfo.sid.issuerAndSerialNumber.serialNumber),
                        }
                        : undefined,
                    subjectKeyIdentifier: signerInfo.sid.subjectKeyIdentifier
                        ? binary_1.Binary.from(signerInfo.sid.subjectKeyIdentifier.buffer).toString("hex")
                        : undefined,
                },
            },
            certificate: {
                tbs: {
                    bytes: binary_1.Binary.from(asn1_schema_1.AsnSerializer.serialize(tbs)),
                    version: tbs.version,
                    serialNumber: binary_1.Binary.from(tbs.serialNumber),
                    signatureAlgorithm: {
                        name: (0, oids_1.getOIDName)(tbs.signature.algorithm),
                        parameters: tbs.signature.parameters
                            ? binary_1.Binary.from(tbs.signature.parameters)
                            : undefined,
                    },
                    issuer: formatDN(tbs.issuer),
                    validity: {
                        notBefore: tbs.validity.notBefore.getTime(),
                        notAfter: tbs.validity.notAfter.getTime(),
                    },
                    subject: formatDN(tbs.subject),
                    subjectPublicKeyInfo: {
                        signatureAlgorithm: {
                            name: (0, oids_1.getOIDName)(tbs.subjectPublicKeyInfo.algorithm.algorithm),
                            parameters: tbs.subjectPublicKeyInfo.algorithm.parameters
                                ? binary_1.Binary.from(tbs.subjectPublicKeyInfo.algorithm.parameters)
                                : undefined,
                        },
                        subjectPublicKey: binary_1.Binary.from(tbs.subjectPublicKeyInfo.subjectPublicKey),
                    },
                    issuerUniqueID: tbs.issuerUniqueID ? binary_1.Binary.from(tbs.issuerUniqueID) : undefined,
                    subjectUniqueID: tbs.subjectUniqueID ? binary_1.Binary.from(tbs.subjectUniqueID) : undefined,
                    extensions: new Map(tbs.extensions?.map((v) => [
                        (0, oids_1.getOIDName)(v.extnID),
                        { critical: v.critical, value: binary_1.Binary.from(v.extnValue.buffer) },
                    ]) ?? []),
                },
                signatureAlgorithm: {
                    name: (0, oids_1.getOIDName)(cert.signatureAlgorithm.algorithm),
                    parameters: cert.signatureAlgorithm.parameters
                        ? binary_1.Binary.from(cert.signatureAlgorithm.parameters)
                        : undefined,
                },
                signature: binary_1.Binary.from(cert.signatureValue),
            },
        });
    }
}
exports.SOD = SOD;
