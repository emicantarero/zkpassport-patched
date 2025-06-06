import { ContentInfo, SignedData } from "@peculiar/asn1-cms";
import { AsnConvert, AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { Binary } from "../binary/index.js";
import { AttributeSet, LDSSecurityObject, Time } from "../cms/asn.js";
import { decodeOID, getHashAlgorithmName, getOIDName } from "../cms/oids.js";
export class DataGroupHashValues {
    constructor(values) {
        this.values = values;
    }
    [Symbol.for("nodejs.util.inspect.custom")]() {
        return new Map(Object.entries(this.values).map(([key, value]) => [Number(key), value]));
    }
}
function formatDN(issuer) {
    return issuer
        .map((i) => i
        .map((j) => `${getOIDName(j.type)}=${j.value.toString()}`)
        .join(", "))
        .join(", ");
}
export class SOD {
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
        der = der.slice(0, 2).equals(Binary.from([119, 130])) ? der.slice(4) : der;
        const contentInfo = AsnParser.parse(der.toUInt8Array(), ContentInfo);
        const signedData = AsnParser.parse(contentInfo.content, SignedData);
        if (!signedData.encapContentInfo?.eContent?.single)
            throw new Error("No eContent found");
        const eContent = AsnConvert.parse(signedData.encapContentInfo?.eContent?.single, LDSSecurityObject);
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
        const signedAttrsMap = new Map(signerInfo.signedAttrs.map((v) => [getOIDName(v.attrType), Binary.from(v.attrValues[0])]));
        // Reconstruct signed attributes using AttributeSet to get the correct bytes that are signed
        const reconstructedSignedAttrs = new AttributeSet(signerInfo.signedAttrs.map((v) => v));
        const messageDigest = signedAttrsMap.get("messageDigest");
        if (!messageDigest)
            throw new Error("No signedAttrs.messageDigest found");
        const signingTimeAttr = signedAttrsMap.get("signingTime");
        const signingTime = signingTimeAttr
            ? AsnParser.parse(signingTimeAttr.toUInt8Array(), Time).getTime()
            : undefined;
        const signedAttrs = {
            bytes: Binary.from(AsnSerializer.serialize(reconstructedSignedAttrs)),
            contentType: getOIDName(decodeOID(signedAttrsMap.get("contentType").toNumberArray())),
            messageDigest,
            ...(signingTime && { signingTime }),
        };
        return new SOD({
            bytes: der,
            version: signedData.version,
            digestAlgorithms: signedData.digestAlgorithms.map((v) => getHashAlgorithmName(v.algorithm)),
            encapContentInfo: {
                eContentType: getOIDName(signedData.encapContentInfo.eContentType),
                eContent: {
                    bytes: Binary.from(signedData.encapContentInfo.eContent.single.buffer),
                    version: eContent.version,
                    hashAlgorithm: getHashAlgorithmName(eContent.hashAlgorithm.algorithm),
                    dataGroupHashValues: new DataGroupHashValues(Object.fromEntries(eContent.dataGroups.map((v) => [v.number, Binary.from(v.hash)]))),
                },
            },
            signerInfo: {
                version: signerInfo.version,
                signedAttrs: signedAttrs,
                digestAlgorithm: getHashAlgorithmName(signerInfo.digestAlgorithm.algorithm),
                signatureAlgorithm: {
                    name: getOIDName(signerInfo.signatureAlgorithm.algorithm),
                    parameters: signerInfo.signatureAlgorithm.parameters
                        ? Binary.from(signerInfo.signatureAlgorithm.parameters)
                        : undefined,
                },
                signature: Binary.from(signerInfo.signature.buffer),
                sid: {
                    issuerAndSerialNumber: signerInfo.sid.issuerAndSerialNumber
                        ? {
                            issuer: formatDN(signerInfo.sid.issuerAndSerialNumber.issuer),
                            serialNumber: Binary.from(signerInfo.sid.issuerAndSerialNumber.serialNumber),
                        }
                        : undefined,
                    subjectKeyIdentifier: signerInfo.sid.subjectKeyIdentifier
                        ? Binary.from(signerInfo.sid.subjectKeyIdentifier.buffer).toString("hex")
                        : undefined,
                },
            },
            certificate: {
                tbs: {
                    bytes: Binary.from(AsnSerializer.serialize(tbs)),
                    version: tbs.version,
                    serialNumber: Binary.from(tbs.serialNumber),
                    signatureAlgorithm: {
                        name: getOIDName(tbs.signature.algorithm),
                        parameters: tbs.signature.parameters
                            ? Binary.from(tbs.signature.parameters)
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
                            name: getOIDName(tbs.subjectPublicKeyInfo.algorithm.algorithm),
                            parameters: tbs.subjectPublicKeyInfo.algorithm.parameters
                                ? Binary.from(tbs.subjectPublicKeyInfo.algorithm.parameters)
                                : undefined,
                        },
                        subjectPublicKey: Binary.from(tbs.subjectPublicKeyInfo.subjectPublicKey),
                    },
                    issuerUniqueID: tbs.issuerUniqueID ? Binary.from(tbs.issuerUniqueID) : undefined,
                    subjectUniqueID: tbs.subjectUniqueID ? Binary.from(tbs.subjectUniqueID) : undefined,
                    extensions: new Map(tbs.extensions?.map((v) => [
                        getOIDName(v.extnID),
                        { critical: v.critical, value: Binary.from(v.extnValue.buffer) },
                    ]) ?? []),
                },
                signatureAlgorithm: {
                    name: getOIDName(cert.signatureAlgorithm.algorithm),
                    parameters: cert.signatureAlgorithm.parameters
                        ? Binary.from(cert.signatureAlgorithm.parameters)
                        : undefined,
                },
                signature: Binary.from(cert.signatureValue),
            },
        });
    }
}
