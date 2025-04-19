import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { ECParameters } from "@peculiar/asn1-ecc";
import { RSAPublicKey, RsaSaPssParams } from "@peculiar/asn1-rsa";
import { AsnParser } from "@peculiar/asn1-schema";
import { AuthorityKeyIdentifier, PrivateKeyUsagePeriod, SubjectKeyIdentifier, } from "@peculiar/asn1-x509";
import { BRAINPOOL_CURVES, BRAINPOOL_CURVES_ABBR, CURVE_OIDS, HASH_OIDS, id_authorityKeyIdentifier, id_privateKeyUsagePeriod, id_subjectKeyIdentifier, OIDS_TO_PUBKEY_TYPE, OIDS_TO_SIG_ALGORITHM, RSA_OIDS, } from "./constants.js";
export function getAbbreviatedCurveName(ecParams) {
    const curveName = getCurveName(ecParams);
    return BRAINPOOL_CURVES_ABBR[curveName] || curveName;
}
export function getCurveName(ecParams) {
    if (ecParams.namedCurve) {
        if (!(ecParams.namedCurve in CURVE_OIDS)) {
            throw new Error(`Unknown curve OID: ${ecParams.namedCurve}`);
        }
        return CURVE_OIDS[ecParams.namedCurve];
    }
    if (!ecParams.specifiedCurve) {
        throw new Error("No named or specified curve found in ECParameters");
    }
    // Map the specified curve to a known Brainpool curve name
    const a = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.curve.a).toString("hex")}`);
    const b = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.curve.b).toString("hex")}`);
    const n = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.order).toString("hex")}`);
    const p = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.fieldID.parameters.slice(2)).toString("hex")}`);
    if (a == p256.CURVE.a && b == p256.CURVE.b && n == p256.CURVE.n && p == p256.CURVE.Fp.ORDER) {
        return "P-256";
    }
    else if (a == p384.CURVE.a &&
        b == p384.CURVE.b &&
        n == p384.CURVE.n &&
        p == p384.CURVE.Fp.ORDER) {
        return "P-384";
    }
    else if (a == p521.CURVE.a &&
        b == p521.CURVE.b &&
        n == p521.CURVE.n &&
        p == p521.CURVE.Fp.ORDER) {
        return "P-521";
    }
    for (const key in BRAINPOOL_CURVES) {
        if (a == BRAINPOOL_CURVES[key].a &&
            b == BRAINPOOL_CURVES[key].b &&
            n == BRAINPOOL_CURVES[key].n &&
            p == BRAINPOOL_CURVES[key].p) {
            return key;
        }
    }
    throw new Error(`Unknown curve: ${a}, ${b}, ${n}, ${p}`);
}
export function getAuthorityKeyId(cert) {
    const authKeyExt = cert.tbsCertificate.extensions?.find((ext) => ext.extnID === id_authorityKeyIdentifier);
    if (authKeyExt?.extnValue) {
        try {
            const authKeyId = AsnParser.parse(authKeyExt.extnValue, AuthorityKeyIdentifier);
            const keyId = authKeyId?.keyIdentifier?.buffer;
            if (!keyId)
                return;
            return `0x${Buffer.from(keyId).toString("hex")}`;
        }
        catch (error) {
            return;
        }
    }
    return;
}
export function getSubjectKeyId(cert) {
    const subjKeyExt = cert.tbsCertificate.extensions?.find((ext) => ext.extnID === id_subjectKeyIdentifier);
    if (subjKeyExt?.extnValue) {
        try {
            const subjKeyId = AsnParser.parse(subjKeyExt.extnValue, SubjectKeyIdentifier);
            const keyId = subjKeyId?.buffer;
            if (!keyId)
                return;
            return `0x${Buffer.from(keyId).toString("hex")}`;
        }
        catch (error) {
            return;
        }
    }
    return;
}
export function getPrivateKeyUsagePeriod(cert) {
    const pkupExt = cert.tbsCertificate.extensions?.find((ext) => ext.extnID === id_privateKeyUsagePeriod);
    if (pkupExt?.extnValue) {
        const pkup = AsnParser.parse(pkupExt.extnValue, PrivateKeyUsagePeriod);
        return {
            not_before: pkup.notBefore ? Math.floor(pkup.notBefore.getTime() / 1000) : undefined,
            not_after: pkup.notAfter ? Math.floor(pkup.notAfter.getTime() / 1000) : undefined,
        };
    }
    return;
}
function fromBytesToBigInt(bytes) {
    return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}
function fromArrayBufferToBigInt(buffer) {
    return BigInt("0x" + Buffer.from(buffer).toString("hex"));
}
export function getECDSAInfo(subjectPublicKeyInfo) {
    const parsedParams = AsnParser.parse(subjectPublicKeyInfo.algorithm.parameters, ECParameters);
    const curve = getCurveName(parsedParams);
    return {
        curve,
        publicKey: new Uint8Array(subjectPublicKeyInfo.subjectPublicKey),
        keySize: getKeySizeFromCurve(curve),
    };
}
export function getRSAPSSParams(signatureAlgorithm) {
    const parsedKey = AsnParser.parse(signatureAlgorithm.parameters, RsaSaPssParams);
    const hashAlgorithm = HASH_OIDS[parsedKey.hashAlgorithm.algorithm] ?? "";
    const maskGenAlgorithm = HASH_OIDS[parsedKey.maskGenAlgorithm.algorithm] ?? "";
    return {
        hashAlgorithm: hashAlgorithm.replace("SHA-", "SHA"),
        saltLength: parsedKey.saltLength,
        maskGenAlgorithm,
    };
}
export function getRSAInfo(subjectPublicKeyInfo) {
    const parsedKey = AsnParser.parse(subjectPublicKeyInfo.subjectPublicKey, RSAPublicKey);
    const type = RSA_OIDS[subjectPublicKeyInfo.algorithm.algorithm] ?? "";
    return {
        modulus: fromArrayBufferToBigInt(parsedKey.modulus),
        exponent: fromArrayBufferToBigInt(parsedKey.publicExponent),
        type: type.includes("pss") ? "pss" : "pkcs",
    };
}
export function getSigningKeyType(cert) {
    const spki = cert.tbsCertificate.subjectPublicKeyInfo;
    const publicKeyAlgOID = spki.algorithm.algorithm;
    const publicKeyType = OIDS_TO_PUBKEY_TYPE[publicKeyAlgOID] || publicKeyAlgOID;
    const sigAlgOID = cert.tbsCertificate.signature.algorithm;
    const sigAlg = OIDS_TO_SIG_ALGORITHM[sigAlgOID] ?? sigAlgOID;
    if (publicKeyType === "rsaEncryption") {
        const rsaInfo = getRSAInfo(spki);
        const keySize = rsaInfo.modulus.toString(2).length.toString();
        if (sigAlg === "rsassa-pss") {
            return `RSAPSS-${keySize}`;
        }
        else {
            return `RSA-${keySize}`;
        }
    }
    else if (publicKeyType === "ecPublicKey") {
        const curve = getAbbreviatedCurveName(AsnParser.parse(spki.algorithm.parameters, ECParameters));
        const pubkey = new Uint8Array(spki.subjectPublicKey);
        // Ensure the key size is within the curve
        // The first byte is 0x04, which is the prefix for uncompressed public keys so we get rid of it
        const pubkeyX = BigInt("0x" + Buffer.from(pubkey.slice(1, pubkey.length / 2 + 1)).toString("hex"));
        const pubkeyY = BigInt("0x" + Buffer.from(pubkey.slice(pubkey.length / 2 + 1)).toString("hex"));
        const pubkeySizeX = pubkeyX.toString(2).length;
        const pubkeySizeY = pubkeyY.toString(2).length;
        const expectedKeySize = parseInt(curve.split("-")[1]);
        if (pubkeySizeX > expectedKeySize || pubkeySizeY > expectedKeySize) {
            throw new Error(`Key size exceeds size of curve ${curve}`);
        }
        return curve;
    }
    return "";
}
// TODO: Consider throwing and error or returning undefined instead of ""?
export function getSignatureAlgorithmType(signatureAlgorithm) {
    if (signatureAlgorithm.toLowerCase().includes("rsa")) {
        return "RSA";
    }
    else if (signatureAlgorithm.toLowerCase().includes("ecdsa")) {
        return "ECDSA";
    }
    return "";
}
export function getBitSizeFromCurve(curve) {
    const curveName = curve
        .replace("brainpoolP", "")
        .replace("nist", "")
        .replace("-", "")
        .replace("r1", "")
        .replace("t1", "")
        .toLowerCase();
    return Number(curveName.replace("p", ""));
}
export function getCertificateIssuer(cert) {
    return formatAbbreviatedDN(cert.tbsCertificate.issuer);
}
export function getCertificateSubject(cert) {
    return formatAbbreviatedDN(cert.tbsCertificate.subject);
}
export function getCertificateIssuerCountry(cert) {
    for (const rdn of cert.tbsCertificate.subject) {
        for (const attr of rdn) {
            if (attr.type === "2.5.4.6") {
                const countryCode = attr.value.toString().toUpperCase();
                return countryCode;
            }
        }
    }
}
// Map OIDs to their abbreviated names according to RFC 4514 and X.520
export function formatAbbreviatedDN(issuer) {
    const abbreviations = {
        "1.2.840.113549.1.9.1": "emailAddress", // emailAddress
        "2.5.4.10": "O", // organizationName
        "2.5.4.11": "OU", // organizationalUnitName
        "2.5.4.17": "postalCode", // postalCode
        "2.5.4.20": "telephoneNumber", // telephoneNumber
        "2.5.4.3": "CN", // commonName
        "2.5.4.4": "SN", // surname
        "2.5.4.5": "serialNumber", // serialNumber
        "2.5.4.6": "C", // countryName
        "2.5.4.7": "L", // localityName
        "2.5.4.8": "ST", // stateOrProvinceName
        "2.5.4.9": "street", // streetAddress
    };
    return issuer
        .map((i) => i
        .map((j) => `${abbreviations[j.type] || j.type}=${j.value}`)
        .join(", "))
        .join(", ");
}
// Convert DER to PEM format
export function derToPem(der) {
    return `-----BEGIN CERTIFICATE-----\n${Buffer.from(der)
        .toString("base64")
        .match(/.{1,64}/g)
        ?.join("\n")}\n-----END CERTIFICATE-----`;
}
export const CURVE_TO_KEYSIZE = {
    // NIST curves
    "P-256": 256,
    "P-384": 384,
    "P-521": 521,
    // Brainpool curves
    "brainpoolP160r1": 160,
    "brainpoolP160t1": 160,
    "brainpoolP192r1": 192,
    "brainpoolP192t1": 192,
    "brainpoolP224r1": 224,
    "brainpoolP224t1": 224,
    "brainpoolP256r1": 256,
    "brainpoolP256t1": 256,
    "brainpoolP320r1": 320,
    "brainpoolP320t1": 320,
    "brainpoolP384r1": 384,
    "brainpoolP384t1": 384,
    "brainpoolP512r1": 512,
    "brainpoolP512t1": 512,
};
export function getKeySizeFromCurve(curve) {
    if (CURVE_TO_KEYSIZE[curve] === undefined) {
        throw new Error(`Unknown curve: ${curve}`);
    }
    return CURVE_TO_KEYSIZE[curve];
}
