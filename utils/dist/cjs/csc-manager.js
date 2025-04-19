"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseCertificate = parseCertificate;
exports.parseCertificates = parseCertificates;
const asn1_schema_1 = require("@peculiar/asn1-schema");
const asn1_x509_1 = require("@peculiar/asn1-x509");
const i18n_iso_countries_1 = require("i18n-iso-countries");
const constants_1 = require("./cms/constants");
const utils_1 = require("./cms/utils");
const utils_2 = require("./cms/utils");
function parseCertificate(content) {
    if (typeof content === "string") {
        // Remove PEM headers and convert to binary
        const b64 = content.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, "");
        content = Buffer.from(b64, "base64");
    }
    // Parse using @peculiar/asn1-schema
    const x509 = asn1_schema_1.AsnParser.parse(content, asn1_x509_1.Certificate);
    // Extract common fields
    let countryCode = "Unknown";
    // Iterate over the issuer values to find the country code
    for (const val of x509.tbsCertificate.issuer.values()) {
        for (const attrAndType of val) {
            if (attrAndType.type === "2.5.4.6") {
                countryCode = attrAndType.value.printableString?.toUpperCase() ?? "Unknown";
                const temp = countryCode;
                countryCode = (0, i18n_iso_countries_1.alpha2ToAlpha3)(countryCode) ?? "N/A";
                // Some country codes are re not ISO 3166-1 alpha-2 codes
                // or do not correspond to any specific nation (e.g. EU, UN)
                if (countryCode === "N/A" && !!temp) {
                    countryCode = temp.length === 2 ? `${temp}_` : temp;
                }
            }
        }
    }
    const notBefore = Math.floor(new Date(x509.tbsCertificate.validity.notBefore.getTime()).getTime() / 1000);
    const notAfter = Math.floor(new Date(x509.tbsCertificate.validity.notAfter.getTime()).getTime() / 1000);
    // Get the public key
    const spkiAlgorithm = constants_1.OIDS_TO_DESCRIPTION[x509.tbsCertificate.subjectPublicKeyInfo.algorithm
        .algorithm] ?? x509.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
    // Check if it's RSA by examining the algorithm identifier
    const isRSA = spkiAlgorithm.toLowerCase().includes("rsa");
    const signatureAlgorithm = constants_1.OIDS_TO_DESCRIPTION[x509.tbsCertificate.signature.algorithm] ?? x509.tbsCertificate.signature.algorithm;
    const publicKeyType = constants_1.OIDS_TO_DESCRIPTION[x509.tbsCertificate.subjectPublicKeyInfo.algorithm
        .algorithm] ?? x509.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
    // Some certificate have incoherent signatureAlgorithm and publicKeyType
    // e.g. rsaEncryption and ecdsa-with-SHA256
    // So we filter them out here by checking both the publicKeyType and signatureAlgorithm
    if (publicKeyType === "rsaEncryption" && signatureAlgorithm.toLowerCase().includes("rsa")) {
        const rsaInfo = (0, utils_1.getRSAInfo)(x509.tbsCertificate.subjectPublicKeyInfo);
        return {
            signature_algorithm: signatureAlgorithm,
            public_key: {
                type: publicKeyType,
                modulus: `0x${rsaInfo.modulus.toString(16)}`,
                exponent: Number(rsaInfo.exponent),
                hash_algorithm: signatureAlgorithm.includes("pss")
                    ? (0, utils_1.getRSAPSSParams)(x509.signatureAlgorithm).hashAlgorithm
                    : undefined,
                scheme: signatureAlgorithm.includes("pss") ? "pss" : "pkcs",
            },
            country: countryCode,
            validity: {
                not_before: notBefore,
                not_after: notAfter,
            },
            key_size: rsaInfo.modulus.toString(2).length,
            authority_key_identifier: (0, utils_2.getAuthorityKeyId)(x509),
            subject_key_identifier: (0, utils_1.getSubjectKeyId)(x509),
            private_key_usage_period: (0, utils_1.getPrivateKeyUsagePeriod)(x509),
        };
    }
    else if (publicKeyType === "ecPublicKey" &&
        signatureAlgorithm.toLowerCase().includes("ecdsa")) {
        const ecdsaInfo = (0, utils_1.getECDSAInfo)(x509.tbsCertificate.subjectPublicKeyInfo);
        return {
            signature_algorithm: signatureAlgorithm,
            public_key: {
                type: publicKeyType,
                curve: ecdsaInfo.curve,
                // The first byte is 0x04, which is the prefix for uncompressed public keys
                // so we get rid of it
                public_key_x: `0x${Buffer.from(ecdsaInfo.publicKey.slice(1, ecdsaInfo.publicKey.length / 2 + 1)).toString("hex")}`,
                public_key_y: `0x${Buffer.from(ecdsaInfo.publicKey.slice(ecdsaInfo.publicKey.length / 2 + 1)).toString("hex")}`,
            },
            country: countryCode,
            validity: {
                not_before: notBefore,
                not_after: notAfter,
            },
            key_size: (0, utils_1.getBitSizeFromCurve)(ecdsaInfo.curve),
            authority_key_identifier: (0, utils_2.getAuthorityKeyId)(x509),
            subject_key_identifier: (0, utils_1.getSubjectKeyId)(x509),
            private_key_usage_period: (0, utils_1.getPrivateKeyUsagePeriod)(x509),
        };
    }
    else {
        throw new Error("Unsupported public key type");
    }
}
function parseCertificates(pemContent) {
    const certificates = [];
    try {
        // Split the PEM content into individual certificates
        const pemRegex = /(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)/g;
        const matches = pemContent.match(pemRegex) || [];
        for (const certPem of matches) {
            // Remove PEM headers and convert to binary
            const b64 = certPem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, "");
            const binary = Buffer.from(b64, "base64");
            try {
                certificates.push(parseCertificate(binary));
            }
            catch (certError) {
                console.error("Error parsing individual certificate:", certError);
            }
        }
    }
    catch (error) {
        console.error("Error parsing certificates:", error);
    }
    return certificates;
}
