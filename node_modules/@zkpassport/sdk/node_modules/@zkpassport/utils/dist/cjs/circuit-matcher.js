"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isSignatureAlgorithmSupported = isSignatureAlgorithmSupported;
exports.isCSCSupported = isCSCSupported;
exports.isIDSupported = isIDSupported;
exports.getCSCMasterlist = getCSCMasterlist;
exports.getTBSMaxLen = getTBSMaxLen;
exports.getCSCForPassport = getCSCForPassport;
exports.processECDSASignature = processECDSASignature;
exports.getScopeHash = getScopeHash;
exports.processSodSignature = processSodSignature;
exports.getDSCCircuitInputs = getDSCCircuitInputs;
exports.getIDDataCircuitInputs = getIDDataCircuitInputs;
exports.getDSCCountry = getDSCCountry;
exports.getIntegrityCheckCircuitInputs = getIntegrityCheckCircuitInputs;
exports.getFirstNameRange = getFirstNameRange;
exports.getLastNameRange = getLastNameRange;
exports.getFullNameRange = getFullNameRange;
exports.getDiscloseCircuitInputs = getDiscloseCircuitInputs;
exports.getDiscloseFlagsCircuitInputs = getDiscloseFlagsCircuitInputs;
exports.calculateAge = calculateAge;
exports.getAgeCircuitInputs = getAgeCircuitInputs;
exports.getNationalityInclusionCircuitInputs = getNationalityInclusionCircuitInputs;
exports.getIssuingCountryInclusionCircuitInputs = getIssuingCountryInclusionCircuitInputs;
exports.getNationalityExclusionCircuitInputs = getNationalityExclusionCircuitInputs;
exports.getIssuingCountryExclusionCircuitInputs = getIssuingCountryExclusionCircuitInputs;
exports.getBirthdateCircuitInputs = getBirthdateCircuitInputs;
exports.getExpiryDateCircuitInputs = getExpiryDateCircuitInputs;
const tslib_1 = require("tslib");
const sha256_1 = require("@noble/hashes/sha256");
const asn1_schema_1 = require("@peculiar/asn1-schema");
const asn1_x509_1 = require("@peculiar/asn1-x509");
const date_fns_1 = require("date-fns");
const i18n_iso_countries_1 = require("i18n-iso-countries");
const csc_masterlist_json_1 = tslib_1.__importDefault(require("./assets/certificates/csc-masterlist.json"));
const barrett_reduction_1 = require("./barrett-reduction");
const binary_1 = require("./binary");
const circuits_1 = require("./circuits");
const disclose_1 = require("./circuits/disclose");
const utils_1 = require("./cms/utils");
const constants_1 = require("./constants");
const merkle_tree_1 = require("./merkle-tree");
const passport_reader_1 = require("./passport/passport-reader");
const utils_2 = require("./utils");
const SUPPORTED_HASH_ALGORITHMS = ["SHA256", "SHA384", "SHA512"];
// TODO: Improve this with a structured list of supported signature algorithms
function isSignatureAlgorithmSupported(passport, signatureAlgorithm) {
    const tbsCertificate = (0, passport_reader_1.extractTBS)(passport);
    if (!tbsCertificate) {
        return false;
    }
    if (signatureAlgorithm === "ECDSA") {
        try {
            const ecdsaInfo = (0, utils_1.getECDSAInfo)(tbsCertificate.subjectPublicKeyInfo);
            return !!ecdsaInfo.curve;
        }
        catch (e) {
            return false;
        }
    }
    else if (signatureAlgorithm === "RSA") {
        const rsaInfo = (0, utils_1.getRSAInfo)(tbsCertificate.subjectPublicKeyInfo);
        const modulusBits = (0, utils_2.getBitSize)(rsaInfo.modulus);
        return ((modulusBits === 1024 ||
            modulusBits === 2048 ||
            modulusBits === 3072 ||
            modulusBits === 4096) &&
            (rsaInfo.exponent === 3n || rsaInfo.exponent === 65537n));
    }
    return false;
}
function isCSCSupported(csc) {
    if (csc.signature_algorithm.toLowerCase().includes("rsa")) {
        return ((csc.key_size === 1024 ||
            csc.key_size === 2048 ||
            csc.key_size === 3072 ||
            csc.key_size === 4096) &&
            (csc.public_key.exponent === 3 ||
                csc.public_key.exponent === 65537));
    }
    return (SUPPORTED_HASH_ALGORITHMS.some((x) => csc.signature_algorithm.toLowerCase().includes(x.toLowerCase())) ||
        // We assume that PSS is always sha256, sha384, or sha512
        csc.signature_algorithm.toLowerCase().includes("pss"));
}
function isIDSupported(passport) {
    const sodSignatureAlgorithm = (0, passport_reader_1.getSodSignatureAlgorithmType)(passport);
    return (isSignatureAlgorithmSupported(passport, sodSignatureAlgorithm) &&
        (SUPPORTED_HASH_ALGORITHMS.some((x) => passport.sod.certificate.signatureAlgorithm.name.toLowerCase().includes(x.toLowerCase())) ||
            // We assume that PSS is always sha256, sha384, or sha512
            passport.sod.certificate.signatureAlgorithm.name.toLowerCase().includes("pss")) &&
        (SUPPORTED_HASH_ALGORITHMS.some((x) => passport.sod.signerInfo.signatureAlgorithm.name.toLowerCase().includes(x.toLowerCase())) ||
            // We assume that PSS is always sha256, sha384, or sha512
            passport.sod.signerInfo.signatureAlgorithm.name.toLowerCase().includes("pss")) &&
        passport.sod.digestAlgorithms.every((digest) => SUPPORTED_HASH_ALGORITHMS.includes(digest)) &&
        SUPPORTED_HASH_ALGORITHMS.includes(passport.sod.encapContentInfo.eContent.hashAlgorithm) &&
        SUPPORTED_HASH_ALGORITHMS.includes(passport.sod.signerInfo.digestAlgorithm));
}
function getCSCMasterlist() {
    return csc_masterlist_json_1.default;
}
function getTBSMaxLen(passport) {
    const tbs_len = passport.sod.certificate.tbs.bytes.length;
    if (tbs_len <= 700) {
        return 700;
    }
    else if (tbs_len <= 1000) {
        return 1000;
    }
    else if (tbs_len <= 1200) {
        return 1200;
    }
    else {
        return 1500;
    }
}
function getCSCForPassport(passport, masterlist) {
    const cscMasterlist = masterlist ?? getCSCMasterlist();
    const extensions = passport.sod.certificate.tbs.extensions;
    let notBefore;
    let notAfter;
    const pkupBuffer = extensions.get("privateKeyUsagePeriod")?.value.toBuffer();
    if (pkupBuffer) {
        const pkup = asn1_schema_1.AsnParser.parse(pkupBuffer, asn1_x509_1.PrivateKeyUsagePeriod);
        notBefore = pkup.notBefore?.getTime() ?? 0 / 1000;
        notAfter = pkup.notAfter?.getTime() ?? 0 / 1000;
    }
    let authorityKeyIdentifier;
    const akiBuffer = extensions.get("authorityKeyIdentifier")?.value.toBuffer();
    if (akiBuffer) {
        const parsed = asn1_schema_1.AsnParser.parse(akiBuffer, asn1_x509_1.AuthorityKeyIdentifier);
        if (parsed?.keyIdentifier?.buffer) {
            authorityKeyIdentifier = binary_1.Binary.from(parsed.keyIdentifier.buffer).toHex().replace("0x", "");
        }
    }
    const country = getDSCCountry(passport);
    const formattedCountry = country === "D<<" ? "DEU" : country;
    const checkAgainstAuthorityKeyIdentifier = (cert) => {
        return (authorityKeyIdentifier &&
            cert.subject_key_identifier?.replace("0x", "") === authorityKeyIdentifier);
    };
    const checkAgainstPrivateKeyUsagePeriod = (cert) => {
        return (cert.private_key_usage_period &&
            cert.private_key_usage_period?.not_before &&
            cert.private_key_usage_period?.not_after &&
            notBefore &&
            notAfter &&
            notBefore >= (cert.private_key_usage_period?.not_before || 0) &&
            notAfter <= (cert.private_key_usage_period?.not_after || 0));
    };
    const certificate = cscMasterlist.certificates.find((cert) => {
        return (cert.country.toLowerCase() === formattedCountry.toLowerCase() &&
            (checkAgainstAuthorityKeyIdentifier(cert) || checkAgainstPrivateKeyUsagePeriod(cert)));
    });
    if (!certificate) {
        console.warn(`Could not find CSC for DSC`);
    }
    return certificate ?? null;
}
function getDSCDataInputs(passport, maxTbsLength) {
    const signatureAlgorithm = (0, passport_reader_1.getSodSignatureAlgorithmType)(passport);
    const tbsCertificate = (0, passport_reader_1.extractTBS)(passport);
    if (!tbsCertificate) {
        return null;
    }
    if (signatureAlgorithm === "ECDSA") {
        const ecdsaInfo = (0, utils_1.getECDSAInfo)(tbsCertificate.subjectPublicKeyInfo);
        // The first byte is 0x04, which is the ASN.1 sequence tag for a SEQUENCE of two integers
        // So we skip the first byte
        const dscPubkeyX = Array.from(ecdsaInfo.publicKey.slice(1, (ecdsaInfo.publicKey.length - 1) / 2 + 1));
        const dscPubkeyY = Array.from(ecdsaInfo.publicKey.slice((ecdsaInfo.publicKey.length - 1) / 2 + 1));
        return {
            tbs_certificate: (0, utils_2.rightPadArrayWithZeros)(passport?.tbsCertificate ?? [], maxTbsLength),
            pubkey_offset_in_tbs: (0, utils_2.getOffsetInArray)(passport?.tbsCertificate ?? [], dscPubkeyX),
            dsc_pubkey_x: dscPubkeyX,
            dsc_pubkey_y: dscPubkeyY,
        };
    }
    else {
        const { modulus, exponent } = (0, utils_1.getRSAInfo)(tbsCertificate.subjectPublicKeyInfo);
        const modulusBytes = (0, utils_2.bigintToBytes)(modulus);
        return {
            dsc_pubkey: modulusBytes,
            exponent: (0, utils_2.bigintToNumber)(exponent),
            dsc_pubkey_redc_param: (0, barrett_reduction_1.redcLimbsFromBytes)(modulusBytes),
            tbs_certificate: (0, utils_2.rightPadArrayWithZeros)(passport?.tbsCertificate ?? [], maxTbsLength),
            pubkey_offset_in_tbs: (0, utils_2.getOffsetInArray)(passport?.tbsCertificate ?? [], modulusBytes),
        };
    }
}
function getIDDataInputs(passport) {
    const dg1 = passport?.dataGroups.find((dg) => dg.groupNumber === 1);
    const dg1Offset = (0, utils_2.getOffsetInArray)(passport?.eContent ?? [], dg1?.hash ?? []);
    const id_data = {
        // Padded with 0s to make it 700 bytes
        e_content: (0, utils_2.rightPadArrayWithZeros)(passport?.eContent ?? [], 700),
        e_content_size: passport?.eContent?.length ?? 0,
        dg1_offset_in_e_content: dg1Offset,
        // Padded to 200 bytes with 0s
        signed_attributes: (0, utils_2.rightPadArrayWithZeros)(passport?.signedAttributes ?? [], 200),
        signed_attributes_size: passport?.signedAttributes?.length ?? 0,
        // Padded to 95 bytes with 0s
        dg1: (0, utils_2.rightPadArrayWithZeros)(dg1?.value ?? [], 95),
    };
    return id_data;
}
function processECDSASignature(signature, byteSize) {
    if (signature[0] !== 0x30) {
        // Not a valid ASN.1 sequence
        return signature;
    }
    const innerLengthIndex = signature[1] == signature.length - 2 ? 1 : 2;
    // This is the length of the inner sequence
    const innerLength = signature[innerLengthIndex];
    if (signature[innerLengthIndex + 1] !== 0x02 ||
        innerLength !== signature.length - innerLengthIndex - 1) {
        // Not a valid ASN.1 sequence
        return signature;
    }
    const rLength = signature[innerLengthIndex + 2];
    let r = signature.slice(innerLengthIndex + 3, innerLengthIndex + 3 + rLength);
    if (signature[innerLengthIndex + 3 + rLength] !== 0x02) {
        // Not a valid ASN.1 sequence
        return signature;
    }
    const sLength = signature[innerLengthIndex + 3 + rLength + 1];
    let s = signature.slice(innerLengthIndex + 3 + rLength + 2, innerLengthIndex + 3 + rLength + 2 + sLength);
    // Remove leading 0s
    for (let i = 0; i < r.length; i++) {
        if (r[i] !== 0x00) {
            r = r.slice(i);
            break;
        }
    }
    for (let i = 0; i < s.length; i++) {
        if (s[i] !== 0x00) {
            s = s.slice(i);
            break;
        }
    }
    // Pad r and s to the expected byte size
    r = (0, utils_2.leftPadArrayWithZeros)(r, byteSize);
    s = (0, utils_2.leftPadArrayWithZeros)(s, byteSize);
    return [...r, ...s];
}
function getScopeHash(value) {
    if (!value) {
        return 0n;
    }
    // Hash the value using SHA256 and truncate to 31 bytes (248 bits)
    const sha2Hash = (0, sha256_1.sha256)(value).slice(0, 31);
    // Convert the hash to a bigint
    const bytes = (0, utils_2.fromBytesToBigInt)(Array.from(sha2Hash));
    return bytes;
}
function processSodSignature(signature, passport) {
    const signatureAlgorithm = (0, passport_reader_1.getSodSignatureAlgorithmType)(passport);
    if (signatureAlgorithm === "ECDSA") {
        const tbsCertificate = (0, passport_reader_1.extractTBS)(passport);
        if (!tbsCertificate)
            return [];
        const ecdsaInfo = (0, utils_1.getECDSAInfo)(tbsCertificate.subjectPublicKeyInfo);
        const curve = ecdsaInfo.curve;
        const bitSize = (0, utils_1.getBitSizeFromCurve)(curve);
        return processECDSASignature(signature, Math.ceil(bitSize / 8));
    }
    else {
        return signature;
    }
}
async function getDSCCircuitInputs(passport, salt, merkleTreeLeaves, masterlist, merkleProof) {
    // Get the CSC for this passport's DSC
    const csc = getCSCForPassport(passport, masterlist);
    if (!csc)
        return null;
    // Generate the certificate registry merkle proof
    const cscMasterlist = masterlist ?? getCSCMasterlist();
    const leaves = merkleTreeLeaves ??
        (await Promise.all(cscMasterlist.certificates.map(async (cert) => {
            const hash = await (0, circuits_1.getCertificateLeafHash)(cert);
            return binary_1.Binary.fromHex(hash);
        })));
    const index = cscMasterlist.certificates.findIndex((cert) => cert.subject_key_identifier === csc.subject_key_identifier);
    const finalMerkleProof = merkleProof ?? (await (0, merkle_tree_1.computeMerkleProof)(leaves, index, constants_1.CERTIFICATE_REGISTRY_HEIGHT));
    const inputs = {
        certificate_registry_root: finalMerkleProof.root,
        certificate_registry_index: finalMerkleProof.index,
        certificate_registry_hash_path: finalMerkleProof.path,
        certificate_registry_id: constants_1.CERTIFICATE_REGISTRY_ID,
        certificate_type: 1,
        country: csc.country,
        salt: `0x${salt.toString(16)}`,
    };
    const signatureAlgorithm = (0, passport_reader_1.getDSCSignatureAlgorithmType)(passport);
    const maxTbsLength = getTBSMaxLen(passport);
    if (signatureAlgorithm === "ECDSA") {
        const cscPublicKey = csc?.public_key;
        const publicKeyXBytes = Buffer.from(cscPublicKey.public_key_x.replace("0x", ""), "hex");
        const publicKeyYBytes = Buffer.from(cscPublicKey.public_key_y.replace("0x", ""), "hex");
        const curve = csc.public_key.curve;
        const bitSize = (0, utils_1.getBitSizeFromCurve)(curve);
        const dscSignature = processECDSASignature(passport?.dscSignature ?? [], Math.ceil(bitSize / 8));
        return {
            ...inputs,
            csc_pubkey_x: Array.from(publicKeyXBytes),
            csc_pubkey_y: Array.from(publicKeyYBytes),
            dsc_signature: dscSignature,
            tbs_certificate: (0, utils_2.rightPadArrayWithZeros)(passport?.tbsCertificate ?? [], maxTbsLength),
            tbs_certificate_len: passport?.tbsCertificate?.length,
        };
    }
    else if (signatureAlgorithm === "RSA") {
        const cscPublicKey = csc?.public_key;
        const modulusBytes = (0, utils_2.bigintToBytes)(BigInt(cscPublicKey.modulus));
        return {
            ...inputs,
            tbs_certificate: (0, utils_2.rightPadArrayWithZeros)(passport?.tbsCertificate ?? [], maxTbsLength),
            tbs_certificate_len: passport?.tbsCertificate?.length,
            dsc_signature: passport?.dscSignature ?? [],
            csc_pubkey: modulusBytes,
            csc_pubkey_redc_param: (0, barrett_reduction_1.redcLimbsFromBytes)(modulusBytes),
            exponent: cscPublicKey.exponent,
        };
    }
}
async function getIDDataCircuitInputs(passport, saltIn, saltOut) {
    const idData = getIDDataInputs(passport);
    const maxTbsLength = getTBSMaxLen(passport);
    const dscData = getDSCDataInputs(passport, maxTbsLength);
    if (!dscData || !idData)
        return null;
    const commIn = await (0, circuits_1.hashSaltCountryTbs)(saltIn, getDSCCountry(passport), binary_1.Binary.from(passport.tbsCertificate), maxTbsLength);
    const inputs = {
        dg1: idData.dg1,
        signed_attributes: idData.signed_attributes,
        signed_attributes_size: idData.signed_attributes_size,
        comm_in: commIn.toHex(),
        salt_in: `0x${saltIn.toString(16)}`,
        salt_out: `0x${saltOut.toString(16)}`,
    };
    const signatureAlgorithm = (0, passport_reader_1.getSodSignatureAlgorithmType)(passport);
    if (signatureAlgorithm === "ECDSA") {
        return {
            ...inputs,
            tbs_certificate: dscData.tbs_certificate,
            pubkey_offset_in_tbs: dscData.pubkey_offset_in_tbs,
            dsc_pubkey_x: dscData.dsc_pubkey_x,
            dsc_pubkey_y: dscData.dsc_pubkey_y,
            sod_signature: processSodSignature(passport?.sodSignature ?? [], passport),
            signed_attributes: idData.signed_attributes,
            signed_attributes_size: idData.signed_attributes_size,
        };
    }
    else if (signatureAlgorithm === "RSA") {
        return {
            ...inputs,
            dsc_pubkey: dscData.dsc_pubkey,
            exponent: dscData.exponent,
            sod_signature: passport?.sodSignature ?? [],
            dsc_pubkey_redc_param: dscData.dsc_pubkey_redc_param,
            tbs_certificate: dscData.tbs_certificate,
            pubkey_offset_in_tbs: dscData.pubkey_offset_in_tbs,
            signed_attributes: idData.signed_attributes,
            signed_attributes_size: idData.signed_attributes_size,
        };
    }
}
function getDSCCountry(passport) {
    const country = passport.sod.certificate.tbs.issuer?.match(/countryName=([A-Z]+)/)?.[1];
    const formattedCountryCode = country?.length === 2 ? (0, i18n_iso_countries_1.alpha2ToAlpha3)(country) : country;
    return formattedCountryCode ?? passport.nationality;
}
async function getIntegrityCheckCircuitInputs(passport, saltIn, saltOut) {
    const maxTbsLength = getTBSMaxLen(passport);
    const dscData = getDSCDataInputs(passport, maxTbsLength);
    if (!dscData)
        return null;
    const idData = getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const comm_in = await (0, circuits_1.hashSaltCountrySignedAttrDg1PrivateNullifier)(saltIn, getDSCCountry(passport), binary_1.Binary.from(passport.signedAttributes).padEnd(constants_1.SIGNED_ATTR_INPUT_SIZE), BigInt(passport.signedAttributes.length), binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    return {
        current_date: (0, date_fns_1.format)(new Date(), "yyyyMMdd"),
        dg1: idData.dg1,
        signed_attributes: idData.signed_attributes,
        signed_attributes_size: idData.signed_attributes_size,
        e_content: idData.e_content,
        e_content_size: idData.e_content_size,
        dg1_offset_in_e_content: idData.dg1_offset_in_e_content,
        comm_in: comm_in.toHex(),
        private_nullifier: privateNullifier.toHex(),
        salt_in: `0x${saltIn.toString(16)}`,
        salt_out: `0x${saltOut.toString(16)}`,
    };
}
function getFirstNameRange(passport) {
    const mrz = passport?.mrz;
    const isIDCard = mrz.length == 90;
    const lastNameStartIndex = isIDCard ? 60 : 5;
    const firstNameStartIndex = (0, utils_2.getOffsetInArray)(mrz.split(""), ["<", "<"], lastNameStartIndex) + 2;
    const firstNameEndIndex = (0, utils_2.getOffsetInArray)(mrz.split(""), ["<"], firstNameStartIndex);
    // Subtract 2 from the start index to include the two angle brackets
    return [firstNameStartIndex - 2, firstNameEndIndex];
}
function getLastNameRange(passport) {
    const mrz = passport?.mrz;
    const isIDCard = mrz.length == 90;
    const lastNameStartIndex = isIDCard ? 60 : 5;
    const lastNameEndIndex = (0, utils_2.getOffsetInArray)(mrz.split(""), ["<", "<"], lastNameStartIndex);
    // Add 2 to the end index to include the two angle brackets
    return [lastNameStartIndex, lastNameEndIndex + 2];
}
function getFullNameRange(passport) {
    const mrz = passport?.mrz;
    const isIDCard = mrz.length == 90;
    return [isIDCard ? 60 : 5, isIDCard ? 90 : 44];
}
function getBirthdateRange(passport) {
    const mrz = passport?.mrz;
    const isIDCard = mrz.length == 90;
    return [isIDCard ? 30 : 57, isIDCard ? 36 : 63];
}
function getDocumentNumberRange(passport) {
    const mrz = passport?.mrz;
    const isIDCard = mrz.length == 90;
    return [isIDCard ? 5 : 44, isIDCard ? 14 : 53];
}
function getNationalityRange(passport) {
    const mrz = passport?.mrz;
    const isIDCard = mrz.length == 90;
    return [isIDCard ? 45 : 54, isIDCard ? 48 : 57];
}
function getExpiryDateRange(passport) {
    const mrz = passport?.mrz;
    const isIDCard = mrz.length == 90;
    return [isIDCard ? 38 : 65, isIDCard ? 44 : 71];
}
function getGenderRange(passport) {
    const mrz = passport?.mrz;
    const isIDCard = mrz.length == 90;
    return [isIDCard ? 37 : 64, isIDCard ? 38 : 65];
}
async function getDiscloseCircuitInputs(passport, query, salt, service_scope = 0n, service_subscope = 0n) {
    const idData = getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const commIn = await (0, circuits_1.hashSaltDg1PrivateNullifier)(salt, binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    const discloseMask = Array(90).fill(0);
    let fieldsToDisclose = {};
    for (const field in query) {
        if (query[field]?.disclose || query[field]?.eq) {
            fieldsToDisclose[field] = true;
        }
    }
    for (const field in fieldsToDisclose) {
        if (fieldsToDisclose[field]) {
            switch (field) {
                case "firstname":
                    const firstNameRange = getFirstNameRange(passport);
                    discloseMask.fill(1, firstNameRange[0], firstNameRange[1]);
                    break;
                case "lastname":
                    const lastNameRange = getLastNameRange(passport);
                    discloseMask.fill(1, lastNameRange[0], lastNameRange[1]);
                    break;
                case "fullname":
                    const fullNameRange = getFullNameRange(passport);
                    discloseMask.fill(1, fullNameRange[0], fullNameRange[1]);
                    break;
                case "birthdate":
                    const birthdateRange = getBirthdateRange(passport);
                    discloseMask.fill(1, birthdateRange[0], birthdateRange[1]);
                    break;
                case "document_number":
                    const documentNumberRange = getDocumentNumberRange(passport);
                    discloseMask.fill(1, documentNumberRange[0], documentNumberRange[1]);
                    break;
                case "nationality":
                    const nationalityRange = getNationalityRange(passport);
                    discloseMask.fill(1, nationalityRange[0], nationalityRange[1]);
                    break;
                case "document_type":
                    discloseMask.fill(1, 0, 2);
                    break;
                case "expiry_date":
                    const expiryDateRange = getExpiryDateRange(passport);
                    discloseMask.fill(1, expiryDateRange[0], expiryDateRange[1]);
                    break;
                case "gender":
                    const genderRange = getGenderRange(passport);
                    discloseMask.fill(1, genderRange[0], genderRange[1]);
                    break;
                case "issuing_country":
                    discloseMask.fill(1, 2, 5);
                    break;
            }
        }
    }
    return {
        dg1: idData.dg1,
        disclose_mask: discloseMask,
        comm_in: commIn.toHex(),
        private_nullifier: privateNullifier.toHex(),
        service_scope: `0x${service_scope.toString(16)}`,
        service_subscope: `0x${service_subscope.toString(16)}`,
        salt: `0x${salt.toString(16)}`,
    };
}
async function getDiscloseFlagsCircuitInputs(passport, query, salt, service_scope = 0n, service_subscope = 0n) {
    const idData = getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const commIn = await (0, circuits_1.hashSaltDg1PrivateNullifier)(salt, binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    const discloseFlags = {
        issuing_country: query.issuing_country?.disclose ?? false,
        nationality: query.nationality?.disclose ?? false,
        document_type: query.document_type?.disclose ?? false,
        document_number: query.document_number?.disclose ?? false,
        date_of_expiry: query.expiry_date?.disclose ?? false,
        date_of_birth: query.birthdate?.disclose ?? false,
        gender: query.gender?.disclose ?? false,
        name: query.fullname?.disclose ?? false,
    };
    return {
        dg1: idData.dg1,
        disclose_flags: discloseFlags,
        comm_in: commIn.toHex(),
        private_nullifier: privateNullifier.toHex(),
        service_scope: `0x${service_scope.toString(16)}`,
        service_subscope: `0x${service_subscope.toString(16)}`,
        salt: `0x${salt.toString(16)}`,
    };
}
function calculateAge(passport) {
    const birthdate = passport.dateOfBirth;
    if (!birthdate)
        return 0;
    const birthdateDate = (0, disclose_1.parseDate)(new TextEncoder().encode(birthdate));
    const currentDate = new Date();
    let age = currentDate.getFullYear() - birthdateDate.getFullYear();
    const monthDiff = currentDate.getMonth() - birthdateDate.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && currentDate.getDate() < birthdateDate.getDate())) {
        age--;
    }
    return age;
}
async function getAgeCircuitInputs(passport, query, salt, service_scope = 0n, service_subscope = 0n) {
    const idData = await getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const commIn = await (0, circuits_1.hashSaltDg1PrivateNullifier)(salt, binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    let age = calculateAge(passport);
    let minAge = 0;
    let maxAge = 0;
    if (query.age) {
        if (query.age.gt) {
            minAge = query.age.gt;
        }
        else if (query.age.gte) {
            minAge = query.age.gte;
        }
        else if (query.age.range) {
            minAge = query.age.range[0];
            maxAge = query.age.range[1];
        }
        else if (query.age.eq) {
            minAge = query.age.eq;
            maxAge = query.age.eq;
        }
        else if (query.age.disclose) {
            minAge = age;
            maxAge = age;
        }
        if (query.age.lt) {
            maxAge = query.age.lt;
        }
        else if (query.age.lte) {
            maxAge = query.age.lte;
        }
    }
    return {
        dg1: idData.dg1,
        current_date: (0, date_fns_1.format)(new Date(), "yyyyMMdd"),
        comm_in: commIn.toHex(),
        private_nullifier: privateNullifier.toHex(),
        service_scope: `0x${service_scope.toString(16)}`,
        service_subscope: `0x${service_subscope.toString(16)}`,
        salt: `0x${salt.toString(16)}`,
        min_age_required: minAge,
        max_age_required: maxAge,
    };
}
function padCountryList(countryList) {
    const paddedCountryList = Array(200).fill(new TextDecoder().decode(new Uint8Array([0, 0, 0])));
    for (let i = 0; i < countryList.length; i++) {
        paddedCountryList[i] = countryList[i];
    }
    return paddedCountryList;
}
async function getNationalityInclusionCircuitInputs(passport, query, salt, service_scope = 0n, service_subscope = 0n) {
    const idData = getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const commIn = await (0, circuits_1.hashSaltDg1PrivateNullifier)(salt, binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    return {
        dg1: idData.dg1,
        country_list: padCountryList(query.nationality?.in ?? []),
        comm_in: commIn.toHex(),
        private_nullifier: privateNullifier.toHex(),
        service_scope: `0x${service_scope.toString(16)}`,
        service_subscope: `0x${service_subscope.toString(16)}`,
        salt: `0x${salt.toString(16)}`,
    };
}
async function getIssuingCountryInclusionCircuitInputs(passport, query, salt, service_scope = 0n, service_subscope = 0n) {
    const idData = getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const commIn = await (0, circuits_1.hashSaltDg1PrivateNullifier)(salt, binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    return {
        dg1: idData.dg1,
        country_list: padCountryList(query.issuing_country?.in ?? []),
        comm_in: commIn.toHex(),
        private_nullifier: privateNullifier.toHex(),
        service_scope: `0x${service_scope.toString(16)}`,
        service_subscope: `0x${service_subscope.toString(16)}`,
        salt: `0x${salt.toString(16)}`,
    };
}
async function getNationalityExclusionCircuitInputs(passport, query, salt, service_scope = 0n, service_subscope = 0n) {
    const idData = getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const commIn = await (0, circuits_1.hashSaltDg1PrivateNullifier)(salt, binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    const countryList = [];
    for (let i = 0; i < (query.nationality?.out ?? []).length; i++) {
        const country = (query.nationality?.out ?? [])[i];
        countryList.push((0, circuits_1.getCountryWeightedSum)(country));
    }
    return {
        dg1: idData.dg1,
        // Sort the country list in ascending order
        country_list: (0, utils_2.rightPadArrayWithZeros)(countryList.sort((a, b) => a - b), 200),
        comm_in: commIn.toHex(),
        private_nullifier: privateNullifier.toHex(),
        service_scope: `0x${service_scope.toString(16)}`,
        service_subscope: `0x${service_subscope.toString(16)}`,
        salt: `0x${salt.toString(16)}`,
    };
}
async function getIssuingCountryExclusionCircuitInputs(passport, query, salt, service_scope = 0n, service_subscope = 0n) {
    const idData = getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const commIn = await (0, circuits_1.hashSaltDg1PrivateNullifier)(salt, binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    const countryList = [];
    for (let i = 0; i < (query.issuing_country?.out ?? []).length; i++) {
        const country = (query.issuing_country?.out ?? [])[i];
        countryList.push((0, circuits_1.getCountryWeightedSum)(country));
    }
    return {
        dg1: idData.dg1,
        // Sort the country list in ascending order
        country_list: (0, utils_2.rightPadArrayWithZeros)(countryList.sort((a, b) => a - b), 200),
        comm_in: commIn.toHex(),
        private_nullifier: privateNullifier.toHex(),
        service_scope: `0x${service_scope.toString(16)}`,
        service_subscope: `0x${service_subscope.toString(16)}`,
        salt: `0x${salt.toString(16)}`,
    };
}
async function getBirthdateCircuitInputs(passport, query, salt, service_scope = 0n, service_subscope = 0n) {
    const idData = getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const commIn = await (0, circuits_1.hashSaltDg1PrivateNullifier)(salt, binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    let minDate;
    let maxDate;
    if (query.birthdate) {
        if (query.birthdate.gt) {
            minDate = query.birthdate.gt;
        }
        else if (query.birthdate.gte) {
            minDate = query.birthdate.gte;
        }
        else if (query.birthdate.range) {
            minDate = query.birthdate.range[0];
            maxDate = query.birthdate.range[1];
        }
        else if (query.birthdate.eq) {
            minDate = query.birthdate.eq;
            maxDate = query.birthdate.eq;
        }
        else if (query.birthdate.disclose) {
            minDate = (0, disclose_1.parseDate)(new TextEncoder().encode(passport.dateOfBirth));
            maxDate = (0, disclose_1.parseDate)(new TextEncoder().encode(passport.dateOfBirth));
        }
        if (query.birthdate.lt) {
            maxDate = query.birthdate.lt;
        }
        else if (query.birthdate.lte) {
            maxDate = query.birthdate.lte;
        }
    }
    return {
        dg1: idData.dg1,
        current_date: (0, date_fns_1.format)(new Date(), "yyyyMMdd"),
        comm_in: commIn.toHex(),
        private_nullifier: privateNullifier.toHex(),
        service_scope: `0x${service_scope.toString(16)}`,
        service_subscope: `0x${service_subscope.toString(16)}`,
        salt: `0x${salt.toString(16)}`,
        // "11111111" means the date is ignored
        min_date: minDate ? (0, date_fns_1.format)(minDate, "yyyyMMdd") : "1".repeat(8),
        max_date: maxDate ? (0, date_fns_1.format)(maxDate, "yyyyMMdd") : "1".repeat(8),
    };
}
async function getExpiryDateCircuitInputs(passport, query, salt, service_scope = 0n, service_subscope = 0n) {
    const idData = getIDDataInputs(passport);
    if (!idData)
        return null;
    const privateNullifier = await (0, circuits_1.calculatePrivateNullifier)(binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), binary_1.Binary.from(processSodSignature(passport?.sodSignature ?? [], passport)));
    const commIn = await (0, circuits_1.hashSaltDg1PrivateNullifier)(salt, binary_1.Binary.from(idData.dg1).padEnd(constants_1.DG1_INPUT_SIZE), privateNullifier.toBigInt());
    let minDate;
    let maxDate;
    if (query.expiry_date) {
        if (query.expiry_date.gt) {
            minDate = query.expiry_date.gt;
        }
        else if (query.expiry_date.gte) {
            minDate = query.expiry_date.gte;
        }
        else if (query.expiry_date.range) {
            minDate = query.expiry_date.range[0];
            maxDate = query.expiry_date.range[1];
        }
        else if (query.expiry_date.eq) {
            minDate = query.expiry_date.eq;
            maxDate = query.expiry_date.eq;
        }
        else if (query.expiry_date.disclose) {
            minDate = (0, disclose_1.parseDate)(new TextEncoder().encode(passport.passportExpiry));
            maxDate = (0, disclose_1.parseDate)(new TextEncoder().encode(passport.passportExpiry));
        }
        if (query.expiry_date.lt) {
            maxDate = query.expiry_date.lt;
        }
        else if (query.expiry_date.lte) {
            maxDate = query.expiry_date.lte;
        }
    }
    return {
        dg1: idData.dg1,
        current_date: (0, date_fns_1.format)(new Date(), "yyyyMMdd"),
        comm_in: commIn.toHex(),
        private_nullifier: privateNullifier.toHex(),
        service_scope: `0x${service_scope.toString(16)}`,
        service_subscope: `0x${service_subscope.toString(16)}`,
        salt: `0x${salt.toString(16)}`,
        // "11111111" means the date is ignored
        min_date: minDate ? (0, date_fns_1.format)(minDate, "yyyyMMdd") : "1".repeat(8),
        max_date: maxDate ? (0, date_fns_1.format)(maxDate, "yyyyMMdd") : "1".repeat(8),
    };
}
