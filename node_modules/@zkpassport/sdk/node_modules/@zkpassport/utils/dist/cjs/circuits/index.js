"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getDiscloseEVMParameterCommitment = exports.getDiscloseParameterCommitment = exports.getDisclosedBytesFromMrzAndMask = exports.parseDocumentType = exports.formatName = exports.createDisclosedDataRaw = exports.DisclosedData = exports.ProofType = exports.DEFAULT_DATE_VALUE = void 0;
exports.calculatePrivateNullifier = calculatePrivateNullifier;
exports.hashSaltCountryTbs = hashSaltCountryTbs;
exports.hashSaltCountrySignedAttrDg1PrivateNullifier = hashSaltCountrySignedAttrDg1PrivateNullifier;
exports.hashSaltDg1PrivateNullifier = hashSaltDg1PrivateNullifier;
exports.getCertificateLeafHash = getCertificateLeafHash;
exports.getNullifierFromDisclosureProof = getNullifierFromDisclosureProof;
exports.getParameterCommitmentFromDisclosureProof = getParameterCommitmentFromDisclosureProof;
exports.getServiceSubScopeFromDisclosureProof = getServiceSubScopeFromDisclosureProof;
exports.getServiceScopeFromDisclosureProof = getServiceScopeFromDisclosureProof;
exports.getCommitmentInFromDisclosureProof = getCommitmentInFromDisclosureProof;
exports.getHostedPackagedCircuitByNameAndHash = getHostedPackagedCircuitByNameAndHash;
exports.getHostedPackagedCircuitByVkeyHash = getHostedPackagedCircuitByVkeyHash;
exports.getHostedPackagedCircuitByName = getHostedPackagedCircuitByName;
exports.getNumberOfPublicInputs = getNumberOfPublicInputs;
exports.getCommittedInputCount = getCommittedInputCount;
exports.getFormattedDate = getFormattedDate;
exports.getDateBytes = getDateBytes;
exports.getCurrentDateFromCommittedInputs = getCurrentDateFromCommittedInputs;
const tslib_1 = require("tslib");
const constants_1 = require("../constants");
const binary_1 = require("../binary");
const poseidon2_1 = require("@zkpassport/poseidon2");
const disclose_1 = require("./disclose");
const disclose_2 = require("./disclose");
const integrity_1 = require("./integrity");
const age_1 = require("./age");
const date_1 = require("./date");
const dsc_1 = require("./dsc");
const __1 = require("..");
const date_fns_1 = require("date-fns");
async function calculatePrivateNullifier(dg1, sodSig) {
    return binary_1.Binary.from(await (0, poseidon2_1.poseidon2HashAsync)([
        ...Array.from(dg1).map((x) => BigInt(x)),
        ...Array.from(sodSig).map((x) => BigInt(x)),
    ]));
}
async function hashSaltCountryTbs(salt, country, tbs, maxTbsLength) {
    const result = [];
    result.push(salt);
    result.push(...country.split("").map((x) => BigInt(x.charCodeAt(0))));
    result.push(...Array.from(tbs.padEnd(maxTbsLength)).map((x) => BigInt(x)));
    return binary_1.Binary.from(await (0, poseidon2_1.poseidon2HashAsync)(result.map((x) => BigInt(x))));
}
async function hashSaltCountrySignedAttrDg1PrivateNullifier(salt, country, paddedSignedAttr, signedAttrSize, dg1, privateNullifier) {
    const result = [];
    result.push(salt);
    result.push(...country.split("").map((x) => BigInt(x.charCodeAt(0))));
    result.push(...Array.from(paddedSignedAttr).map((x) => BigInt(x)));
    result.push(signedAttrSize);
    result.push(...Array.from(dg1).map((x) => BigInt(x)));
    result.push(privateNullifier);
    return binary_1.Binary.from(await (0, poseidon2_1.poseidon2HashAsync)(result.map((x) => BigInt(x))));
}
async function hashSaltDg1PrivateNullifier(salt, dg1, privateNullifier) {
    const result = [];
    result.push(salt);
    result.push(...Array.from(dg1).map((x) => BigInt(x)));
    result.push(privateNullifier);
    return binary_1.Binary.from(await (0, poseidon2_1.poseidon2HashAsync)(result.map((x) => BigInt(x))));
}
async function getCertificateLeafHash(cert, options) {
    const registryId = options?.registry_id ?? constants_1.CERTIFICATE_REGISTRY_ID;
    const certType = options?.cert_type ?? constants_1.CERT_TYPE_CSC;
    let publicKey;
    if (cert.public_key.type === "rsaEncryption") {
        publicKey = binary_1.Binary.from(cert.public_key.modulus);
    }
    else if (cert.public_key.type === "ecPublicKey") {
        publicKey = binary_1.Binary.from(cert.public_key.public_key_x).concat(binary_1.Binary.from(cert.public_key.public_key_y));
    }
    else {
        throw new Error("Unsupported signature algorithm");
    }
    return binary_1.Binary.from(await (0, poseidon2_1.poseidon2HashAsync)([
        BigInt(registryId),
        BigInt(certType),
        ...Array.from(cert.country).map((char) => BigInt(char.charCodeAt(0))),
        ...Array.from(publicKey).map((x) => BigInt(x)),
    ])).toHex();
}
function getNullifierFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 1]);
}
function getParameterCommitmentFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 2]);
}
function getServiceSubScopeFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 3]);
}
function getServiceScopeFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 4]);
}
function getCommitmentInFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[0]);
}
async function getHostedPackagedCircuitByNameAndHash(name, vkeyHash) {
    const response = await fetch(`https://circuits.zkpassport.id/artifacts/${name}_${vkeyHash
        .replace("0x", "")
        .substring(0, 16)}.json.gz`);
    const circuit = await response.json();
    return circuit;
}
async function getHostedPackagedCircuitByVkeyHash(vkeyHash) {
    const response = await fetch(`https://circuits.zkpassport.id/hashes/${vkeyHash.replace("0x", "")}.json.gz`);
    const circuit = await response.json();
    return circuit;
}
async function getHostedPackagedCircuitByName(version, name) {
    const response = await fetch(`https://circuits.zkpassport.id/versions/${version}/${name}.json.gz`);
    const circuit = await response.json();
    return circuit;
}
/**
 * Get the number of public inputs for a circuit.
 * @param circuitName - The name of the circuit.
 * @returns The number of public inputs.
 */
function getNumberOfPublicInputs(circuitName) {
    if (circuitName.startsWith("disclose_bytes")) {
        return (0, disclose_2.getDiscloseBytesProofPublicInputCount)();
    }
    else if (circuitName.startsWith("disclose_flags")) {
        return (0, disclose_1.getDiscloseFlagsProofPublicInputCount)();
    }
    else if (circuitName.startsWith("compare_age")) {
        return (0, age_1.getAgeProofPublicInputCount)();
    }
    else if (circuitName.startsWith("compare_birthdate") ||
        circuitName.startsWith("compare_expiry")) {
        return (0, date_1.getDateProofPublicInputCount)();
    }
    else if (circuitName.startsWith("exclusion_check")) {
        return (0, __1.getCountryExclusionProofPublicInputCount)();
    }
    else if (circuitName.startsWith("inclusion_check")) {
        return (0, __1.getCountryInclusionProofPublicInputCount)();
    }
    else if (circuitName.startsWith("data_check_integrity")) {
        return (0, integrity_1.getIntegrityProofPublicInputCount)();
    }
    else if (circuitName.startsWith("sig_check_id_data")) {
        return (0, __1.getIDDataProofPublicInputCount)();
    }
    else if (circuitName.startsWith("sig_check_dsc")) {
        return (0, dsc_1.getDSCProofPublicInputCount)();
    }
    else if (circuitName.startsWith("outer")) {
        // Get the characters after the last underscore
        const disclosureProofCount = Number(circuitName.substring(circuitName.lastIndexOf("_") + 1)) - 3;
        return 12 + disclosureProofCount;
    }
    return 0;
}
function getCommittedInputCount(circuitName) {
    switch (circuitName) {
        case "compare_age_evm":
            return 11;
        case "compare_birthdate_evm":
            return 25;
        case "compare_expiry_evm":
            return 25;
        case "disclose_bytes_evm":
            return 181;
        case "inclusion_check_issuing_country_evm":
            return 601;
        case "inclusion_check_nationality_evm":
            return 601;
        case "exclusion_check_issuing_country_evm":
            return 601;
        case "exclusion_check_nationality_evm":
            return 601;
        case "compare_age":
            return 11;
        case "compare_birthdate":
            return 25;
        case "compare_expiry":
            return 25;
        case "disclose_bytes":
            return 181;
        case "inclusion_check_issuing_country":
            return 201;
        case "inclusion_check_nationality":
            return 201;
        case "exclusion_check_issuing_country":
            return 201;
        case "exclusion_check_nationality":
            return 201;
        default:
            throw new Error(`Unknown circuit name: ${circuitName}`);
    }
}
function getFormattedDate(date) {
    return (0, date_fns_1.formatDate)(date, "yyyyMMdd");
}
function getDateBytes(date) {
    return binary_1.Binary.from(new TextEncoder().encode(getFormattedDate(date)));
}
function getCurrentDateFromCommittedInputs(committedInputs) {
    return (0, __1.convertDateBytesToDate)(committedInputs.currentDate);
}
exports.DEFAULT_DATE_VALUE = new Date(Date.UTC(1111, 10, 11));
var ProofType;
(function (ProofType) {
    ProofType[ProofType["DISCLOSE"] = 0] = "DISCLOSE";
    ProofType[ProofType["AGE"] = 1] = "AGE";
    ProofType[ProofType["BIRTHDATE"] = 2] = "BIRTHDATE";
    ProofType[ProofType["EXPIRY_DATE"] = 3] = "EXPIRY_DATE";
    ProofType[ProofType["NATIONALITY_INCLUSION"] = 4] = "NATIONALITY_INCLUSION";
    ProofType[ProofType["NATIONALITY_EXCLUSION"] = 5] = "NATIONALITY_EXCLUSION";
    ProofType[ProofType["ISSUING_COUNTRY_INCLUSION"] = 6] = "ISSUING_COUNTRY_INCLUSION";
    ProofType[ProofType["ISSUING_COUNTRY_EXCLUSION"] = 7] = "ISSUING_COUNTRY_EXCLUSION";
})(ProofType || (exports.ProofType = ProofType = {}));
var disclose_3 = require("./disclose");
Object.defineProperty(exports, "DisclosedData", { enumerable: true, get: function () { return disclose_3.DisclosedData; } });
Object.defineProperty(exports, "createDisclosedDataRaw", { enumerable: true, get: function () { return disclose_3.createDisclosedDataRaw; } });
Object.defineProperty(exports, "formatName", { enumerable: true, get: function () { return disclose_3.formatName; } });
Object.defineProperty(exports, "parseDocumentType", { enumerable: true, get: function () { return disclose_3.parseDocumentType; } });
Object.defineProperty(exports, "getDisclosedBytesFromMrzAndMask", { enumerable: true, get: function () { return disclose_3.getDisclosedBytesFromMrzAndMask; } });
Object.defineProperty(exports, "getDiscloseParameterCommitment", { enumerable: true, get: function () { return disclose_3.getDiscloseParameterCommitment; } });
Object.defineProperty(exports, "getDiscloseEVMParameterCommitment", { enumerable: true, get: function () { return disclose_3.getDiscloseEVMParameterCommitment; } });
tslib_1.__exportStar(require("./country"), exports);
tslib_1.__exportStar(require("./age"), exports);
tslib_1.__exportStar(require("./date"), exports);
tslib_1.__exportStar(require("./integrity"), exports);
tslib_1.__exportStar(require("./id-data"), exports);
tslib_1.__exportStar(require("./dsc"), exports);
tslib_1.__exportStar(require("./vkey"), exports);
