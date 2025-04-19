import { CERTIFICATE_REGISTRY_ID, CERT_TYPE_CSC } from "../constants/index.js";
import { Binary } from "../binary/index.js";
import { poseidon2HashAsync } from "@zkpassport/poseidon2";
import { getDiscloseFlagsProofPublicInputCount } from "./disclose.js";
import { getDiscloseBytesProofPublicInputCount } from "./disclose.js";
import { getIntegrityProofPublicInputCount } from "./integrity.js";
import { getAgeProofPublicInputCount } from "./age.js";
import { getDateProofPublicInputCount } from "./date.js";
import { getDSCProofPublicInputCount } from "./dsc.js";
import { convertDateBytesToDate, getCountryExclusionProofPublicInputCount, getCountryInclusionProofPublicInputCount, getIDDataProofPublicInputCount, } from "../index.js";
import { formatDate } from "date-fns";
export async function calculatePrivateNullifier(dg1, sodSig) {
    return Binary.from(await poseidon2HashAsync([
        ...Array.from(dg1).map((x) => BigInt(x)),
        ...Array.from(sodSig).map((x) => BigInt(x)),
    ]));
}
export async function hashSaltCountryTbs(salt, country, tbs, maxTbsLength) {
    const result = [];
    result.push(salt);
    result.push(...country.split("").map((x) => BigInt(x.charCodeAt(0))));
    result.push(...Array.from(tbs.padEnd(maxTbsLength)).map((x) => BigInt(x)));
    return Binary.from(await poseidon2HashAsync(result.map((x) => BigInt(x))));
}
export async function hashSaltCountrySignedAttrDg1PrivateNullifier(salt, country, paddedSignedAttr, signedAttrSize, dg1, privateNullifier) {
    const result = [];
    result.push(salt);
    result.push(...country.split("").map((x) => BigInt(x.charCodeAt(0))));
    result.push(...Array.from(paddedSignedAttr).map((x) => BigInt(x)));
    result.push(signedAttrSize);
    result.push(...Array.from(dg1).map((x) => BigInt(x)));
    result.push(privateNullifier);
    return Binary.from(await poseidon2HashAsync(result.map((x) => BigInt(x))));
}
export async function hashSaltDg1PrivateNullifier(salt, dg1, privateNullifier) {
    const result = [];
    result.push(salt);
    result.push(...Array.from(dg1).map((x) => BigInt(x)));
    result.push(privateNullifier);
    return Binary.from(await poseidon2HashAsync(result.map((x) => BigInt(x))));
}
export async function getCertificateLeafHash(cert, options) {
    const registryId = options?.registry_id ?? CERTIFICATE_REGISTRY_ID;
    const certType = options?.cert_type ?? CERT_TYPE_CSC;
    let publicKey;
    if (cert.public_key.type === "rsaEncryption") {
        publicKey = Binary.from(cert.public_key.modulus);
    }
    else if (cert.public_key.type === "ecPublicKey") {
        publicKey = Binary.from(cert.public_key.public_key_x).concat(Binary.from(cert.public_key.public_key_y));
    }
    else {
        throw new Error("Unsupported signature algorithm");
    }
    return Binary.from(await poseidon2HashAsync([
        BigInt(registryId),
        BigInt(certType),
        ...Array.from(cert.country).map((char) => BigInt(char.charCodeAt(0))),
        ...Array.from(publicKey).map((x) => BigInt(x)),
    ])).toHex();
}
export function getNullifierFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 1]);
}
export function getParameterCommitmentFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 2]);
}
export function getServiceSubScopeFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 3]);
}
export function getServiceScopeFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[proofData.publicInputs.length - 4]);
}
export function getCommitmentInFromDisclosureProof(proofData) {
    return BigInt(proofData.publicInputs[0]);
}
export async function getHostedPackagedCircuitByNameAndHash(name, vkeyHash) {
    const response = await fetch(`https://circuits.zkpassport.id/artifacts/${name}_${vkeyHash
        .replace("0x", "")
        .substring(0, 16)}.json.gz`);
    const circuit = await response.json();
    return circuit;
}
export async function getHostedPackagedCircuitByVkeyHash(vkeyHash) {
    const response = await fetch(`https://circuits.zkpassport.id/hashes/${vkeyHash.replace("0x", "")}.json.gz`);
    const circuit = await response.json();
    return circuit;
}
export async function getHostedPackagedCircuitByName(version, name) {
    const response = await fetch(`https://circuits.zkpassport.id/versions/${version}/${name}.json.gz`);
    const circuit = await response.json();
    return circuit;
}
/**
 * Get the number of public inputs for a circuit.
 * @param circuitName - The name of the circuit.
 * @returns The number of public inputs.
 */
export function getNumberOfPublicInputs(circuitName) {
    if (circuitName.startsWith("disclose_bytes")) {
        return getDiscloseBytesProofPublicInputCount();
    }
    else if (circuitName.startsWith("disclose_flags")) {
        return getDiscloseFlagsProofPublicInputCount();
    }
    else if (circuitName.startsWith("compare_age")) {
        return getAgeProofPublicInputCount();
    }
    else if (circuitName.startsWith("compare_birthdate") ||
        circuitName.startsWith("compare_expiry")) {
        return getDateProofPublicInputCount();
    }
    else if (circuitName.startsWith("exclusion_check")) {
        return getCountryExclusionProofPublicInputCount();
    }
    else if (circuitName.startsWith("inclusion_check")) {
        return getCountryInclusionProofPublicInputCount();
    }
    else if (circuitName.startsWith("data_check_integrity")) {
        return getIntegrityProofPublicInputCount();
    }
    else if (circuitName.startsWith("sig_check_id_data")) {
        return getIDDataProofPublicInputCount();
    }
    else if (circuitName.startsWith("sig_check_dsc")) {
        return getDSCProofPublicInputCount();
    }
    else if (circuitName.startsWith("outer")) {
        // Get the characters after the last underscore
        const disclosureProofCount = Number(circuitName.substring(circuitName.lastIndexOf("_") + 1)) - 3;
        return 12 + disclosureProofCount;
    }
    return 0;
}
export function getCommittedInputCount(circuitName) {
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
export function getFormattedDate(date) {
    return formatDate(date, "yyyyMMdd");
}
export function getDateBytes(date) {
    return Binary.from(new TextEncoder().encode(getFormattedDate(date)));
}
export function getCurrentDateFromCommittedInputs(committedInputs) {
    return convertDateBytesToDate(committedInputs.currentDate);
}
export const DEFAULT_DATE_VALUE = new Date(Date.UTC(1111, 10, 11));
export var ProofType;
(function (ProofType) {
    ProofType[ProofType["DISCLOSE"] = 0] = "DISCLOSE";
    ProofType[ProofType["AGE"] = 1] = "AGE";
    ProofType[ProofType["BIRTHDATE"] = 2] = "BIRTHDATE";
    ProofType[ProofType["EXPIRY_DATE"] = 3] = "EXPIRY_DATE";
    ProofType[ProofType["NATIONALITY_INCLUSION"] = 4] = "NATIONALITY_INCLUSION";
    ProofType[ProofType["NATIONALITY_EXCLUSION"] = 5] = "NATIONALITY_EXCLUSION";
    ProofType[ProofType["ISSUING_COUNTRY_INCLUSION"] = 6] = "ISSUING_COUNTRY_INCLUSION";
    ProofType[ProofType["ISSUING_COUNTRY_EXCLUSION"] = 7] = "ISSUING_COUNTRY_EXCLUSION";
})(ProofType || (ProofType = {}));
export { DisclosedData, createDisclosedDataRaw, formatName, parseDocumentType, getDisclosedBytesFromMrzAndMask, getDiscloseParameterCommitment, getDiscloseEVMParameterCommitment, } from "./disclose.js";
export * from "./country.js";
export * from "./age.js";
export * from "./date.js";
export * from "./integrity.js";
export * from "./id-data.js";
export * from "./dsc.js";
export * from "./vkey.js";
