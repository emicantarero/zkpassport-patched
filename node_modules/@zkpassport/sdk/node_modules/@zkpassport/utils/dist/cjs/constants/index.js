"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CERT_TYPE_DSC = exports.CERT_TYPE_CSC = exports.CERTIFICATE_REGISTRY_ID = exports.CERTIFICATE_REGISTRY_HEIGHT = exports.E_CONTENT_INPUT_SIZE = exports.DG1_INPUT_SIZE = exports.SIGNED_ATTR_INPUT_SIZE = exports.MERCOSUR_COUNTRIES = exports.ASEAN_COUNTRIES = exports.SCHENGEN_COUNTRIES = exports.EEA_COUNTRIES = exports.EU_COUNTRIES = exports.SANCTIONED_COUNTRIES = void 0;
/**
 * List of countries that are sanctioned by the US government.
 */
const SANCTIONED_COUNTRIES = [
    "North Korea",
    "Iran",
    "Iraq",
    "Libya",
    "Somalia",
    "Sudan",
    "Syrian Arab Republic",
    "Yemen",
];
exports.SANCTIONED_COUNTRIES = SANCTIONED_COUNTRIES;
/**
 * List of countries that are part of the European Union.
 */
const EU_COUNTRIES = [
    "Austria",
    "Belgium",
    "Bulgaria",
    "Croatia",
    "Cyprus",
    "Czech Republic",
    "Denmark",
    "Estonia",
    "Finland",
    "France",
    "Germany",
    "Greece",
    "Hungary",
    "Ireland",
    "Italy",
    "Latvia",
    "Lithuania",
    "Luxembourg",
    "Malta",
    "Netherlands",
    "Poland",
    "Portugal",
    "Romania",
    "Slovakia",
    "Slovenia",
    "Spain",
    "Sweden",
];
exports.EU_COUNTRIES = EU_COUNTRIES;
/**
 * List of countries that are part of the European Economic Area.
 */
const EEA_COUNTRIES = [...EU_COUNTRIES, "Iceland", "Liechtenstein", "Norway"];
exports.EEA_COUNTRIES = EEA_COUNTRIES;
/**
 * List of countries that are part of the Schengen Area.
 */
const SCHENGEN_COUNTRIES = [
    ...EU_COUNTRIES.filter((country) => country !== "Cyprus" && country !== "Ireland"),
    "Switzerland",
    "Iceland",
    "Liechtenstein",
    "Norway",
];
exports.SCHENGEN_COUNTRIES = SCHENGEN_COUNTRIES;
/**
 * List of countries that are part of the Association of Southeast Asian Nations.
 */
const ASEAN_COUNTRIES = [
    "Brunei Darussalam",
    "Cambodia",
    "Indonesia",
    "Lao People's Democratic Republic",
    "Malaysia",
    "Myanmar",
    "Philippines",
    "Singapore",
    "Thailand",
    "Vietnam",
];
exports.ASEAN_COUNTRIES = ASEAN_COUNTRIES;
/**
 * List of countries that are part of the Mercosur.
 */
const MERCOSUR_COUNTRIES = [
    "Argentina",
    "Brazil",
    "Chile",
    "Colombia",
    "Paraguay",
    "Uruguay",
];
exports.MERCOSUR_COUNTRIES = MERCOSUR_COUNTRIES;
const SIGNED_ATTR_INPUT_SIZE = 200;
exports.SIGNED_ATTR_INPUT_SIZE = SIGNED_ATTR_INPUT_SIZE;
const DG1_INPUT_SIZE = 95;
exports.DG1_INPUT_SIZE = DG1_INPUT_SIZE;
const E_CONTENT_INPUT_SIZE = 700;
exports.E_CONTENT_INPUT_SIZE = E_CONTENT_INPUT_SIZE;
const CERTIFICATE_REGISTRY_HEIGHT = 14;
exports.CERTIFICATE_REGISTRY_HEIGHT = CERTIFICATE_REGISTRY_HEIGHT;
const CERTIFICATE_REGISTRY_ID = 1;
exports.CERTIFICATE_REGISTRY_ID = CERTIFICATE_REGISTRY_ID;
const CERT_TYPE_CSC = 1;
exports.CERT_TYPE_CSC = CERT_TYPE_CSC;
const CERT_TYPE_DSC = 2;
exports.CERT_TYPE_DSC = CERT_TYPE_DSC;
