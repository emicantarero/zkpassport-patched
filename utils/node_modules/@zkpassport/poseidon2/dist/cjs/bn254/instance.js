"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPoseidon2BN254 = getPoseidon2BN254;
const field_js_1 = require("../core/field.js");
const poseidon2_js_1 = require("../core/poseidon2.js");
const poseidon2params_js_1 = require("../core/poseidon2params.js");
const constants_js_1 = require("./constants.js");
const bn254Field = new field_js_1.F1Field(BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617"));
let instance = null;
function getPoseidon2BN254() {
    if (!instance) {
        instance = new poseidon2_js_1.Poseidon2((0, poseidon2params_js_1.getPoseidon2Params)(4, 5, 8, 56, constants_js_1.MAT_DIAG4_M_1, constants_js_1.MAT_INTERNAL4, constants_js_1.RC4), bn254Field);
    }
    return instance;
}
