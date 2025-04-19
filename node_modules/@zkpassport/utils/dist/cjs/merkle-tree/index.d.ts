import { Binary } from "../binary";
import { AsyncIMT } from "./async-imt";
export declare function computeMerkleProof(leaves: Binary[], index: number, height: number): Promise<{
    root: string | import("../binary").HexString;
    index: number;
    path: (string | import("../binary").HexString)[];
}>;
export { AsyncIMT };
