/**
 * Compute an array of 120-bit limbs that represents a Barrett reduction parameter
 */
export declare function redcLimbs(bn: bigint, numBits: number): number[];
export declare function redcLimbsFromBytes(bytes: number[] | Buffer): number[];
