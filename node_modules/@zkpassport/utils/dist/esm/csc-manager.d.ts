import { Certificate } from "./types";
export declare function parseCertificate(content: Buffer | string): Certificate;
export declare function parseCertificates(pemContent: string): Certificate[];
