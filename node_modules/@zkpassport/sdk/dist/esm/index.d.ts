import { type DisclosableIDCredential, type IDCredential, type IDCredentialValue, type NumericalIDCredential, type ProofResult, type QueryResult, ProofMode } from "@zkpassport/utils";
export type QueryResultError<T> = {
    expected?: T;
    received?: T;
    message: string;
};
export type QueryResultErrors = {
    [key in IDCredential | "sig_check_dsc" | "sig_check_id_data" | "data_check_integrity" | "outer" | "disclose"]: {
        disclose?: QueryResultError<string | number | Date>;
        gte?: QueryResultError<number | Date>;
        lte?: QueryResultError<number | Date>;
        lt?: QueryResultError<number | Date>;
        range?: QueryResultError<[number | Date, number | Date]>;
        in?: QueryResultError<string[]>;
        out?: QueryResultError<string[]>;
        eq?: QueryResultError<string | number | Date>;
        commitment?: QueryResultError<string>;
        date?: QueryResultError<string>;
        certificate?: QueryResultError<string>;
    };
};
export type SolidityVerifierParameters = {
    vkeyHash: string;
    proof: string;
    publicInputs: string[];
    committedInputs: string;
    committedInputCounts: number[];
    validityPeriodInDays: number;
};
export type EVMChain = "ethereum_sepolia" | "local_anvil";
export type * from "@zkpassport/utils";
export { SANCTIONED_COUNTRIES, EU_COUNTRIES, EEA_COUNTRIES, SCHENGEN_COUNTRIES, ASEAN_COUNTRIES, MERCOSUR_COUNTRIES, } from "@zkpassport/utils";
export type QueryBuilderResult = {
    /**
     * The URL of the request.
     *
     * You can either encode the URL in a QR code or let the user click the link
     * to this URL on your website if they're visiting your website on their phone.
     */
    url: string;
    /**
     * The id of the request.
     */
    requestId: string;
    /**
     * Called when the user has scanned the QR code or clicked the link to the request.
     *
     * This means the user is currently viewing the request popup with your website information
     * and the information requested from them.
     */
    onRequestReceived: (callback: () => void) => void;
    /**
     * Called when the user has accepted the request and
     * started to generate the proof on their phone.
     */
    onGeneratingProof: (callback: () => void) => void;
    /**
     * Called when the SDK successfully connects to the bridge with the mobile app.
     */
    onBridgeConnect: (callback: () => void) => void;
    /**
     * Called when the user has generated a proof.
     *
     * There is a minimum of 4 proofs, but there can be more depending
     * on the type of information requested from the user.
     */
    onProofGenerated: (callback: (proof: ProofResult) => void) => void;
    /**
     * Called when the user has sent the query result.
     *
     * The response contains the unique identifier associated to the user,
     * your domain name and chosen scope, along with the query result and whether
     * the proofs were successfully verified.
     */
    onResult: (callback: (response: {
        uniqueIdentifier: string | undefined;
        verified: boolean;
        result: QueryResult;
        queryResultErrors?: QueryResultErrors;
    }) => void) => void;
    /**
     * Called when the user has rejected the request.
     */
    onReject: (callback: () => void) => void;
    /**
     * Called when an error occurs, such as one of the requirements not being met
     * or a proof failing to be generated.
     */
    onError: (callback: (error: string) => void) => void;
    /**
     * @returns true if the bridge with the mobile app is connected
     */
    isBridgeConnected: () => boolean;
    /**
     * Get if the user has scanned the QR code or the link to this request
     * @returns true if the request has been received by the user on their phone
     */
    requestReceived: () => boolean;
};
export type QueryBuilder = {
    /**
     * Requires this attribute to be equal to the provided value.
     * @param key The attribute to compare.
     * @param value The value of the attribute you require.
     */
    eq: <T extends IDCredential>(key: T, value: IDCredentialValue<T>) => QueryBuilder;
    /**
     * Requires this attribute to be greater than or equal to the provided value.
     * @param key The attribute to compare.
     * @param value The value of the attribute you require.
     */
    gte: <T extends NumericalIDCredential>(key: T, value: IDCredentialValue<T>) => QueryBuilder;
    /**
     * Requires this attribute to be less than or equal to the provided value.
     * @param key The attribute to compare.
     * @param value The value of the attribute you require.
     */
    lte: <T extends "birthdate" | "expiry_date">(key: T, value: IDCredentialValue<T>) => QueryBuilder;
    /**
     * Requires this attribute to be less than the provided value.
     * @param key The attribute to compare.
     * @param value The value of the attribute you require.
     */
    lt: <T extends "age">(key: T, value: IDCredentialValue<T>) => QueryBuilder;
    /**
     * Requires this attribute to be included in the provided range.
     * @param key The attribute to compare.
     * @param start The start of the range.
     * @param end The end of the range.
     */
    range: <T extends NumericalIDCredential>(key: T, start: IDCredentialValue<T>, end: IDCredentialValue<T>) => QueryBuilder;
    /**
     * Requires this attribute to be included in the provided list.
     * @param key The attribute to compare.
     * @param value The list of values to check inclusion against.
     */
    in: <T extends "nationality" | "issuing_country">(key: T, value: IDCredentialValue<T>[]) => QueryBuilder;
    /**
     * Requires this attribute to be excluded from the provided list.
     * @param key The attribute to compare.
     * @param value The list of values to check exclusion against.
     */
    out: <T extends "nationality" | "issuing_country">(key: T, value: IDCredentialValue<T>[]) => QueryBuilder;
    /**
     * Requires this attribute to be disclosed.
     * @param key The attribute to disclose.
     */
    disclose: (key: DisclosableIDCredential) => QueryBuilder;
    /**
     * Builds the request.
     *
     * This will return the URL of the request, which you can either encode in a QR code
     * or provide as a link to the user if they're visiting your website on their phone.
     * It also returns all the callbacks you can use to handle the user's response.
     */
    done: () => QueryBuilderResult;
};
export declare class ZKPassport {
    private domain;
    private topicToConfig;
    private topicToLocalConfig;
    private topicToKeyPair;
    private topicToWebSocketClient;
    private topicToSharedSecret;
    private topicToRequestReceived;
    private topicToService;
    private topicToProofs;
    private topicToExpectedProofCount;
    private topicToFailedProofCount;
    private topicToResults;
    private onRequestReceivedCallbacks;
    private onGeneratingProofCallbacks;
    private onBridgeConnectCallbacks;
    private onProofGeneratedCallbacks;
    private onResultCallbacks;
    private onRejectCallbacks;
    private onErrorCallbacks;
    constructor(_domain?: string);
    private handleResult;
    private setExpectedProofCount;
    /**
     * @notice Handle an encrypted message.
     * @param request The request.
     * @param outerRequest The outer request.
     */
    private handleEncryptedMessage;
    private getZkPassportRequest;
    /**
     * @notice Create a new request
     * @param name Your service name
     * @param logo The logo of your service
     * @param purpose To explain what you want to do with the user's data
     * @param scope Scope this request to a specific use case
     * @param validity How many days ago should have the ID been last scanned by the user?
     * @returns The query builder object.
     */
    request({ name, logo, purpose, scope, mode, validity, topicOverride, keyPairOverride, }: {
        name: string;
        logo: string;
        purpose: string;
        scope?: string;
        mode?: ProofMode;
        validity?: number;
        topicOverride?: string;
        keyPairOverride?: {
            privateKey: Uint8Array;
            publicKey: Uint8Array;
        };
    }): Promise<QueryBuilder>;
    private checkDiscloseBytesPublicInputs;
    private checkAgePublicInputs;
    private checkBirthdatePublicInputs;
    private checkExpiryDatePublicInputs;
    private checkNationalityExclusionPublicInputs;
    private checkIssuingCountryExclusionPublicInputs;
    private checkNationalityInclusionPublicInputs;
    private checkIssuingCountryInclusionPublicInputs;
    private checkPublicInputs;
    /**
     * @notice Verify the proofs received from the mobile app.
     * @param proofs The proofs to verify.
     * @param queryResult The query result to verify against
     * @param validity How many days ago should have the ID been last scanned by the user?
     * @returns An object containing the unique identifier associated to the user
     * and a boolean indicating whether the proofs were successfully verified.
     */
    verify({ proofs, queryResult, validity, }: {
        proofs: Array<ProofResult>;
        queryResult: QueryResult;
        validity?: number;
    }): Promise<{
        uniqueIdentifier: string | undefined;
        verified: boolean;
        queryResultErrors?: QueryResultErrors;
    }>;
    getSolidityVerifierDetails(network: EVMChain): {
        address: string;
        abi: {
            type: "function" | "event" | "constructor";
            name: string;
            inputs: {
                name: string;
                type: string;
                internalType: string;
            }[];
            outputs: {
                name: string;
                type: string;
                internalType: string;
            }[];
        }[];
    };
    getSolidityVerifierParameters(proof: ProofResult, validityPeriodInDays?: number): SolidityVerifierParameters;
    /**
     * @notice Returns the URL of the request.
     * @param requestId The request ID.
     * @returns The URL of the request.
     */
    getUrl(requestId: string): string;
    /**
     * @notice Cancels a request by closing the WebSocket connection and deleting the associated data.
     * @param requestId The request ID.
     */
    cancelRequest(requestId: string): void;
    /**
     * @notice Clears all requests.
     */
    clearAllRequests(): void;
}
