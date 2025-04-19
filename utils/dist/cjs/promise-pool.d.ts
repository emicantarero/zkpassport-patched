export declare class PromisePool {
    private concurrency;
    private queue;
    private activePromises;
    private onCompletionCallbacks;
    private _errors;
    private isClosed;
    constructor(concurrency: number);
    add(fn: () => Promise<void>): Promise<void>;
    private notifyCompletion;
    await(): Promise<void>;
    drain(): Promise<void>;
    get active(): number;
    get queued(): number;
    get size(): number;
    get hasErrors(): boolean;
    get errors(): Error[];
}
declare const AggregateError: any;
export { AggregateError };
