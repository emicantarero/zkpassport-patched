"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AggregateError = exports.PromisePool = void 0;
// Promise pool for controlled concurrency
class PromisePool {
    constructor(concurrency) {
        this.concurrency = concurrency;
        this.queue = [];
        this.activePromises = 0;
        this.onCompletionCallbacks = [];
        this._errors = [];
        this.isClosed = false;
    }
    async add(fn) {
        if (this.isClosed) {
            throw new Error("Cannot add to closed PromisePool");
        }
        if (this.activePromises >= this.concurrency) {
            // Queue the task if we're at max concurrency
            return new Promise((resolve, reject) => {
                this.queue.push(async () => {
                    try {
                        await fn();
                        resolve();
                    }
                    catch (error) {
                        this._errors.push(error instanceof Error ? error : new Error(String(error)));
                        reject(error);
                    }
                });
            });
        }
        else {
            // Execute immediately if under the concurrency limit
            this.activePromises++;
            try {
                await fn();
            }
            catch (error) {
                this._errors.push(error instanceof Error ? error : new Error(String(error)));
                throw error;
            }
            finally {
                this.activePromises--;
                // Process next queued task if any
                if (this.queue.length > 0) {
                    const next = this.queue.shift();
                    this.add(() => next());
                }
                else if (this.activePromises === 0) {
                    // If no active promises and queue is empty, notify all completion callbacks
                    this.notifyCompletion();
                }
            }
        }
    }
    notifyCompletion() {
        // Call all completion callbacks
        for (const callback of this.onCompletionCallbacks) {
            callback();
        }
        this.onCompletionCallbacks = [];
    }
    async await() {
        // If there are no active promises and no queued tasks, return immediately
        if (this.activePromises === 0 && this.queue.length === 0) {
            return;
        }
        // Otherwise, wait for all queued and active promises to complete
        return new Promise((resolve) => {
            this.onCompletionCallbacks.push(resolve);
        });
    }
    async drain() {
        this.isClosed = true;
        await this.await();
        if (this._errors.length > 0) {
            throw new AggregateError(this._errors, "Errors occurred during execution");
        }
    }
    get active() {
        return this.activePromises;
    }
    get queued() {
        return this.queue.length;
    }
    get size() {
        return this.activePromises + this.queue.length;
    }
    get hasErrors() {
        return this._errors.length > 0;
    }
    get errors() {
        return [...this._errors];
    }
}
exports.PromisePool = PromisePool;
// AggregateError polyfill for environments that don't support it natively
class CustomAggregateError extends Error {
    constructor(errors, message) {
        super(message);
        this.name = "AggregateError";
        this.errors = errors;
    }
}
// Use native AggregateError if available, otherwise use our polyfill
const AggregateError = typeof globalThis !== "undefined" && "AggregateError" in globalThis
    ? globalThis.AggregateError
    : CustomAggregateError;
exports.AggregateError = AggregateError;
