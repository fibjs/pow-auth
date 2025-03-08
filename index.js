// Hash-based authentication module using Web Crypto API
import { LRUCache } from 'lru-cache';
const encoder = new TextEncoder();

/**
 * @typedef {Object} HashAuthConfig
 * @property {number} difficulty - number of leading zeros required for proof of work
 * @property {number} [timeWindow=300000] - Time window in milliseconds (default 5 minutes)
 * @property {number} [timeTolerance=60000] - Time tolerance in milliseconds (default 1 minute)
 * @property {number} [maxCacheSize=10000] - Maximum number of used proofs to store
 */

/**
 * @typedef {Object} VerifyResult
 * @property {boolean} valid - Whether the proof is valid
 * @property {string} reason - Reason for failure if invalid
 * @property {string} [code] - Error code if invalid
 */

export class PowAuth {
    /**
     * Create a new PowAuth instance
     * @param {HashAuthConfig} config - Configuration object
     */
    constructor(config) {
        const {
            difficulty,
            timeWindow = 300000,
            timeTolerance = 60000,
            maxCacheSize = 10000
        } = config || {};

        if (typeof difficulty !== 'number') {
            throw new Error('difficulty must be a number');
        }

        this.difficulty = Math.max(0, Math.floor(difficulty));
        this.timeWindow = Math.max(1000, timeWindow);
        this.timeTolerance = Math.max(0, timeTolerance);
        this.maxCacheSize = maxCacheSize;
        
        // Configure LRU cache with TTL and automatic purge
        this.usedProofs = new LRUCache({
            max: this.maxCacheSize,
            ttl: this.timeWindow,
            updateAgeOnGet: false
        });
    }

    /**
     * Generate SHA-256 key from name and password
     * @throws {Error} If name or password is invalid
     */
    async generateKey(name, password) {
        if (typeof name !== 'string' || typeof password !== 'string') {
            throw new Error('Name and password must be strings');
        }

        const data = encoder.encode(`${name}:${password}`);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Generate proof of work based on hashcash principle
     * @throws {Error} If name or password is invalid
     */
    async generateProof(name, password) {
        if (typeof name !== 'string' || typeof password !== 'string') {
            throw new Error('Name and password must be strings');
        }

        const key = await this.generateKey(name, password);
        const ts = Date.now();
        let nonce = 0;
        const target = '0'.repeat(this.difficulty);
        
        while (true) {
            const data = encoder.encode(`${key}:${ts}:${nonce}`);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hash = Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            
            if (hash.startsWith(target)) {
                return {
                    name,
                    ts,
                    nonce,
                    hash
                };
            }
            nonce++;
        }
    }

    /**
     * Verify proof of work and key
     * @throws {Error} If proof object is invalid
     * @returns {Promise<VerifyResult>} Verification result
     */
    async verifyProof(proof, key) {
        if (!proof || typeof proof !== 'object') {
            throw new Error('Invalid proof object');
        }

        const { ts, nonce, hash } = proof;
        
        if (typeof ts !== 'number' || typeof nonce !== 'number' || typeof hash !== 'string') {
            throw new Error('Invalid proof format: ts and nonce must be numbers, hash must be string');
        }

        if (typeof key !== 'string') {
            throw new Error('Invalid key format: key must be string');
        }
        
        const now = Date.now();
        
        // Verify timestamp is within allowed window with tolerance
        if (ts < now - this.timeWindow) {
            return { valid: false, code: 'EXPIRED', reason: 'Proof has expired' };
        }
        
        if (ts > now + this.timeTolerance) {
            return { valid: false, code: 'FUTURE_TIMESTAMP', reason: 'Proof timestamp is too far in the future' };
        }

        // Check for replay attack using TTL cache
        const proofKey = `${key}:${ts}:${nonce}`;
        if (this.usedProofs.has(proofKey)) {
            return { valid: false, code: 'REPLAY', reason: 'Proof has already been used' };
        }

        // First verify the difficulty requirement
        const target = '0'.repeat(this.difficulty);
        if (!hash.startsWith(target)) {
            return { valid: false, code: 'INSUFFICIENT_DIFFICULTY', reason: 'Hash does not meet difficulty requirement' };
        }

        // Then verify the proof hash
        const data = encoder.encode(proofKey);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const calculatedHash = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        
        if (calculatedHash !== hash) {
            return { valid: false, code: 'INVALID_HASH', reason: 'Hash verification failed' };
        }
        
        // Store the proof in cache if valid
        this.usedProofs.set(proofKey, true);
        
        return { valid: true, code: 'OK', reason: 'Proof is valid' };
    }
}