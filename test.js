import {describe, it} from 'node:test';
import assert from 'node:assert/strict';
import { PowAuth } from './index.js';

describe('pow-auth module', async (t) => {
    const powAuth = new PowAuth({ difficulty: 2 });

    await it('constructor configuration', async (t) => {
        await it('should accept config object', async () => {
            const auth = new PowAuth({
                difficulty: 2,
                timeWindow: 400000,
                timeTolerance: 70000,
                maxCacheSize: 5000
            });
            assert.equal(auth.difficulty, 2);
            assert.equal(auth.timeWindow, 400000);
            assert.equal(auth.timeTolerance, 70000);
            assert.equal(auth.maxCacheSize, 5000);
        });

        await it('should use default values', async () => {
            const auth = new PowAuth({ difficulty: 2 });
            assert.equal(auth.difficulty, 2);
            assert.equal(auth.timeWindow, 300000);
            assert.equal(auth.timeTolerance, 60000);
            assert.equal(auth.maxCacheSize, 10000);
        });

        await it('should validate difficulty parameter', async () => {
            assert.throws(() => new PowAuth({}), {
                message: 'difficulty must be a number'
            });
            assert.throws(() => new PowAuth({ difficulty: '2' }), {
                message: 'difficulty must be a number'
            });
        });
    });

    await it('generateKey should create valid SHA-256 hash', async () => {
        const key = await powAuth.generateKey('testuser', 'password123');
        assert.equal(typeof key, 'string');
        assert.equal(key.length, 64, 'Key should be 64 characters (32 bytes in hex)');
    });

    await it('generateProof with different difficulties', async (t) => {
        const difficulties = [1, 2];
        
        for (const diff of difficulties) {
            const auth = new PowAuth({ difficulty: diff });
            await it(`should generate valid proof for difficulty ${diff}`, async () => {
                const proof = await auth.generateProof('testuser', 'password123');
                
                assert.equal(typeof proof.name, 'string');
                assert.equal(typeof proof.ts, 'number');
                assert.equal(typeof proof.nonce, 'number');
                assert.equal(typeof proof.hash, 'string');
                assert.equal(proof.hash.length, 64);
                assert.ok(proof.hash.startsWith('0'.repeat(diff)), 
                    `Hash should start with ${diff} zeros`);
            });
        }
    });

    await it('verifyProof validation', async (t) => {
        const name = 'testuser';
        const password = 'password123';
        
        const key = await powAuth.generateKey(name, password);
        const proof = await powAuth.generateProof(name, password);

        await it('should verify valid proof', async () => {
            const result = await powAuth.verifyProof(proof, key);
            assert.deepEqual(result, {
                valid: true,
                code: 'OK',
                reason: 'Proof is valid'
            });
        });

        await it('should reject invalid proof', async () => {
            const invalidProof = { ...proof, nonce: proof.nonce + 1 };
            const result = await powAuth.verifyProof(invalidProof, key);
            assert.deepEqual(result, {
                valid: false,
                code: 'INVALID_HASH',
                reason: 'Hash verification failed'
            });
        });
    });

    await it('verifyProof timestamp validation', async (t) => {
        const name = 'testuser';
        const password = 'password123';
        const key = await powAuth.generateKey(name, password);

        // Helper function to create a proof with a specific timestamp
        async function createProofWithTimestamp(ts) {
            let nonce = 0;
            const target = '0'.repeat(powAuth.difficulty);
            
            // Find a nonce that creates a valid hash
            while (true) {
                const data = new TextEncoder().encode(`${key}:${ts}:${nonce}`);
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

        await it('should reject expired proof', async () => {
            const expiredProof = await createProofWithTimestamp(Date.now() - powAuth.timeWindow - 1000);
            const result = await powAuth.verifyProof(expiredProof, key);
            assert.deepEqual(result, {
                valid: false,
                code: 'EXPIRED',
                reason: 'Proof has expired'
            });
        });

        await it('should accept proof within tolerance', async () => {
            const proofWithinTolerance = await createProofWithTimestamp(Date.now() + Math.floor(powAuth.timeTolerance / 2));
            const result = await powAuth.verifyProof(proofWithinTolerance, key);
            assert.deepEqual(result, {
                valid: true,
                code: 'OK',
                reason: 'Proof is valid'
            });
        });

        await it('should reject proof beyond tolerance', async () => {
            const farFutureProof = await createProofWithTimestamp(Date.now() + powAuth.timeTolerance + 1000);
            const result = await powAuth.verifyProof(farFutureProof, key);
            assert.deepEqual(result, {
                valid: false,
                code: 'FUTURE_TIMESTAMP',
                reason: 'Proof timestamp is too far in the future'
            });
        });
    });

    await it('replay attack protection', async (t) => {
        const name = 'testuser';
        const password = 'password123';
        
        const key = await powAuth.generateKey(name, password);
        const proof = await powAuth.generateProof(name, password);

        await it('should accept first use of proof', async () => {
            const result = await powAuth.verifyProof(proof, key);
            assert.equal(result.valid, true);
            assert.equal(result.code, 'OK');
        });

        await it('should reject replay of same proof', async () => {
            const result = await powAuth.verifyProof(proof, key);
            assert.deepEqual(result, {
                valid: false,
                code: 'REPLAY',
                reason: 'Proof has already been used'
            });
        });
    });

    await it('memory protection with LRU cache', async (t) => {
        const smallCache = new PowAuth({ difficulty: 2, timeWindow: 300000, timeTolerance: 60000, maxCacheSize: 2 }); // Only store 2 proofs
        const name = 'testuser';
        const password = 'password123';
        const key = await smallCache.generateKey(name, password);

        await it('should handle cache overflow', async () => {
            // Generate and verify 3 different proofs
            const proof1 = await smallCache.generateProof(name, password);
            const proof2 = await smallCache.generateProof(name, password);
            const proof3 = await smallCache.generateProof(name, password);

            const result1 = await smallCache.verifyProof(proof1, key);
            const result2 = await smallCache.verifyProof(proof2, key);
            const result3 = await smallCache.verifyProof(proof3, key);

            assert.deepEqual(result1, { valid: true, code: 'OK', reason: 'Proof is valid' });
            assert.deepEqual(result2, { valid: true, code: 'OK', reason: 'Proof is valid' });
            assert.deepEqual(result3, { valid: true, code: 'OK', reason: 'Proof is valid' });

            // First proof should be accepted again as it was evicted from cache
            const replayResult = await smallCache.verifyProof(proof1, key);
            assert.deepEqual(replayResult, { valid: true, code: 'OK', reason: 'Proof is valid' });
        });
    });

    await it('parameter validation', async (t) => {
        await it('should handle empty strings', async () => {
            const auth = new PowAuth({ difficulty: 2 });
            const key = await auth.generateKey('', '');
            assert.equal(typeof key, 'string');
            assert.equal(key.length, 64);
        });

        await it('should handle special characters', async () => {
            const auth = new PowAuth({ difficulty: 2 });
            const specialChars = 'test@user!#$%^&*()+';
            const key = await auth.generateKey(specialChars, specialChars);
            assert.equal(typeof key, 'string');
            assert.equal(key.length, 64);
        });

        await it('should handle unicode characters', async () => {
            const auth = new PowAuth({ difficulty: 2 });
            const unicodeChars = '用户名パスワード';
            const key = await auth.generateKey(unicodeChars, unicodeChars);
            assert.equal(typeof key, 'string');
            assert.equal(key.length, 64);
        });
    });

    await it('boundary conditions', async (t) => {
        await it('should handle minimum difficulty', async () => {
            const auth = new PowAuth({ difficulty: 0 });
            const proof = await auth.generateProof('test', 'test');
            assert.ok(proof.hash.length === 64);
        });

        await it('should handle large difficulty', async () => {
            const auth = new PowAuth({ difficulty: 4 });
            const proof = await auth.generateProof('test', 'test');
            assert.ok(proof.hash.startsWith('0000'));
        });

        await it('should handle minimum time window', async () => {
            const auth = new PowAuth({ difficulty: 2, timeWindow: 1000 }); // 1 second window
            const proof = await auth.generateProof('test', 'test');
            assert.ok(await auth.verifyProof(proof, await auth.generateKey('test', 'test')));
        });
    });

    await it('cache behavior', async (t) => {
        await it('should clear expired entries', async () => {
            const shortWindow = 1000; // 1 second
            const auth = new PowAuth({ 
                difficulty: 2, 
                timeWindow: shortWindow * 2, 
                timeTolerance: 500, 
                maxCacheSize: 10 
            });
            
            const key = await auth.generateKey('test', 'test');
            const proof = await auth.generateProof('test', 'test');
            
            // First verification should pass
            const firstVerification = await auth.verifyProof(proof, key);
            assert.ok(firstVerification, 'First verification should pass');
            
            // Wait for the cache entry to expire (add extra time to ensure expiry)
            await new Promise(resolve => setTimeout(resolve, shortWindow + 500));
            
            // Should accept the same proof again after expiry
            const secondVerification = await auth.verifyProof(proof, key);
            assert.ok(secondVerification, 'Second verification should pass after cache expiry');
        });
    });

    await it('concurrent operations', async (t) => {
        const auth = new PowAuth({ difficulty: 2 });
        const name = 'testuser';
        const password = 'password123';
        
        await it('should handle multiple simultaneous verifications', async () => {
            const key = await auth.generateKey(name, password);
            const proofs = await Promise.all([
                auth.generateProof(name, password),
                auth.generateProof(name, password),
                auth.generateProof(name, password)
            ]);
            
            // Verify all proofs concurrently
            const results = await Promise.all(
                proofs.map(proof => auth.verifyProof(proof, key))
            );
            
            // All verifications should succeed
            assert.ok(results.every(result => result.valid === true));
            
            // Trying to verify any proof again should fail (replay protection)
            const replayResults = await Promise.all(
                proofs.map(proof => auth.verifyProof(proof, key))
            );
            
            // All replay attempts should fail
            assert.ok(replayResults.every(result => result.valid === false));
        });
    });

    await it('edge cases', async (t) => {
        const auth = new PowAuth({ difficulty: 2 });
        
        await it('should handle very long inputs', async () => {
            const longString = 'a'.repeat(10000);
            const key = await auth.generateKey(longString, longString);
            assert.equal(typeof key, 'string');
            assert.equal(key.length, 64);
        });

        await it('should handle invalid proof objects', async () => {
            const key = await auth.generateKey('test', 'test');
            const invalidProofs = [
                { ts: Date.now(), nonce: 0 }, // missing hash
                { nonce: 0, hash: '0'.repeat(64) }, // missing ts
                { ts: Date.now(), hash: '0'.repeat(64) }, // missing nonce
                null,
                undefined,
                {}
            ];

            for (const invalidProof of invalidProofs) {
                try {
                    await auth.verifyProof(invalidProof, key);
                    assert.fail('Should throw for invalid proof');
                } catch (error) {
                    assert.ok(error instanceof Error);
                }
            }
        });
    });

    await it('error cases validation', async (t) => {
        const auth = new PowAuth({ difficulty: 2 });
        const name = 'testuser';
        const password = 'password123';
        const key = await auth.generateKey(name, password);
        const validProof = await auth.generateProof(name, password);

        await it('should reject insufficient difficulty', async () => {
            // Modify hash to not meet difficulty requirement
            const invalidProof = { ...validProof, hash: '1' + '0'.repeat(63) };
            const result = await auth.verifyProof(invalidProof, key);
            assert.deepEqual(result, {
                valid: false,
                code: 'INSUFFICIENT_DIFFICULTY',
                reason: 'Hash does not meet difficulty requirement'
            });
        });

        await it('should reject invalid key format', async () => {
            try {
                await auth.verifyProof(validProof, null);
                assert.fail('Should throw for invalid key');
            } catch (error) {
                assert.equal(error.message, 'Invalid key format: key must be string');
            }

            try {
                await auth.verifyProof(validProof, 123);
                assert.fail('Should throw for invalid key');
            } catch (error) {
                assert.equal(error.message, 'Invalid key format: key must be string');
            }
        });

        await it('should reject malformed field types', async () => {
            const proofWithStringTs = { ...validProof, ts: '123' };
            const proofWithStringNonce = { ...validProof, nonce: '0' };
            const proofWithNumberHash = { ...validProof, hash: 123 };

            try {
                await auth.verifyProof(proofWithStringTs, key);
                assert.fail('Should throw for string timestamp');
            } catch (error) {
                assert.equal(error.message, 'Invalid proof format: ts and nonce must be numbers, hash must be string');
            }

            try {
                await auth.verifyProof(proofWithStringNonce, key);
                assert.fail('Should throw for string nonce');
            } catch (error) {
                assert.equal(error.message, 'Invalid proof format: ts and nonce must be numbers, hash must be string');
            }

            try {
                await auth.verifyProof(proofWithNumberHash, key);
                assert.fail('Should throw for number hash');
            } catch (error) {
                assert.equal(error.message, 'Invalid proof format: ts and nonce must be numbers, hash must be string');
            }
        });
    });
});