interface HashAuthConfig {
    difficulty: number;
    timeWindow?: number;
    timeTolerance?: number;
    maxCacheSize?: number;
}

interface VerifyResult {
    valid: boolean;
    reason: string;
    code?: string;
}

interface Proof {
    name: string;
    ts: number;
    nonce: number;
    hash: string;
}

export class PowAuth {
    constructor(config: HashAuthConfig);
    generateKey(name: string, password: string): Promise<string>;
    generateProof(name: string, password: string): Promise<Proof>;
    verifyProof(proof: Proof, key: string): Promise<VerifyResult>;
}