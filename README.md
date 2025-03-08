# Pow Auth

A proof-of-work based authentication module using Web Crypto API.

## Features

- Hashcash-style proof of work authentication
- Configurable difficulty level
- Replay attack protection using LRU cache
- Time-based validation with configurable windows
- Built on Web Crypto API for secure cryptographic operations

## Installation

```bash
npm install pow-auth
```

## Usage

```javascript
import { PowAuth } from 'pow-auth';

// Create a new instance with difficulty level 2 (requiring 2 leading zeros)
const auth = new PowAuth({ 
  difficulty: 2,
  timeWindow: 300000,    // 5 minutes
  timeTolerance: 60000,  // 1 minute
  maxCacheSize: 10000    // Maximum number of proofs to cache
});

// Generate a key from username and password
const key = await auth.generateKey('username', 'password');

// Generate a proof of work
const proof = await auth.generateProof('username', 'password');

// Verify the proof
const result = await auth.verifyProof(proof, key);
if (result.valid) {
  console.log('Authentication successful');
} else {
  console.log(`Authentication failed: ${result.reason}`);
}
```

## API

### `new PowAuth(config)`

Creates a new PowAuth instance.

#### Config Options

- `difficulty`: Number of leading zeros required for proof of work
- `timeWindow`: Time window in milliseconds (default: 300000, 5 minutes)
- `timeTolerance`: Time tolerance in milliseconds (default: 60000, 1 minute)
- `maxCacheSize`: Maximum number of used proofs to store (default: 10000)

### `generateKey(name: string, password: string): Promise<string>`

Generates a SHA-256 hash key from name and password.

### `generateProof(name: string, password: string): Promise<Proof>`

Generates a proof of work based on the hashcash principle.

Returns a proof object containing:
- `name`: Username
- `ts`: Timestamp
- `nonce`: Nonce value
- `hash`: Generated hash

### `verifyProof(proof: Proof, key: string): Promise<VerifyResult>`

Verifies a proof against a key.

Returns a result object containing:
- `valid`: Boolean indicating if proof is valid
- `code`: Status code ('OK' or error code)
- `reason`: Description of the result

#### Error Codes

- `EXPIRED`: Proof has expired
- `FUTURE_TIMESTAMP`: Proof timestamp is too far in the future
- `REPLAY`: Proof has already been used
- `INSUFFICIENT_DIFFICULTY`: Hash does not meet difficulty requirement
- `INVALID_HASH`: Hash verification failed

## Security Considerations

1. The difficulty level should be set based on your security requirements
2. Time windows should be adjusted based on your network latency expectations
3. Cache size should be set based on your expected traffic volume

## License

MIT
