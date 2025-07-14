# zkLogin Proving Service

A zero-knowledge proving service for the MySocial blockchain that generates zkLogin proofs using Circom, snarkjs, and rapidsnark.

## Overview

This service implements a simplified zkLogin-like scheme that proves JWT ownership without revealing sensitive data. It uses:
- **Circom** for circuit definition
- **snarkjs** for witness generation and trusted setup
- **rapidsnark** for fast proof generation
- **Express.js** for the HTTP API

## Circuit Design

The circuit (`circuits/zklogin_mys.circom`) implements a simple proof scheme:
- **Inputs**: `jwtHash`, `nonce`, `pubKeyHash`
- **Output**: `isValid` (1 if jwtHash == Poseidon(nonce, pubKeyHash), 0 otherwise)

This is a simplified version for demonstration. A production zkLogin would include RSA signature verification.

## API Endpoints

### POST /prove
Generate a zero-knowledge proof for JWT ownership.

**Request Body:**
```json
{
  "jwtHash": "123456789",
  "nonce": "987654321",
  "pubKeyHash": "555555555"
}
```

**Response:**
```json
{
  "proof": {
    "pi_a": [...],
    "pi_b": [[...], [...]],
    "pi_c": [...],
    "protocol": "groth16",
    "curve": "bn128"
  },
  "public": ["1"]
}
```

## Local Development

### Prerequisites
- Node.js 18+
- Yarn
- Rust (for circom)
- Build tools (gcc, make, cmake)

### Setup

1. Install dependencies:
```bash
yarn install
```

2. Compile circuit (if needed):
```bash
yarn compile-circuit
```

3. Generate proving keys (if needed):
```bash
yarn setup-zkey
```

4. Build rapidsnark for your platform:
```bash
cd rapidsnark
git submodule init && git submodule update
./build_gmp.sh macos_arm64  # or linux_amd64
make macos_arm64  # or linux_amd64
cp build_prover_*/prover ../rapidsnark/rapidsnark
```

5. Run the server:
```bash
yarn start
```

## Docker Deployment

Build and run with Docker:
```bash
docker build -t zklogin-prover .
docker run -p 4000:4000 zklogin-prover
```

## Railway Deployment

1. Push to GitHub
2. Connect repository to Railway
3. Railway will automatically build and deploy using the Dockerfile

## Project Structure

```
zklogin-prover/
├── circuits/          # Circom circuit files
├── keys/             # Proving and verification keys
├── inputs/           # Temporary input files
├── outputs/          # Temporary output files
├── rapidsnark/       # Rapidsnark binary
├── server.js         # Express API server
├── Dockerfile        # Container configuration
└── package.json      # Node dependencies
```

## Security Notes

- This is a demonstration implementation
- Do not use in production without proper security review
- The simplified circuit does not verify actual JWT signatures
- Trusted setup ceremony should be done properly for production use