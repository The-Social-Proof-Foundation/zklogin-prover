# zkLogin Proving Service

A zero-knowledge proving service for the MySocial blockchain that generates zkLogin proofs using Circom, snarkjs, and rapidsnark.

## Overview

This service implements a production-ready zkLogin scheme that proves JWT ownership without revealing sensitive data. It uses:
- **Circom** for circuit definition
- **snarkjs** for witness generation and proof generation
- **rapidsnark** for optimized proof generation (optional)
- **Express.js** for the HTTP API

## Key Features

- OAuth JWT validation and parsing
- RSA signature verification in zero-knowledge
- Ed25519 key handling for ephemeral and deterministic keys
- Precise proof formatting
- Robust error handling and timeout management
- Automatic file path detection for deployment flexibility

## API Endpoints

### POST /prove
Generate a zero-knowledge proof for JWT authentication.

**Request Body:**
```json
{
  "jwt": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJkN2VkMzM4...",
  "extendedEphemeralPublicKey": "AMVEkksXfBMRe5lXUR9DgafDcqGeVg7HBSfFsZ6Fts2H",
  "maxEpoch": 198,
  "jwtRandomness": "213253234141032554525221902411422537422595",
  "salt": "36076524674750310186155015208229402348",
  "keyClaimName": "sub"
}
```

**Response:**
```json
{
  "proofPoints": {
    "a": [
      "12234123715652362199371541931151339029163252329389588935135212270789401977116",
      "18065837346929099921427098303503809773507263684626085921920343234606512875075",
      "1"
    ],
    "b": [
      [
        "3958960297738772916258666205616777970781765149824845012865028432983359824665",
        "12016726424119005839339901753382498079969199571774498139057101477951554269628"
      ],
      [
        "9422561494274889496959915111300561742180323233510478882713520009902886701600",
        "7847696142557332131871722508573249391294296952081554192650473356691911744918"
      ],
      [
        "1",
        "0"
      ]
    ],
    "c": [
      "14879978459917643413036131046031323539952714989434091384857383092609307573868",
      "2737304604196597293545108002723022311265168424073584948591086523089183710299",
      "1"
    ]
  },
  "issBase64Details": {
    "value": "yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC",
    "indexMod4": 1
  },
  "headerBase64": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJkN2VkMzM4YzBmMTQ1N2IyMTRhMjc0YjVlMGU2NjdiNDRhNDJkZGUiLCJ0eXAiOiJKV1QifQ"
}
```

### GET /health
Check the health of the service and OAuth providers.

### GET /debug/jwk/:provider/:keyId?
Inspect JWK information for debugging.

### POST /debug/clear-cache
Clear the JWK cache.

## Local Development

### Prerequisites
- Node.js 18+
- Yarn or npm
- Build tools (gcc, make, cmake) for rapidsnark (optional)

### Setup

1. Install dependencies:
```bash
yarn install
```

2. Run the server:
```bash
yarn start
```

## Docker Deployment

Railway uses `Dockerfile.railway` (no trusted setup). The ceremony image is local-only:

```bash
docker build -f Dockerfile.dev-ceremony -t zklogin-prover-dev .
```

Do not point Railway at `Dockerfile.dev-ceremony`.

## Railway Deployment

Production proves with `zklogin_myso_final.zkey` and the matching WASM on the `keys-storage` volume mounted at `/app/keys`. The process exits before it listens if either SHA-256 does not match. See [docs/RAILWAY_DEPLOY.md](docs/RAILWAY_DEPLOY.md).

The same zkey is the localnet verifying key documented in myso-core (`docs/content/guides/developer/cryptography/zklogin-integration.mdx`, SHA-256 `0b892f2a26827ba5cf9fb0ad936596f940d04e5efb7c8f87d23566775865fc2e`).

## Project Structure

```
zklogin-prover/
├── circuits/          # Circom circuit files
│   └── zklogin_myso.circom
├── keys/              # Volume layout: zkey + zklogin_myso_js/zklogin_myso.wasm
├── server.js          # Express API server
├── verify-prover-artifacts.js
├── Dockerfile.railway # Production image (no ceremony)
├── Dockerfile.dev-ceremony
└── package.json
```

## Critical Implementation Notes

1. **MySoKit Proof Format**: The proof format must exactly match MySoKit's expectations:
   - Array `a` must have 3 elements with the third being `"1"`
   - Array `b` must have 3 rows, with the third being `["1", "0"]`
   - Values in `b` arrays must be flipped compared to snarkjs output
   - Array `c` must have 3 elements with the third being `"1"`

2. **File Paths**: Startup loads only `keys/zklogin_myso_final.zkey` and `keys/zklogin_myso_js/zklogin_myso.wasm` (override with `ZKEY_PATH` and `WASM_PATH`) and checks their SHA-256 before listening.

3. **Timeout Handling**: The service implements robust timeout handling to prevent hanging requests.

4. **JWK Caching**: OAuth provider JWKs are cached to improve performance and reduce external API calls.

## Security Notes

- This implementation verifies RSA signatures in zero-knowledge
- OAuth JWTs are validated for expiration, signature, and issuer
- Proper error handling prevents information leakage
- Production deployments should use HTTPS and appropriate rate limiting
- Consider implementing additional security measures like IP restrictions for sensitive deployments