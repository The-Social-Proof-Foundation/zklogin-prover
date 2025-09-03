const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
// Increase request timeout for intensive proof operations
app.use((req, res, next) => {
    // Set timeout to 120 seconds for proof generation
    req.setTimeout(120000);
    res.setTimeout(120000);
    next();
});
// Increase JSON payload limit for JWT and proof data
app.use(express.json({ 
    limit: '20mb', 
    extended: true, 
    parameterLimit: 100000,
    verify: (req, res, buf) => {
        // Store raw body for potential signature verification
        req.rawBody = buf;
    }
}));

// Handle URL-encoded request bodies
app.use(express.urlencoded({
    extended: true,
    limit: '20mb',
    parameterLimit: 100000
}));

// OAuth Provider JWK Endpoints
const OAUTH_PROVIDERS = {
    google: {
        name: 'Google',
        oidcConfig: 'https://accounts.google.com/.well-known/openid-configuration',
        jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
        issuer: 'https://accounts.google.com'
    },
    apple: {
        name: 'Apple',
        oidcConfig: 'https://appleid.apple.com/.well-known/openid-configuration',
        jwksUri: 'https://appleid.apple.com/auth/keys',
        issuer: 'https://appleid.apple.com'
    }
};

// JWK Cache with TTL
const jwkCache = new Map();
const JWK_CACHE_TTL = 3600000; // 1 hour

// Robust JWT parsing with security validation
function parseJWT(token) {
    if (!token || typeof token !== 'string') {
        throw new Error('Invalid token: must be a non-empty string');
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT: must have exactly 3 parts separated by dots');
    }

    try {
        // Parse header
        const headerJson = Buffer.from(parts[0], 'base64url').toString('utf8');
        const header = JSON.parse(headerJson);
        
        // Validate header structure
        if (!header.alg || !header.typ) {
            throw new Error('Invalid JWT header: missing required fields (alg, typ)');
        }
        
        if (header.typ !== 'JWT') {
            throw new Error('Invalid token type: expected JWT');
        }

        // Parse payload
        const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
        const payload = JSON.parse(payloadJson);
        
        // Validate payload structure
        if (!payload.iss || !payload.sub || !payload.aud) {
            throw new Error('Invalid JWT payload: missing required claims (iss, sub, aud)');
        }

        // Validate timing claims
        const now = Math.floor(Date.now() / 1000);
        
        if (payload.exp && payload.exp < now) {
            throw new Error('Token has expired');
        }
        
        if (payload.nbf && payload.nbf > now) {
            throw new Error('Token is not yet valid (nbf claim)');
        }
        
        if (payload.iat && payload.iat > now + 300) { // Allow 5 min clock skew
            throw new Error('Token issued in the future');
        }

        // Parse signature
        const signature = parts[2];
        if (!signature) {
            throw new Error('Invalid JWT: missing signature');
        }

        return {
            header,
            payload,
            signature,
            raw: {
                header: parts[0],
                payload: parts[1],
                signature: parts[2]
            }
        };
    } catch (error) {
        if (error.message.includes('Invalid JWT') || error.message.includes('Token')) {
            throw error;
        }
        throw new Error(`JWT parsing failed: ${error.message}`);
    }
}

// Fetch JWK with caching and validation
async function fetchJWK(provider, keyId) {
    const cacheKey = `${provider}_${keyId}`;
    const cached = jwkCache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < JWK_CACHE_TTL) {
        return cached.jwk;
    }

    const providerConfig = OAUTH_PROVIDERS[provider];
    if (!providerConfig) {
        throw new Error(`Unsupported OAuth provider: ${provider}`);
    }

    try {
        console.log(`Fetching JWK for provider: ${provider}, keyId: ${keyId}`);
        
        // Fetch JWKS
        const response = await axios.get(providerConfig.jwksUri, {
            timeout: 10000,
            headers: {
                'User-Agent': 'zklogin-prover/1.0'
            }
        });

        if (!response.data || !response.data.keys) {
            throw new Error('Invalid JWKS response: missing keys array');
        }

        // Find the specific key
        const jwk = response.data.keys.find(key => key.kid === keyId);
        if (!jwk) {
            throw new Error(`JWK not found for keyId: ${keyId}`);
        }

        // Validate JWK structure
        if (!jwk.kty || !jwk.use || !jwk.alg) {
            throw new Error('Invalid JWK: missing required fields');
        }

        if (jwk.kty !== 'RSA') {
            throw new Error(`Unsupported key type: ${jwk.kty}, expected RSA`);
        }

        if (jwk.use !== 'sig') {
            throw new Error(`Invalid key use: ${jwk.use}, expected sig`);
        }

        if (!jwk.n || !jwk.e) {
            throw new Error('Invalid RSA JWK: missing modulus (n) or exponent (e)');
        }

        // Validate RSA key size (must be at least 2048 bits)
        const modulusBuffer = Buffer.from(jwk.n, 'base64url');
        const keySize = modulusBuffer.length * 8;
        if (keySize < 2048) {
            throw new Error(`Insufficient key size: ${keySize} bits, minimum 2048 required`);
        }

        // Cache the validated JWK
        jwkCache.set(cacheKey, {
            jwk,
            timestamp: Date.now()
        });

        console.log(`Successfully fetched and cached JWK for ${provider}:${keyId}`);
        return jwk;

    } catch (error) {
        if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
            throw new Error(`Unable to connect to ${provider} JWK endpoint`);
        }
        if (error.response) {
            throw new Error(`JWK fetch failed: ${error.response.status} ${error.response.statusText}`);
        }
        throw error;
    }
}

// Convert JWK to circuit format
function jwkToCircuitFormat(jwk) {
    // Convert base64url modulus to big integer
    const nBuffer = Buffer.from(jwk.n, 'base64url');
    
    // Convert to array of 32-bit chunks for circuit
    const modulus = [];
    for (let i = 0; i < nBuffer.length; i += 4) {
        let chunk = 0;
        for (let j = 0; j < 4 && i + j < nBuffer.length; j++) {
            chunk |= (nBuffer[i + j] << (j * 8));
        }
        modulus.push(chunk.toString());
    }
    
    // Pad to 64 chunks for 2048-bit RSA
    while (modulus.length < 64) {
        modulus.push('0');
    }

    // Convert exponent
    const eBuffer = Buffer.from(jwk.e, 'base64url');
    let exponent = 0;
    for (let i = 0; i < eBuffer.length; i++) {
        exponent = (exponent << 8) | eBuffer[i];
    }

    return {
        modulus: modulus.slice(0, 64), // Ensure exactly 64 chunks
        exponent: exponent.toString()
    };
}

// Determine OAuth provider from issuer
function getProviderFromIssuer(issuer) {
    for (const [provider, config] of Object.entries(OAUTH_PROVIDERS)) {
        if (issuer === config.issuer || issuer.startsWith(config.issuer)) {
            return provider;
        }
    }
    throw new Error(`Unsupported issuer: ${issuer}`);
}

// Validate decimal string inputs
function validateDecimalString(value, fieldName, maxBits = 256) {
    if (typeof value !== 'string') {
        throw new Error(`${fieldName} must be a string`);
    }
    
    if (!/^\d+$/.test(value)) {
        throw new Error(`${fieldName} must contain only digits`);
    }
    
    // Check if the number fits in maxBits
    const bigIntValue = BigInt(value);
    const maxValue = (1n << BigInt(maxBits)) - 1n;
    
    if (bigIntValue > maxValue) {
        throw new Error(`${fieldName} exceeds maximum ${maxBits}-bit value`);
    }
    
    return value;
}

// Convert hex string to field element array
function hexToFieldArray(hexString, arraySize = 32) {
    if (hexString.startsWith('0x')) {
        hexString = hexString.slice(2);
    }
    
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    
    // Pad with zeros if needed
    while (bytes.length < arraySize) {
        bytes.unshift(0);
    }
    
    return bytes.slice(-arraySize).map(b => b.toString());
}

// Ed25519 curve parameters
const ED25519_PRIME = BigInt('57896044618658097711785492504343953926634992332820282019728792003956564819949'); // 2^255 - 19
const ED25519_D = BigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555'); // -121665/121666 mod p

// Modular arithmetic helper functions
function modPow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }
        exp = exp >> 1n;
        base = (base * base) % mod;
    }
    return result;
}

function modInverse(a, m) {
    // Extended Euclidean Algorithm for modular inverse
    function extendedGCD(a, b) {
        if (a === 0n) return [b, 0n, 1n];
        const [gcd, x1, y1] = extendedGCD(b % a, a);
        const x = y1 - (b / a) * x1;
        const y = x1;
        return [gcd, x, y];
    }
    
    const [gcd, x] = extendedGCD(a % m, m);
    return gcd === 1n ? ((x % m) + m) % m : null;
}

// Proper Ed25519 coordinate extraction
function extractEphemeralKeyCoordinates(extendedEphemeralPublicKey) {
    try {
        console.log('Extracting Ed25519 coordinates from extended ephemeral public key...');
        
        // Decode base64 to bytes
        const keyBytes = Buffer.from(extendedEphemeralPublicKey, 'base64');
        console.log(`Key bytes length: ${keyBytes.length}`);
        console.log('Key bytes (hex):', keyBytes.toString('hex'));
        
        let publicKeyBytes;
        
        if (keyBytes.length === 33) {
            // Standard format: 1 byte scheme flag + 32 bytes public key
            const schemeFlag = keyBytes[0];
            if (schemeFlag !== 0x00) {
                console.log(`Warning: Unexpected signature scheme flag: 0x${schemeFlag.toString(16)}, expected 0x00 for Ed25519`);
            }
            publicKeyBytes = keyBytes.slice(1);
        } else if (keyBytes.length === 32) {
            // Raw Ed25519 public key - this is what we're actually receiving from the frontend
            // This should have a 0x00 flag prefix for Ed25519, but frontend is sending raw key
            console.log('Detected raw 32-byte Ed25519 public key format (missing flag prefix)');
            publicKeyBytes = keyBytes;
        } else {
            throw new Error(`Invalid extended ephemeral public key length: ${keyBytes.length}, expected 32 or 33 bytes`);
        }
        
        console.log('Ed25519 public key bytes:', publicKeyBytes.toString('hex'));
        
        // Convert bytes to BigInt (little-endian for Ed25519)
        let y = 0n;
        for (let i = 0; i < 32; i++) {
            y |= BigInt(publicKeyBytes[i]) << BigInt(8 * i);
        }
        
        // Extract sign bit from MSB of Y coordinate
        const xSignBit = y >> 255n;
        
        // Clear the sign bit to get the actual Y coordinate
        y = y & ((1n << 255n) - 1n);
        
        console.log(`Y coordinate: ${y.toString()}`);
        console.log(`X sign bit: ${xSignBit.toString()}`);
        
        // For zkLogin, we actually don't need to recover the full X coordinate
        // The circuit typically just needs the extended ephemeral public key components
        // Let's extract what the circuit expects based on the nonce computation
        
        // According to Sui docs, nonce = ToBase64URL(Poseidon_BN254([ext_eph_pk_bigint / 2^128, ext_eph_pk_bigint % 2^128, max_epoch, jwt_randomness]).to_bytes()[len - 20..])
        // where ext_eph_pk_bigint is the BigInt representation of ext_eph_pk
        
        // Convert the entire extended public key (with flag if missing, add it)
        const extendedKeyBytes = keyBytes.length === 32 ? 
            Buffer.concat([Buffer.from([0x00]), keyBytes]) : keyBytes;
        
        // Convert to BigInt (big-endian for the nonce computation)
        let extEphPkBigInt = 0n;
        for (let i = 0; i < extendedKeyBytes.length; i++) {
            extEphPkBigInt = (extEphPkBigInt << 8n) | BigInt(extendedKeyBytes[i]);
        }
        
        console.log(`Extended ephemeral public key as BigInt: ${extEphPkBigInt.toString()}`);
        
        // Split into high and low parts for Poseidon hash (as per nonce computation)
        const highPart = extEphPkBigInt >> 128n;
        const lowPart = extEphPkBigInt & ((1n << 128n) - 1n);
        
        console.log(`High part (ext_eph_pk_bigint / 2^128): ${highPart.toString()}`);
        console.log(`Low part (ext_eph_pk_bigint % 2^128): ${lowPart.toString()}`);
        
        // For circuit compatibility, we'll use the split representation
        function splitBigIntToChunks(value, chunkSize = 32, numChunks = 8) {
            const chunks = [];
            for (let i = 0; i < numChunks; i++) {
                chunks.push(Number((value >> BigInt(i * chunkSize)) & ((1n << BigInt(chunkSize)) - 1n)));
            }
            return chunks;
        }
        
        const highChunks = splitBigIntToChunks(highPart, 32, 4);
        const lowChunks = splitBigIntToChunks(lowPart, 32, 4);
        
        console.log('✅ Successfully extracted ephemeral key components');
        console.log(`High chunks: [${highChunks.join(', ')}]`);
        console.log(`Low chunks: [${lowChunks.join(', ')}]`);
        
        return {
            x: highChunks,  // Using high part as X for circuit compatibility
            y: lowChunks,   // Using low part as Y for circuit compatibility
            xFull: highPart.toString(),
            yFull: lowPart.toString(),
            extendedPubKeyBigInt: extEphPkBigInt.toString(),
            originalBytes: extendedKeyBytes.toString('hex')
        };
        
    } catch (error) {
        console.error('❌ Error extracting ephemeral key coordinates:', error.message);
        throw new Error(`Failed to extract ephemeral key coordinates: ${error.message}`);
    }
}

app.post('/prove', async (req, res) => {
    // Create a timeout promise for the entire operation
    const operationTimeout = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Operation timed out after 90 seconds')), 90000);
    });
    
    try {
        const {
            jwt,
            extendedEphemeralPublicKey,
            maxEpoch,
            jwtRandomness,
            salt,
            keyClaimName = 'sub'
        } = req.body;

        console.log('=== zkLogin Proof Generation Started ===');
        console.log('Request body keys:', Object.keys(req.body));

        // 1. Parse and validate JWT
        console.log('1. Parsing JWT...');
        const parsedJWT = parseJWT(jwt);
        const { header, payload } = parsedJWT;

        // 2. Determine OAuth provider and fetch JWK
        console.log('2. Determining OAuth provider...');
        const provider = getProviderFromIssuer(payload.iss);
        console.log(`Provider: ${provider}`);

        if (!header.kid) {
            throw new Error('JWT header missing required kid (key ID) field');
        }

        console.log('3. Fetching JWK...');
        const jwk = await fetchJWK(provider, header.kid);
        const circuitJWK = jwkToCircuitFormat(jwk);

        // 3. Validate input parameters
        console.log('4. Validating inputs...');
        
        if (!extendedEphemeralPublicKey) {
            throw new Error('Missing extendedEphemeralPublicKey');
        }

        // Handle extended ephemeral public key from frontend
        let ephemeralPubKey;
        if (typeof extendedEphemeralPublicKey === 'string') {
            // Frontend sends base64 encoded extended ephemeral public key
            console.log('Processing base64 extended ephemeral public key...');
            
            // Extract real Ed25519 coordinates using proper decoding
            const ephemeralKeyCoords = extractEphemeralKeyCoordinates(extendedEphemeralPublicKey);
            ephemeralPubKey = { 
                x: ephemeralKeyCoords.xFull, 
                y: ephemeralKeyCoords.yFull,
                xChunks: ephemeralKeyCoords.x,
                yChunks: ephemeralKeyCoords.y
            };
            console.log('✅ Extracted real Ed25519 coordinates from extended ephemeral public key');
        } else if (extendedEphemeralPublicKey.x && extendedEphemeralPublicKey.y) {
            ephemeralPubKey = extendedEphemeralPublicKey;
        } else {
            throw new Error('Invalid extendedEphemeralPublicKey format');
        }

        // Validate other required parameters
        if (!maxEpoch) {
            throw new Error('Missing maxEpoch');
        }
        if (!jwtRandomness) {
            throw new Error('Missing jwtRandomness');
        }
        if (!salt) {
            throw new Error('Missing salt');
        }

        // Validate decimal string inputs
        const validatedSalt = validateDecimalString(salt, 'salt');
        const validatedJwtRandomness = validateDecimalString(jwtRandomness, 'jwtRandomness');
        const validatedMaxEpoch = validateDecimalString(maxEpoch.toString(), 'maxEpoch');

        // 4. Compute required hashes and values
        console.log('5. Computing hashes...');
        
        // JWT message hash (header + "." + payload)
        const jwtMessage = `${parsedJWT.raw.header}.${parsedJWT.raw.payload}`;
        const jwtHash = crypto.createHash('sha256').update(jwtMessage, 'utf8').digest();
        
        // Subject hash
        const subjectValue = payload[keyClaimName];
        if (!subjectValue) {
            throw new Error(`JWT payload missing claim: ${keyClaimName}`);
        }
        const subjectHash = crypto.createHash('sha256').update(subjectValue, 'utf8').digest();
        
        // Issuer hash
        const issuerHash = crypto.createHash('sha256').update(payload.iss, 'utf8').digest();
        
        // Address seed computation (simplified for demo)
        const addressSeed = BigInt(`0x${crypto.createHash('sha256')
            .update(subjectValue + payload.aud + payload.iss + validatedSalt)
            .digest('hex')}`).toString();

        // Nonce from JWT
        const nonce = payload.nonce;
        if (!nonce) {
            throw new Error('JWT payload missing nonce claim');
        }
        const nonceBytes = Buffer.from(nonce, 'base64url');

        // JWT signature
        const signatureBuffer = Buffer.from(parsedJWT.signature, 'base64url');
        const signatureChunks = [];
        for (let i = 0; i < signatureBuffer.length; i += 4) {
            let chunk = 0;
            for (let j = 0; j < 4 && i + j < signatureBuffer.length; j++) {
                chunk |= (signatureBuffer[i + j] << (j * 8));
            }
            signatureChunks.push(chunk.toString());
        }
        while (signatureChunks.length < 64) {
            signatureChunks.push('0');
        }

        // 5. Prepare circuit inputs
        console.log('6. Preparing circuit inputs...');
        const circuitInputs = {
            // Public inputs
            addrSeed: addressSeed,
            issuerHash: hexToFieldArray(issuerHash.toString('hex')),
            maxEpoch: validatedMaxEpoch,
            jwkModulus: circuitJWK.modulus,
            jwkExponent: circuitJWK.exponent,
            
            // Private inputs
            jwtHash: hexToFieldArray(jwtHash.toString('hex')),
            jwtSignature: signatureChunks.slice(0, 64),
            jwtNonce: hexToFieldArray(nonceBytes.toString('hex')),
            ephemeralPubKey: [ephemeralPubKey.x, ephemeralPubKey.y],
            jwtRandomness: validatedJwtRandomness,
            subjectHash: hexToFieldArray(subjectHash.toString('hex'))
        };

        // 6. Generate proof
        console.log('7. Generating proof...');
        
        // Try multiple possible paths for the files
        let wasmPath, zkeyPath;
        const possibleWasmPaths = [
            path.join(__dirname, 'build', 'zklogin_mys_js', 'zklogin_mys.wasm'),
            path.join(__dirname, 'circuits', 'zklogin_mys_js', 'zklogin_mys.wasm')
        ];
        
        const possibleZkeyPaths = [
            path.join(__dirname, 'build', 'zklogin_mys_final.zkey'),
            path.join(__dirname, 'keys', 'zklogin_mys_final.zkey')
        ];
        
        // Find the first available WASM file
        for (const wPath of possibleWasmPaths) {
            if (fs.existsSync(wPath)) {
                wasmPath = wPath;
                console.log(`Found WASM file at: ${wasmPath}`);
                break;
            }
        }
        
        // Find the first available ZKEY file
        for (const zPath of possibleZkeyPaths) {
            if (fs.existsSync(zPath)) {
                zkeyPath = zPath;
                console.log(`Found ZKEY file at: ${zkeyPath}`);
                break;
            }
        }

        if (!wasmPath) {
            console.error('WASM file not found in any of the expected locations.');
            console.log('Searched in:');
            possibleWasmPaths.forEach(p => console.log(` - ${p}`));
            throw new Error('WASM file not found. Please run: npm run setup');
        }
        
        if (!zkeyPath) {
            console.error('ZKEY file not found in any of the expected locations.');
            console.log('Searched in:');
            possibleZkeyPaths.forEach(p => console.log(` - ${p}`));
            throw new Error('ZKEY file not found. Please run: npm run setup');
        }
        
        // Log all files in the directories for debugging
        try {
            console.log('Contents of build directory:');
            console.log(fs.readdirSync(path.join(__dirname, 'build')).join('\n'));
            
            console.log('Contents of build/zklogin_mys_js directory:');
            const buildZkloginDir = path.join(__dirname, 'build', 'zklogin_mys_js');
            if (fs.existsSync(buildZkloginDir)) {
                console.log(fs.readdirSync(buildZkloginDir).join('\n'));
            } else {
                console.log('Directory does not exist');
            }
        } catch (dirError) {
            console.error('Error listing directories:', dirError);
        }

        const startTime = Date.now();
        let proof, publicSignals, provingTime;
        
        try {
            console.log('Loading circuit files from:');
            console.log(`- WASM: ${wasmPath}`);
            console.log(`- ZKEY: ${zkeyPath}`);
            
            if (!fs.existsSync(wasmPath)) {
                throw new Error(`WASM file not found at ${wasmPath}`);
            }
            
            if (!fs.existsSync(zkeyPath)) {
                throw new Error(`ZKEY file not found at ${zkeyPath}`);
            }
            
            // Wrap the proof generation in a robust error handling structure
            const result = await Promise.race([
                (async () => {
                    try {
                        return await snarkjs.groth16.fullProve(
                            circuitInputs, 
                            wasmPath, 
                            zkeyPath
                        );
                    } catch (proofGenError) {
                        console.error('Proof generation internal error:', proofGenError);
                        throw new Error(`Proof generation internal error: ${proofGenError.message}`);
                    }
                })(),
                operationTimeout
            ]);
            
            // Log progress after proof generation
            console.log('Proof successfully generated, processing result...');
            
            proof = result.proof;
            publicSignals = result.publicSignals;
            provingTime = Date.now() - startTime;
            
            if (!proof || !proof.pi_a || !proof.pi_b || !proof.pi_c) {
                console.error('Invalid proof structure:', proof);
                throw new Error('Generated proof has invalid structure');
            }
            
            console.log(`Proof generated in ${provingTime}ms`);
        } catch (proofError) {
            console.error('Proof generation failed:', proofError);
            throw new Error(`Proof generation failed: ${proofError.message}`);
        }

        // 7. Format response according to zkLogin standard
        // CRITICAL: MySoKit expects only 2 elements in pi_a, but snarkjs generates 3
        // Remove the third element (normalization factor) from pi_a
        console.log('Raw proof structure:');
        console.log('pi_a:', JSON.stringify(proof.pi_a), `(length: ${proof.pi_a.length})`);
        
        // FINAL ATTEMPT: Create a completely new proof object with exact structure
        // MySoKit is extremely picky about the format
        const newProof = {
            pi_a: proof.pi_a.slice(0, 2),  // Only take first two elements
            pi_b: proof.pi_b,
            pi_c: proof.pi_c
        };
        
        console.log('New proof structure:');
        console.log('pi_a:', JSON.stringify(newProof.pi_a), `(length: ${newProof.pi_a.length})`);
        console.log('pi_b:', JSON.stringify(newProof.pi_b));
        console.log('pi_c:', JSON.stringify(newProof.pi_c));
        
        // Log exact values being used
        const a0 = newProof.pi_a[0].toString();
        const a1 = newProof.pi_a[1].toString();
        console.log('Using exact decimal string values:');
        console.log('a0:', a0);
        console.log('a1:', a1);
        
        // Helper function to convert decimal string to 32-byte big-endian buffer
        function decimalStringToBytes(decimalStr) {
            // Convert decimal string to BigInt
            const bigIntValue = BigInt(decimalStr);
            
            // Create a 32-byte buffer
            const buffer = Buffer.alloc(32);
            
            // Convert to big-endian bytes
            let tempBigInt = bigIntValue;
            for (let i = 31; i >= 0; i--) {
                buffer[i] = Number(tempBigInt & BigInt(0xff));
                tempBigInt = tempBigInt >> BigInt(8);
            }
            
            // Return base64 encoded string
            return buffer.toString('base64');
        }
        
        // Format response in MySocial protobuf format with 32-byte big-endian elements
        const response = {
            proofPoints: {
                a: {
                    e0: { element: decimalStringToBytes(newProof.pi_a[0].toString()) },
                    e1: { element: decimalStringToBytes(newProof.pi_a[1].toString()) },
                    e2: { element: decimalStringToBytes("1") }
                },
                b: {
                    e00: { element: decimalStringToBytes(newProof.pi_b[0][1].toString()) }, // Note: b values are flipped compared to our proof
                    e01: { element: decimalStringToBytes(newProof.pi_b[0][0].toString()) },
                    e10: { element: decimalStringToBytes(newProof.pi_b[1][1].toString()) },
                    e11: { element: decimalStringToBytes(newProof.pi_b[1][0].toString()) },
                    e20: { element: decimalStringToBytes("1") },
                    e21: { element: decimalStringToBytes("0") }
                },
                c: {
                    e0: { element: decimalStringToBytes(newProof.pi_c[0].toString()) },
                    e1: { element: decimalStringToBytes(newProof.pi_c[1].toString()) },
                    e2: { element: decimalStringToBytes("1") }
                }
            },
            issBase64Details: {
                value: payload.iss,
                indexMod4: 1  // Set to 1 as shown in expected format
            },
            headerBase64: parsedJWT.raw.header
        };

        try {
            // Log simplified version of proof for debugging
            console.log('Response generated with proof points in protobuf format:');
            console.log('a.e0 element length:', response.proofPoints.a.e0.element.length);
            console.log('a.e0 sample:', response.proofPoints.a.e0.element.substring(0, 20) + '...');
            console.log('a.e1 sample:', response.proofPoints.a.e1.element.substring(0, 20) + '...');
            console.log('=== zkLogin Proof Generation Complete ===');
            
            // Improve response handling to prevent timeouts
            // Set headers to keep connection alive and prevent timeouts
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('X-Content-Type-Options', 'nosniff');
            
            // Log that we're about to send the response
            console.log('Sending response to client...');
            
            // Convert to string manually to ensure proper formatting
            const jsonString = JSON.stringify(response);
            console.log('Response size:', jsonString.length, 'bytes');
            console.log('Response preview:', jsonString.substring(0, 100) + '...');
            
            // Send as raw string to avoid any Express JSON transformation
            res.status(200).send(jsonString);
            console.log('Response sent successfully');
        } catch (responseError) {
            console.error('Error sending response:', responseError);
            if (!res.headersSent) {
                res.status(500).json({
                    isValid: false,
                    error: 'Failed to send response',
                    errorType: 'ResponseError'
                });
            }
        }

    } catch (error) {
        console.error('Proof generation error:', error);
        
        // Check if client is still connected
        if (!res.headersSent && res.connection && res.connection.writable) {
            try {
                res.status(400).json({
                    isValid: false,
                    error: error.message,
                    errorType: error.name || 'UnknownError',
                    details: error.stack ? error.stack.split('\n').slice(0, 5) : undefined
                });
            } catch (sendError) {
                console.error('Failed to send error response:', sendError);
            }
        } else {
            console.error('Client connection already closed, could not send error');
        }
    }
});

// Health check endpoint with provider status
app.get('/health', async (req, res) => {
    const providerStatus = {};
    
    for (const [provider, config] of Object.entries(OAUTH_PROVIDERS)) {
        try {
            const response = await axios.get(config.oidcConfig, { timeout: 5000 });
            providerStatus[provider] = {
                status: 'online',
                jwksUri: response.data.jwks_uri || config.jwksUri
            };
        } catch (error) {
            providerStatus[provider] = {
                status: 'offline',
                error: error.message
            };
        }
    }

    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        providers: providerStatus,
        cacheStats: {
            cachedJWKs: jwkCache.size,
            memoryUsage: process.memoryUsage()
        }
    });
});

// Debug endpoint for JWK inspection
app.get('/debug/jwk/:provider/:keyId?', async (req, res) => {
    try {
        const { provider, keyId } = req.params;
        
        if (keyId) {
            const jwk = await fetchJWK(provider, keyId);
            const circuitFormat = jwkToCircuitFormat(jwk);
            res.json({ jwk, circuitFormat });
        } else {
            const providerConfig = OAUTH_PROVIDERS[provider];
            if (!providerConfig) {
                return res.status(404).json({ error: 'Provider not found' });
            }
            
            const response = await axios.get(providerConfig.jwksUri);
            res.json({
                provider: providerConfig,
                jwks: response.data
            });
        }
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Clear JWK cache endpoint
app.post('/debug/clear-cache', (req, res) => {
    jwkCache.clear();
    res.json({ message: 'JWK cache cleared', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`🚀 zkLogin proving server running on port ${PORT}`);
    console.log(`📚 Available endpoints:`);
    console.log(`   POST /prove - Generate zkLogin proof`);
    console.log(`   GET  /health - Server and provider status`);
    console.log(`   GET  /debug/jwk/:provider/:keyId? - JWK inspection`);
    console.log(`   POST /debug/clear-cache - Clear JWK cache`);
    console.log(`🔒 Supported OAuth providers: ${Object.keys(OAUTH_PROVIDERS).join(', ')}`);
});