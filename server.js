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
app.use(express.json({ limit: '10mb' }));

// OAuth Provider JWK Endpoints
const OAUTH_PROVIDERS = {
    google: {
        name: 'Google',
        oidcConfig: 'https://accounts.google.com/.well-known/openid-configuration',
        jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
        issuer: 'https://accounts.google.com'
    },
    facebook: {
        name: 'Facebook',
        oidcConfig: 'https://www.facebook.com/.well-known/oauth/openid-connect/',
        jwksUri: 'https://www.facebook.com/.well-known/oauth/openid-connect/certs/',
        issuer: 'https://www.facebook.com'
    },
    apple: {
        name: 'Apple',
        oidcConfig: 'https://appleid.apple.com/.well-known/openid_configuration',
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

app.post('/prove', async (req, res) => {
    try {
        const {
            jwt,
            ephemeralKeyPair,
            maxEpoch,
            jwtRandomness,
            salt,
            keyClaimName = 'sub'
        } = req.body;

        console.log('=== zkLogin Proof Generation Started ===');

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
        
        if (!ephemeralKeyPair || !ephemeralKeyPair.publicKey) {
            throw new Error('Missing ephemeralKeyPair.publicKey');
        }

        const ephemeralPubKey = ephemeralKeyPair.publicKey;
        if (!ephemeralPubKey.x || !ephemeralPubKey.y) {
            throw new Error('Ephemeral public key missing x or y coordinates');
        }

        // Validate decimal string inputs
        const validatedSalt = validateDecimalString(salt, 'salt');
        const validatedJwtRandomness = validateDecimalString(jwtRandomness, 'jwtRandomness');
        const validatedMaxEpoch = validateDecimalString(maxEpoch, 'maxEpoch');

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
        
        const wasmPath = path.join(__dirname, 'build', 'zklogin_mys.wasm');
        const zkeyPath = path.join(__dirname, 'build', 'zklogin_mys_final.zkey');

        if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
            throw new Error('Circuit build files not found. Please run: npm run build');
        }

        const startTime = Date.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            circuitInputs, 
            wasmPath, 
            zkeyPath
        );
        const provingTime = Date.now() - startTime;
        
        console.log(`Proof generated in ${provingTime}ms`);

        // 7. Format response according to zkLogin standard
        const response = {
            isValid: true,
            proofPoints: {
                a: [proof.pi_a[0], proof.pi_a[1]],
                b: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
                c: [proof.pi_c[0], proof.pi_c[1]]
            },
            issBase64Details: {
                value: payload.iss,
                indexMod4: 0
            },
            headerBase64: parsedJWT.raw.header,
            addressSeed,
            provingTimeMs: provingTime,
            provider,
            keyId: header.kid,
            publicSignals,
            debugInfo: {
                circuitInputs: Object.fromEntries(
                    Object.entries(circuitInputs).map(([key, value]) => [
                        key, 
                        Array.isArray(value) ? `[${value.length} elements]` : value
                    ])
                )
            }
        };

        console.log('=== zkLogin Proof Generation Complete ===');
        res.json(response);

    } catch (error) {
        console.error('Proof generation error:', error);
        res.status(400).json({
            isValid: false,
            error: error.message,
            details: error.stack ? error.stack.split('\n').slice(0, 5) : undefined
        });
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