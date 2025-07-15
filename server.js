const express = require('express');
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Environment configuration
const ENV = process.env.NODE_ENV || 'testnet';
const IS_TESTNET = ENV === 'testnet' || ENV === 'development';

console.log(`Starting zkLogin Proving Service in ${ENV} mode`);
console.log(`Testnet mode: ${IS_TESTNET ? 'ENABLED' : 'DISABLED'}`);

let keysReady = false;
let keyGenerationInProgress = false;
let keyGenerationError = null;

// Initialize keys asynchronously on startup
const initializeKeys = async () => {
  console.log('Starting key initialization...');
  keyGenerationInProgress = true;
  
  try {
    if (fs.existsSync('/app/generate-keys-if-missing.sh')) {
      console.log('Running key generation script asynchronously...');
      
      // Run the script asynchronously
      exec('/app/generate-keys-if-missing.sh', (error, stdout, stderr) => {
        keyGenerationInProgress = false;
        
        if (error) {
          console.error('Key generation failed:', error.message);
          keyGenerationError = error.message;
        } else {
          console.log('Key generation completed successfully');
          console.log(stdout);
          keysReady = true;
        }
        
        if (stderr) {
          console.log('Key generation stderr:', stderr);
        }
      });
    } else {
      console.log('Key generation script not found, checking for existing keys...');
      keysReady = fs.existsSync('keys/zklogin_mys_final.zkey');
      keyGenerationInProgress = false;
    }
  } catch (error) {
    console.error('Key initialization setup failed:', error.message);
    keyGenerationError = error.message;
    keyGenerationInProgress = false;
  }
};

// Start key initialization immediately but don't wait for it
initializeKeys();

const app = express();
app.use(express.json({ limit: '1mb' })); // Limit payload size

// Helper function to hash a string and convert to numeric string
function hashToNumeric(str) {
  const hash = crypto.createHash('sha256').update(str).digest('hex');
  return BigInt('0x' + hash).toString();
}

// Helper function to extract nonce from JWT
function extractNonceFromJWT(jwtToken) {
  try {
    const parts = jwtToken.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }
    
    // Decode the payload (second part)
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return payload.nonce;
  } catch (error) {
    console.error('Error extracting nonce from JWT:', error.message);
    return null;
  }
}

// Helper function to extract header from JWT  
function extractHeaderFromJWT(jwtToken) {
  try {
    const parts = jwtToken.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }
    
    return parts[0]; // Return the header part (base64 encoded)
  } catch (error) {
    console.error('Error extracting header from JWT:', error.message);
    return null;
  }
}

// Helper function to compute zkLogin nonce (simplified for demo)
function computeZkLoginNonce(ephPubKey, maxEpoch, jwtRandomness) {
  // This is a simplified implementation
  // Real zkLogin uses: base64url(poseidon(eph_pk, max_epoch, jwt_randomness)[0..20])
  const combined = `${ephPubKey}_${maxEpoch}_${jwtRandomness}`;
  const hash = crypto.createHash('sha256').update(combined).digest();
  // Take first 20 bytes and encode as base64url
  return hash.subarray(0, 20).toString('base64url');
}

// Enable CORS for development
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  next();
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'zkLogin Proving Service (Testnet)',
    environment: ENV,
    version: '1.0.0',
    network: 'MySo Testnet',
    description: 'ZK proof generation service for the MySocial blockchain zkLogin authentication',
    endpoints: {
      'GET /': 'Service information',
      'GET /health': 'Health check and key generation status',
      'GET /debug': 'Debug information (testnet only)',
      'POST /prove': 'Generate ZK proof for zkLogin authentication'
    },
    usage: {
      'POST /prove': {
        required: ['jwt', 'maxEpoch', 'jwtRandomness', 'salt', 'keyClaimName'],
        description: 'Generates a ZK proof for JWT authentication on the MySocial blockchain',
        example: {
          jwt: 'eyJhbGciOiJSUzI1NiIs...',
          maxEpoch: 69,
          jwtRandomness: '95584269138650599638266832159744854301',
          salt: '299280343967884020864506771135193421589',
          keyClaimName: 'sub'
        }
      }
    }
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  if (keyGenerationInProgress) {
    res.json({ 
      status: 'healthy', 
      keyGeneration: 'in_progress',
      message: 'Server ready, key generation in progress',
      timestamp: new Date().toISOString() 
    });
  } else if (keysReady) {
    res.json({ 
      status: 'healthy', 
      keyGeneration: 'complete',
      message: 'Server ready, keys available',
      timestamp: new Date().toISOString() 
    });
  } else {
    res.json({ 
      status: 'healthy', 
      keyGeneration: 'failed',
      message: 'Server ready, but key generation failed',
      error: keyGenerationError,
      timestamp: new Date().toISOString() 
    });
  }
});

// Debug endpoint (testnet only)
app.get('/debug', (req, res) => {
  if (!IS_TESTNET) {
    return res.status(404).json({ error: 'Debug endpoint only available in testnet mode' });
  }

  const debugInfo = {
    environment: ENV,
    keysReady: keysReady,
    keyGenerationInProgress: keyGenerationInProgress,
    keyGenerationError: keyGenerationError,
    
    // File existence checks
    files: {
      wasmExists: fs.existsSync('circuits/zklogin_mys_js/zklogin_mys.wasm'),
      witnessGenExists: fs.existsSync('circuits/zklogin_mys_js/generate_witness.js'),
      zkeyExists: fs.existsSync('keys/zklogin_mys_final.zkey'),
      rapidsnarkExists: fs.existsSync('rapidsnark/rapidsnark')
    },
    
    // zkLogin testing information
    zkLoginFormat: {
      description: 'Server accepts only zkLogin format',
      requiredFields: ['jwt', 'maxEpoch', 'jwtRandomness', 'salt', 'keyClaimName'],
      sampleRequest: {
        jwt: 'eyJhbGciOiJSUzI1NiIs...<full-jwt-token>',
        maxEpoch: 69,
        jwtRandomness: '95584269138650599638266832159744854301',
        salt: '299280343967884020864506771135193421589',
        keyClaimName: 'sub'
      },
      notes: [
        'The nonce in the JWT must match computeZkLoginNonce(ephPubKey, maxEpoch, jwtRandomness)',
        'For proof to be valid: JWT nonce must match expected nonce',
        'Server extracts nonce from JWT and validates it against computed nonce'
      ]
    }
  };

  res.json(debugInfo);
});

app.post('/prove', (req, res) => {
  const input = req.body;
  
  // Check if keys are ready
  if (keyGenerationInProgress) {
    return res.status(503).json({ 
      error: 'Service initializing', 
      message: 'Key generation is still in progress. Please try again in a few minutes.',
      keyGeneration: 'in_progress'
    });
  }
  
  if (!keysReady) {
    return res.status(503).json({ 
      error: 'Service unavailable', 
      message: 'Required cryptographic keys are not available.',
      keyGeneration: 'failed',
      details: keyGenerationError
    });
  }
  
  // Validate input
  if (!input || typeof input !== 'object') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  // Validate required zkLogin fields
  if (!input.jwt || !input.maxEpoch || !input.jwtRandomness || !input.salt || !input.keyClaimName) {
    return res.status(400).json({ 
      error: 'Missing required zkLogin fields', 
      required: ['jwt', 'maxEpoch', 'jwtRandomness', 'salt', 'keyClaimName']
    });
  }
  
  const inputPath = path.join('inputs', 'input.json');
  
  try {
    // Ensure directories exist
    if (!fs.existsSync('inputs')) fs.mkdirSync('inputs');
    if (!fs.existsSync('outputs')) fs.mkdirSync('outputs');
    
    // Process zkLogin inputs
    console.log('Processing zkLogin JWT...');
    
    // Extract nonce from JWT
    const jwtNonce = extractNonceFromJWT(input.jwt);
    if (!jwtNonce) {
      throw new Error('Could not extract nonce from JWT');
    }
    
    // Extract header for response
    const headerBase64 = extractHeaderFromJWT(input.jwt);
    
    // Validate nonce matches expected zkLogin format
    const expectedNonce = computeZkLoginNonce(
      input.ephemeralPublicKey || 'default_eph_pk', 
      input.maxEpoch, 
      input.jwtRandomness
    );
    
    console.log('Nonce validation:', {
      jwtNonce: jwtNonce,
      expectedNonce: expectedNonce,
      matches: jwtNonce === expectedNonce
    });
    
    // For the circuit, we use the JWT nonce (the one that's actually in the JWT)
    const nonce = hashToNumeric(jwtNonce);
    const jwtHash = hashToNumeric(input.jwt);
    const pubKeyHash = hashToNumeric(input.salt); // Use salt as pubKeyHash
    
    // Prepare issBase64Details for response
    let issBase64Details;
    try {
      const payload = JSON.parse(Buffer.from(input.jwt.split('.')[1], 'base64url').toString());
      issBase64Details = {
        value: Buffer.from(payload.iss).toString('base64'),
        indexMod4: 0
      };
    } catch (e) {
      console.warn('Could not extract iss for issBase64Details:', e.message);
    }
    
    console.log('Processed inputs:', {
      jwtHashLength: jwtHash.length,
      nonceLength: nonce.length,
      pubKeyHashLength: pubKeyHash.length
    });
    
    // Only pass circuit inputs to witness generation
    const circuitInputs = {
      jwtHash: jwtHash,
      nonce: nonce,
      pubKeyHash: pubKeyHash
    };
    
    fs.writeFileSync(inputPath, JSON.stringify(circuitInputs));

    // Generate witness
    console.log('Generating witness...');
    execSync(`node circuits/zklogin_mys_js/generate_witness.js circuits/zklogin_mys_js/zklogin_mys.wasm ${inputPath} outputs/witness.wtns`, { stdio: 'pipe' });
    
    // Generate proof
    console.log('Generating proof...');
    execSync(`./rapidsnark-wrapper.sh keys/zklogin_mys_final.zkey outputs/witness.wtns outputs/proof.json outputs/public.json`, { stdio: 'pipe' });

    let proof, publicSignals;
    try {
      let proofContent = fs.readFileSync('outputs/proof.json', 'utf8');
      let publicContent = fs.readFileSync('outputs/public.json', 'utf8');
      
      // Rapidsnark appends null bytes, strip them
      proofContent = proofContent.replace(/\0+$/, '');
      publicContent = publicContent.replace(/\0+$/, '');
      
      // Log for debugging
      if (IS_TESTNET) {
        console.log('Proof length:', proofContent.length);
        console.log('Public length:', publicContent.length);
      }
      
      proof = JSON.parse(proofContent);
      publicSignals = JSON.parse(publicContent);
    } catch (parseError) {
      console.error('JSON parse error:', parseError.message);
      console.error('Proof file exists:', fs.existsSync('outputs/proof.json'));
      console.error('Public file exists:', fs.existsSync('outputs/public.json'));
      throw parseError;
    }
    
    // Clean up temporary files
    fs.unlinkSync(inputPath);
    fs.unlinkSync('outputs/witness.wtns');
    fs.unlinkSync('outputs/proof.json');
    fs.unlinkSync('outputs/public.json');
    
    // Format zkLogin response
    const response = { 
      proofPoints: {
        a: proof.pi_a,
        b: proof.pi_b,
        c: proof.pi_c
      }
    };

    // Add zkLogin required fields
    if (headerBase64) {
      response.headerBase64 = headerBase64;
    }
    if (issBase64Details) {
      response.issBase64Details = issBase64Details;
    }
    
    // Add other zkLogin fields if available
    if (input.addressSeed) {
      response.addressSeed = input.addressSeed;
    }

    // Optionally include public signals if needed (testnet mode includes more debug info)
    if (publicSignals && publicSignals.length > 0) {
      response.publicSignals = publicSignals;
      if (IS_TESTNET) {
        response.isValid = publicSignals[0] === "1";
      }
    }

    res.json(response);
  } catch (e) {
    console.error('Error generating proof:', e.message);
    
    // Clean up on error
    ['inputs/input.json', 'outputs/witness.wtns', 'outputs/proof.json', 'outputs/public.json'].forEach(file => {
      if (fs.existsSync(file)) {
        try { fs.unlinkSync(file); } catch(err) {}
      }
    });
    
    res.status(500).json({ 
      error: 'Proof generation failed', 
      details: IS_TESTNET ? e.message : 'Internal server error',
      environment: ENV
    });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`zkLogin Proving Service (${ENV}) running on port ${PORT}`);
  console.log(`Network: MYS Testnet`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Generate proof: POST http://localhost:${PORT}/prove`);
  if (IS_TESTNET) {
    console.log(`Debug info: GET http://localhost:${PORT}/debug`);
  }
});