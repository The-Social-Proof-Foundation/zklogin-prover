const express = require('express');
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

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
    service: 'zkLogin Proving Service',
    version: '1.0.0',
    endpoints: {
      POST: '/prove - Generate ZK proof',
      GET: '/health - Health check'
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

// Debug endpoint to check file system
app.get('/debug', (req, res) => {
  try {
    const debug = {
      cwd: process.cwd(),
      files: {
        root: fs.existsSync('.') ? fs.readdirSync('.').filter(f => !f.startsWith('.')) : 'NOT FOUND',
        keys: fs.existsSync('keys') ? fs.readdirSync('keys') : 'NOT FOUND',
        rapidsnark: fs.existsSync('rapidsnark') ? fs.readdirSync('rapidsnark') : 'NOT FOUND',
        circuits: fs.existsSync('circuits') ? fs.readdirSync('circuits') : 'NOT FOUND',
        circuitsJs: fs.existsSync('circuits/zklogin_mys_js') ? fs.readdirSync('circuits/zklogin_mys_js') : 'NOT FOUND'
      },
      rapidsnarkExecutable: fs.existsSync('rapidsnark/rapidsnark') ? 'EXISTS' : 'MISSING',
      wrapperScript: fs.existsSync('rapidsnark-wrapper.sh') ? 'EXISTS' : 'MISSING',
      zkeyFile: fs.existsSync('keys/zklogin_mys_final.zkey') ? 'EXISTS' : 'MISSING',
      wasmFile: fs.existsSync('circuits/zklogin_mys_js/zklogin_mys.wasm') ? 'EXISTS' : 'MISSING'
    };
    
    // Check permissions if files exist
    if (fs.existsSync('rapidsnark/rapidsnark')) {
      const stats = fs.statSync('rapidsnark/rapidsnark');
      debug.rapidsnarkPermissions = stats.mode.toString(8);
    }
    
    if (fs.existsSync('rapidsnark-wrapper.sh')) {
      const stats = fs.statSync('rapidsnark-wrapper.sh');
      debug.wrapperPermissions = stats.mode.toString(8);
    }
    
    res.json(debug);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
  
  // Validate required fields
  if (!input.jwtHash || !input.nonce || !input.pubKeyHash) {
    return res.status(400).json({ 
      error: 'Missing required fields', 
      required: ['jwtHash', 'nonce', 'pubKeyHash'] 
    });
  }
  
  const inputPath = path.join('inputs', 'input.json');
  
  try {
    // Ensure directories exist
    if (!fs.existsSync('inputs')) fs.mkdirSync('inputs');
    if (!fs.existsSync('outputs')) fs.mkdirSync('outputs');
    
    // Process inputs to ensure they're valid numeric strings for the circuit
    let jwtHash, nonce, pubKeyHash;
    
    // If jwtHash looks like a JWT token (contains dots), hash it
    if (typeof input.jwtHash === 'string' && input.jwtHash.includes('.')) {
      console.log('Processing JWT token to numeric hash...');
      jwtHash = hashToNumeric(input.jwtHash);
    } else if (typeof input.jwtHash === 'string' && input.jwtHash.length > 64) {
      // If it's a very long string, hash it
      console.log('Processing long string to numeric hash...');
      jwtHash = hashToNumeric(input.jwtHash);
    } else {
      // Try to convert to BigInt to validate it's a valid numeric string
      try {
        BigInt(input.jwtHash);
        jwtHash = input.jwtHash;
      } catch (e) {
        // If it's not a valid BigInt, hash it
        console.log('Invalid numeric format, hashing...');
        jwtHash = hashToNumeric(input.jwtHash);
      }
    }
    
    // Process nonce
    try {
      BigInt(input.nonce);
      nonce = input.nonce;
    } catch (e) {
      console.log('Converting nonce to numeric format...');
      nonce = hashToNumeric(input.nonce);
    }
    
    // Process pubKeyHash
    try {
      BigInt(input.pubKeyHash);
      pubKeyHash = input.pubKeyHash;
    } catch (e) {
      console.log('Converting pubKeyHash to numeric format...');
      pubKeyHash = hashToNumeric(input.pubKeyHash);
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
      console.log('Proof length:', proofContent.length);
      console.log('Public length:', publicContent.length);
      
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
    
    // Format response
    const response = { 
      proofPoints: {
        a: proof.pi_a,
        b: proof.pi_b,
        c: proof.pi_c
      }
    };

    // Add JWT-related fields if provided in the input
    if (input.issBase64Details) {
      response.issBase64Details = input.issBase64Details;
    }
    
    if (input.headerBase64) {
      response.headerBase64 = input.headerBase64;
    }

    // Optionally include public signals if needed
    if (publicSignals && publicSignals.length > 0) {
      response.publicSignals = publicSignals;
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
      details: e.message 
    });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`zkLogin Proving Service running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Generate proof: POST http://localhost:${PORT}/prove`);
}); 