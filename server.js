const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const app = express();
app.use(express.json({ limit: '1mb' })); // Limit payload size

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
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.post('/prove', (req, res) => {
  const input = req.body;
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
    
    fs.writeFileSync(inputPath, JSON.stringify(input));

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
    
    // Format response similar to the demo
    res.json({ 
      proof: {
        pi_a: proof.pi_a,
        pi_b: proof.pi_b,
        pi_c: proof.pi_c,
        protocol: proof.protocol,
        curve: proof.curve
      },
      publicSignals
    });
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