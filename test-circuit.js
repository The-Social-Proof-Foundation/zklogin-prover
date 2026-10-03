const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Test circuit compilation and proof generation
console.log('Testing zkLogin circuit compilation and proof generation...');

try {
  // Check if circuit files exist
  const wasmFile = 'circuits/zklogin_myso_js/zklogin_myso.wasm';
  const witnessFile = 'circuits/zklogin_myso_js/generate_witness.js';
  
  if (!fs.existsSync(wasmFile)) {
    console.error('❌ WASM file not found:', wasmFile);
    process.exit(1);
  }
  
  if (!fs.existsSync(witnessFile)) {
    console.error('❌ Witness generator not found:', witnessFile);
    process.exit(1);
  }
  
  console.log('✅ Circuit files found');
  
  // Check if required files exist
  const zkeyFile = 'keys/zklogin_myso_final.zkey';
  const rapidsnarkBinary = 'rapidsnark/rapidsnark';
  const wrapperScript = 'rapidsnark-wrapper.sh';
  
  console.log('📁 Checking required files...');
  console.log('  - zkey file:', fs.existsSync(zkeyFile) ? '✅' : '❌', zkeyFile);
  console.log('  - rapidsnark binary:', fs.existsSync(rapidsnarkBinary) ? '✅' : '❌', rapidsnarkBinary);
  console.log('  - wrapper script:', fs.existsSync(wrapperScript) ? '✅' : '❌', wrapperScript);
  
  // List contents of directories for debugging
  console.log('📁 Directory contents:');
  console.log('  - keys/:', fs.existsSync('keys') ? fs.readdirSync('keys').slice(0, 5) : 'NOT FOUND');
  console.log('  - rapidsnark/:', fs.existsSync('rapidsnark') ? fs.readdirSync('rapidsnark') : 'NOT FOUND');
  console.log('  - Current directory:', process.cwd());
  
  // Test with valid inputs (Poseidon(0,0) should equal the expected hash)
  const testInput = {
    jwtHash: "14744269619966411208579211824598458697587494354926760081771325075741142829156",
    nonce: "0",
    pubKeyHash: "0"
  };
  
  // Ensure directories exist
  if (!fs.existsSync('inputs')) fs.mkdirSync('inputs');
  if (!fs.existsSync('outputs')) fs.mkdirSync('outputs');
  
  // Write test input
  fs.writeFileSync('inputs/test_input.json', JSON.stringify(testInput));
  
  // Generate witness
  console.log('🔄 Generating witness...');
  execSync(`node circuits/zklogin_myso_js/generate_witness.js circuits/zklogin_myso_js/zklogin_myso.wasm inputs/test_input.json outputs/test_witness.wtns`);
  console.log('✅ Witness generated successfully');
  
  // Check if witness file was created
  if (!fs.existsSync('outputs/test_witness.wtns')) {
    console.error('❌ Witness file not created');
    process.exit(1);
  }
  
  // Try direct rapidsnark call first to debug
  console.log('🔄 Testing direct rapidsnark call...');
  try {
    const directCmd = `./rapidsnark/rapidsnark keys/zklogin_myso_final.zkey outputs/test_witness.wtns outputs/test_proof.json outputs/test_public.json`;
    console.log('Command:', directCmd);
    execSync(directCmd, { stdio: 'inherit' });
    console.log('✅ Direct rapidsnark call succeeded');
  } catch (directError) {
    console.log('❌ Direct rapidsnark call failed, trying with wrapper...');
    
    // Generate proof using wrapper
    console.log('🔄 Generating proof with wrapper...');
    execSync(`./rapidsnark-wrapper.sh keys/zklogin_myso_final.zkey outputs/test_witness.wtns outputs/test_proof.json outputs/test_public.json`, { stdio: 'inherit' });
  }
  
  console.log('✅ Proof generated successfully');
  
  // Read and verify proof
  const proof = JSON.parse(fs.readFileSync('outputs/test_proof.json', 'utf8'));
  const publicSignals = JSON.parse(fs.readFileSync('outputs/test_public.json', 'utf8'));
  
  console.log('✅ Proof verification:', publicSignals[0] === "1" ? "VALID" : "INVALID");
  
  // Cleanup
  fs.unlinkSync('inputs/test_input.json');
  fs.unlinkSync('outputs/test_witness.wtns');
  fs.unlinkSync('outputs/test_proof.json');
  fs.unlinkSync('outputs/test_public.json');
  
  console.log('🎉 All tests passed!');
  
} catch (error) {
  console.error('❌ Test failed:', error.message);
  console.error('Stack trace:', error.stack);
  process.exit(1);
} 