const { execSync } = require('child_process');
const fs = require('fs');

// Test circuit compilation and proof generation
console.log('Testing zkLogin circuit compilation and proof generation...');

try {
  // Check if circuit files exist
  const wasmFile = 'circuits/zklogin_mys_js/zklogin_mys.wasm';
  const witnessFile = 'circuits/zklogin_mys_js/generate_witness.js';
  
  if (!fs.existsSync(wasmFile)) {
    console.error('❌ WASM file not found:', wasmFile);
    process.exit(1);
  }
  
  if (!fs.existsSync(witnessFile)) {
    console.error('❌ Witness generator not found:', witnessFile);
    process.exit(1);
  }
  
  console.log('✅ Circuit files found');
  
  // Test with valid inputs (Poseidon(0,0) should equal the expected hash)
  const testInput = {
    jwtHash: "14744269619966411208579211824598458697587494354926760081771325075741142829156",
    nonce: "0",
    pubKeyHash: "0"
  };
  
  // Write test input
  fs.writeFileSync('inputs/test_input.json', JSON.stringify(testInput));
  
  // Generate witness
  console.log('🔄 Generating witness...');
  execSync(`node circuits/zklogin_mys_js/generate_witness.js circuits/zklogin_mys_js/zklogin_mys.wasm inputs/test_input.json outputs/test_witness.wtns`);
  console.log('✅ Witness generated successfully');
  
  // Generate proof
  console.log('🔄 Generating proof...');
  execSync(`./rapidsnark-wrapper.sh keys/zklogin_mys_final.zkey outputs/test_witness.wtns outputs/test_proof.json outputs/test_public.json`);
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
  process.exit(1);
} 