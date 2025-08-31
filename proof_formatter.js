/**
 * Proof formatter for zkLogin proofs
 * This ensures consistency between the server's output and what MySoKit expects
 */

/**
 * Format a proof for MySoKit compatibility
 * @param {Object} proof - The proof object from snarkjs 
 * @returns {Object} - The formatted proof for MySoKit
 */
function formatProofForMySoKit(proof) {
  if (!proof || !proof.pi_a || !proof.pi_b || !proof.pi_c) {
    throw new Error('Invalid proof structure');
  }
  
  // Check the shape of the proof
  console.log('Raw proof structure:');
  console.log('pi_a:', JSON.stringify(proof.pi_a), `(length: ${proof.pi_a.length})`);
  console.log('pi_b:', JSON.stringify(proof.pi_b), `(outer length: ${proof.pi_b.length}, inner lengths: ${proof.pi_b[0].length}, ${proof.pi_b[1].length})`);
  console.log('pi_c:', JSON.stringify(proof.pi_c), `(length: ${proof.pi_c.length})`);
  
  // Handle normalization (remove 3rd element from a, if it exists)
  // MySoKit expects exactly 2 elements in 'a', while snarkjs may return 3
  const normalizedProof = {
    pi_a: proof.pi_a.slice(0, 2), // Take only first two elements
    pi_b: proof.pi_b,
    pi_c: proof.pi_c
  };
  
  console.log('Normalized proof structure:');
  console.log('pi_a:', JSON.stringify(normalizedProof.pi_a), `(length: ${normalizedProof.pi_a.length})`);
  
  // Use normalized proof from here onwards
  proof = normalizedProof;
  
  // Ensure proof points are properly formatted
  const formattedProof = {
    // Format 'a' points - MySoKit expects only the first 2 elements
    // The 3rd element (typically "1") is a normalization factor not used by MySoKit
    a: [
      proof.pi_a[0].toString(),
      proof.pi_a[1].toString()
    ],
    
    // Format 'b' points - should be 2x2 array of strings
    b: [
      [proof.pi_b[0][0].toString(), proof.pi_b[0][1].toString()],
      [proof.pi_b[1][0].toString(), proof.pi_b[1][1].toString()]
    ],
    
    // Format 'c' points - should be exactly 2 points as strings
    c: [
      proof.pi_c[0].toString(), 
      proof.pi_c[1].toString()
    ]
  };
  
  // Validate the shape of the formatted proof
  validateProofShape(formattedProof);
  
  return formattedProof;
}

/**
 * Validate the shape of a formatted proof
 * @param {Object} formattedProof - The formatted proof object 
 */
function validateProofShape(formattedProof) {
  // Check 'a' points
  if (!Array.isArray(formattedProof.a) || formattedProof.a.length !== 2) {
    throw new Error(`Invalid 'a' points shape: Expected array of length 2, got ${formattedProof.a.length}`);
  }
  
  // Check 'b' points
  if (!Array.isArray(formattedProof.b) || formattedProof.b.length !== 2) {
    throw new Error(`Invalid 'b' points shape: Expected array of length 2, got ${formattedProof.b.length}`);
  }
  
  if (!Array.isArray(formattedProof.b[0]) || formattedProof.b[0].length !== 2) {
    throw new Error(`Invalid 'b[0]' points shape: Expected array of length 2, got ${formattedProof.b[0].length}`);
  }
  
  if (!Array.isArray(formattedProof.b[1]) || formattedProof.b[1].length !== 2) {
    throw new Error(`Invalid 'b[1]' points shape: Expected array of length 2, got ${formattedProof.b[1].length}`);
  }
  
  // Check 'c' points
  if (!Array.isArray(formattedProof.c) || formattedProof.c.length !== 2) {
    throw new Error(`Invalid 'c' points shape: Expected array of length 2, got ${formattedProof.c.length}`);
  }
  
  console.log('Proof validation passed. Shape is correct.');
}

module.exports = {
  formatProofForMySoKit
};
