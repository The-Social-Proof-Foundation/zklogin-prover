const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

/** SHA-256 of zklogin_myso_final.zkey. Must match myso-core localnet verifying key. */
const EXPECTED_ZKEY_SHA256 = '0b892f2a26827ba5cf9fb0ad936596f940d04e5efb7c8f87d23566775865fc2e'

/**
 * SHA-256 of build/zklogin_myso_js/zklogin_myso.wasm compiled from circuits/zklogin_myso.circom
 * alongside that zkey (local build-production artifact, Oct 2026).
 */
const EXPECTED_WASM_SHA256 = '758f63cb747e5fe8db8510de90856d4c6305fcb62e616801cacbe5e237f54e08'

/**
 * SHA-256 of circuits/zklogin_myso_cpp/zklogin_myso.dat from the Circom --c build
 * of zklogin_myso.circom (synced Oct 2026).
 */
const EXPECTED_WITNESS_DAT_SHA256 =
  '726dfc955b87009fc96c8bc8e445458f583a5377ac875e97d5b440f21b2ccc36'

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(filePath)
    stream.on('error', reject)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}

function witnessEngine() {
  const raw = (process.env.WITNESS_ENGINE || 'cpp').trim().toLowerCase()
  return raw === 'wasm' ? 'wasm' : 'cpp'
}

function artifactPaths() {
  const keysRoot = process.env.ZKLOGIN_KEYS_DIR || path.join(__dirname, 'keys')
  const witnessBinPath =
    process.env.WITNESS_BIN || path.join(keysRoot, 'zklogin_myso_cpp', 'zklogin_myso')
  return {
    zkeyPath: process.env.ZKEY_PATH || path.join(keysRoot, 'zklogin_myso_final.zkey'),
    wasmPath:
      process.env.WASM_PATH || path.join(keysRoot, 'zklogin_myso_js', 'zklogin_myso.wasm'),
    witnessBinPath,
    witnessDatPath: `${witnessBinPath}.dat`,
  }
}

async function verifyHashedArtifact(label, filePath, expected) {
  if (!fs.existsSync(filePath)) {
    console.error(`[zklogin-prover] missing ${label}: ${filePath}`)
    console.error(`[zklogin-prover] expected SHA-256 ${expected}`)
    process.exit(1)
  }
  const actual = await sha256File(filePath)
  if (actual !== expected) {
    console.error(`[zklogin-prover] ${label} SHA-256 mismatch`)
    console.error(`[zklogin-prover] path: ${filePath}`)
    console.error(`[zklogin-prover] expected: ${expected}`)
    console.error(`[zklogin-prover] actual:   ${actual}`)
    process.exit(1)
  }
  console.log(`[zklogin-prover] ${label} ok`)
  console.log(`[zklogin-prover] path: ${filePath}`)
  console.log(`[zklogin-prover] sha256: ${actual}`)
}

async function verifyProverArtifacts() {
  const paths = artifactPaths()
  const engine = witnessEngine()

  await verifyHashedArtifact('zkey', paths.zkeyPath, EXPECTED_ZKEY_SHA256)

  if (engine === 'cpp') {
    if (!fs.existsSync(paths.witnessBinPath)) {
      console.error(`[zklogin-prover] missing witness binary: ${paths.witnessBinPath}`)
      process.exit(1)
    }
    // Railway volume uploads strip +x; restore before the executable check.
    try {
      fs.chmodSync(paths.witnessBinPath, 0o755)
    } catch (err) {
      console.error(
        `[zklogin-prover] failed to chmod witness binary: ${paths.witnessBinPath}`,
        err.message
      )
      process.exit(1)
    }
    try {
      fs.accessSync(paths.witnessBinPath, fs.constants.X_OK)
    } catch {
      console.error(`[zklogin-prover] witness binary is not executable: ${paths.witnessBinPath}`)
      process.exit(1)
    }
    console.log('[zklogin-prover] witness-bin ok')
    console.log(`[zklogin-prover] path: ${paths.witnessBinPath}`)

    await verifyHashedArtifact('witness-dat', paths.witnessDatPath, EXPECTED_WITNESS_DAT_SHA256)
  } else {
    await verifyHashedArtifact('wasm', paths.wasmPath, EXPECTED_WASM_SHA256)
  }

  // Optional wasm check when cpp is primary (kept on volume for WITNESS_ENGINE=wasm).
  if (engine === 'cpp' && fs.existsSync(paths.wasmPath)) {
    const actual = await sha256File(paths.wasmPath)
    if (actual !== EXPECTED_WASM_SHA256) {
      console.warn(`[zklogin-prover] wasm SHA-256 mismatch (ignored; WITNESS_ENGINE=cpp)`)
      console.warn(`[zklogin-prover] path: ${paths.wasmPath}`)
      console.warn(`[zklogin-prover] expected: ${EXPECTED_WASM_SHA256}`)
      console.warn(`[zklogin-prover] actual:   ${actual}`)
    } else {
      console.log('[zklogin-prover] wasm ok (optional; WITNESS_ENGINE=cpp)')
      console.log(`[zklogin-prover] path: ${paths.wasmPath}`)
      console.log(`[zklogin-prover] sha256: ${actual}`)
    }
  }

  // Same volume-upload +x strip for OpenMP rapidsnark when pointed at /app/keys.
  const rapidsnarkBin = process.env.RAPIDSNARK_BIN
  if (rapidsnarkBin && fs.existsSync(rapidsnarkBin)) {
    try {
      fs.chmodSync(rapidsnarkBin, 0o755)
      console.log('[zklogin-prover] rapidsnark-bin chmod ok')
      console.log(`[zklogin-prover] path: ${rapidsnarkBin}`)
    } catch (err) {
      console.warn(
        `[zklogin-prover] failed to chmod rapidsnark binary: ${rapidsnarkBin}`,
        err.message
      )
    }
  }

  console.log(`[zklogin-prover] witness engine: ${engine}`)
  return { ...paths, witnessEngine: engine }
}

module.exports = {
  EXPECTED_WASM_SHA256,
  EXPECTED_WITNESS_DAT_SHA256,
  EXPECTED_ZKEY_SHA256,
  artifactPaths,
  verifyProverArtifacts,
  witnessEngine,
}

if (require.main === module) {
  verifyProverArtifacts().catch((err) => {
    console.error('[zklogin-prover] artifact verification failed', err)
    process.exit(1)
  })
}
