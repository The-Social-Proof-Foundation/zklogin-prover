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

function proveEngine() {
  const raw = (process.env.PROVE_ENGINE || 'proverServer').trim().toLowerCase()
  if (raw === 'snarkjs') return 'snarkjs'
  return 'proverServer'
}

function proverServerUrl() {
  return (process.env.RAPIDSNARK_SERVER_URL || 'http://127.0.0.1:8080').trim().replace(/\/$/, '')
}

function artifactPaths() {
  const keysRoot = process.env.ZKLOGIN_KEYS_DIR || path.join(__dirname, 'keys')
  const witnessBinPath =
    process.env.WITNESS_BIN || path.join(keysRoot, 'zklogin_myso_cpp', 'zklogin_myso')
  const proverServerBinPath =
    process.env.PROVER_SERVER_BIN || path.join(keysRoot, 'rapidsnark', 'proverServer')
  return {
    zkeyPath: process.env.ZKEY_PATH || path.join(keysRoot, 'zklogin_myso_final.zkey'),
    wasmPath:
      process.env.WASM_PATH || path.join(keysRoot, 'zklogin_myso_js', 'zklogin_myso.wasm'),
    witnessBinPath,
    witnessDatPath: `${witnessBinPath}.dat`,
    proverServerBinPath,
    rapidsnarkLibDir: path.join(keysRoot, 'rapidsnark', 'lib'),
  }
}

function chmodExecutable(label, filePath, { required }) {
  if (!fs.existsSync(filePath)) {
    if (required) {
      console.error(`[zklogin-prover] missing ${label}: ${filePath}`)
      process.exit(1)
    }
    return false
  }
  try {
    fs.chmodSync(filePath, 0o755)
  } catch (err) {
    console.error(`[zklogin-prover] failed to chmod ${label}: ${filePath}`, err.message)
    if (required) process.exit(1)
    return false
  }
  try {
    fs.accessSync(filePath, fs.constants.X_OK)
  } catch {
    console.error(`[zklogin-prover] ${label} is not executable: ${filePath}`)
    if (required) process.exit(1)
    return false
  }
  console.log(`[zklogin-prover] ${label} ok`)
  console.log(`[zklogin-prover] path: ${filePath}`)
  return true
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
  const wEngine = witnessEngine()
  const pEngine = proveEngine()
  const serverUrl = proverServerUrl()

  await verifyHashedArtifact('zkey', paths.zkeyPath, EXPECTED_ZKEY_SHA256)

  if (wEngine === 'cpp' || pEngine === 'proverServer') {
    chmodExecutable('witness-bin', paths.witnessBinPath, { required: true })
    await verifyHashedArtifact('witness-dat', paths.witnessDatPath, EXPECTED_WITNESS_DAT_SHA256)
  } else {
    await verifyHashedArtifact('wasm', paths.wasmPath, EXPECTED_WASM_SHA256)
  }

  // Optional wasm check when cpp/proverServer is primary.
  if ((wEngine === 'cpp' || pEngine === 'proverServer') && fs.existsSync(paths.wasmPath)) {
    const actual = await sha256File(paths.wasmPath)
    if (actual !== EXPECTED_WASM_SHA256) {
      console.warn(`[zklogin-prover] wasm SHA-256 mismatch (ignored; prove engine ${pEngine})`)
      console.warn(`[zklogin-prover] path: ${paths.wasmPath}`)
      console.warn(`[zklogin-prover] expected: ${EXPECTED_WASM_SHA256}`)
      console.warn(`[zklogin-prover] actual:   ${actual}`)
    } else {
      console.log(`[zklogin-prover] wasm ok (optional; prove engine ${pEngine})`)
      console.log(`[zklogin-prover] path: ${paths.wasmPath}`)
      console.log(`[zklogin-prover] sha256: ${actual}`)
    }
  }

  if (pEngine === 'proverServer') {
    chmodExecutable('proverServer-bin', paths.proverServerBinPath, { required: true })
    if (fs.existsSync(paths.rapidsnarkLibDir)) {
      console.log('[zklogin-prover] rapidsnark lib dir ok')
      console.log(`[zklogin-prover] path: ${paths.rapidsnarkLibDir}`)
    } else {
      console.warn(
        `[zklogin-prover] rapidsnark lib dir missing (ok if proverServer is fully static): ${paths.rapidsnarkLibDir}`
      )
    }
  }

  // Legacy CLI binary on volume (not used for prove when PROVE_ENGINE=proverServer).
  const rapidsnarkBin = process.env.RAPIDSNARK_BIN
  if (rapidsnarkBin && fs.existsSync(rapidsnarkBin)) {
    try {
      fs.chmodSync(rapidsnarkBin, 0o755)
      console.log('[zklogin-prover] rapidsnark-bin chmod ok (unused when prove engine is proverServer)')
      console.log(`[zklogin-prover] path: ${rapidsnarkBin}`)
    } catch (err) {
      console.warn(
        `[zklogin-prover] failed to chmod rapidsnark binary: ${rapidsnarkBin}`,
        err.message
      )
    }
  }

  console.log(`[zklogin-prover] witness engine: ${wEngine}`)
  console.log(`[zklogin-prover] prove engine: ${pEngine}`)
  if (pEngine === 'proverServer') {
    console.log(`[zklogin-prover] RAPIDSNARK_SERVER_URL: ${serverUrl} (loopback, same container)`)
    console.log(`[zklogin-prover] PROVER_SERVER_BIN: ${paths.proverServerBinPath}`)
    console.log(`[zklogin-prover] OMP_NUM_THREADS: ${process.env.OMP_NUM_THREADS || '8'}`)
  }

  return {
    ...paths,
    witnessEngine: wEngine,
    proveEngine: pEngine,
    proverServerUrl: serverUrl,
  }
}

module.exports = {
  EXPECTED_WASM_SHA256,
  EXPECTED_WITNESS_DAT_SHA256,
  EXPECTED_ZKEY_SHA256,
  artifactPaths,
  proveEngine,
  proverServerUrl,
  verifyProverArtifacts,
  witnessEngine,
}

if (require.main === module) {
  verifyProverArtifacts().catch((err) => {
    console.error('[zklogin-prover] artifact verification failed', err)
    process.exit(1)
  })
}
