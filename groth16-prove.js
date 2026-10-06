const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawn } = require('child_process')
const snarkjs = require('snarkjs')

/**
 * Witness defaults to Circom C++ (zklogin_myso + zklogin_myso.dat).
 * WITNESS_ENGINE=wasm falls back to snarkjs WASM.
 * Rapidsnark (when present) replaces only the Groth16 multiexp step.
 */
function rapidsnarkBinary() {
  if (process.env.PROVE_ENGINE === 'snarkjs') return null
  const candidates = [
    process.env.RAPIDSNARK_BIN,
    path.join(__dirname, 'rapidsnark', 'rapidsnark'),
    '/usr/local/bin/rapidsnark',
  ].filter(Boolean)
  for (const bin of candidates) {
    try {
      fs.accessSync(bin, fs.constants.X_OK)
      return bin
    } catch {
      // try the next location
    }
  }
  return null
}

function resolveWitnessEngine(explicit) {
  if (explicit === 'cpp' || explicit === 'wasm') return explicit
  const raw = (process.env.WITNESS_ENGINE || 'cpp').trim().toLowerCase()
  return raw === 'wasm' ? 'wasm' : 'cpp'
}

/** Circom C++ witness expects JSON numbers/strings; keep nested array shape. */
function circuitInputForCpp(value) {
  if (Array.isArray(value)) {
    return value.map(circuitInputForCpp)
  }
  if (value != null && typeof value === 'object') {
    const out = {}
    for (const [key, v] of Object.entries(value)) {
      out[key] = circuitInputForCpp(v)
    }
    return out
  }
  if (typeof value === 'bigint') return value.toString()
  if (typeof value === 'number') return String(value)
  return value
}

function sampleResources() {
  const mem = process.memoryUsage()
  const cpu = process.cpuUsage()
  return {
    rssMb: Math.round(mem.rss / 1048576),
    heapMb: Math.round(mem.heapUsed / 1048576),
    cpuUserUs: cpu.user,
    cpuSystemUs: cpu.system,
    freeMb: Math.round(os.freemem() / 1048576),
    totalMb: Math.round(os.totalmem() / 1048576),
    cores: os.cpus().length,
  }
}

function phaseLogger(phases) {
  let last = Date.now()
  let name = 'prove-start'
  function mark(msg) {
    const now = Date.now()
    phases.push({ phase: name, ms: now - last })
    last = now
    name = String(msg)
  }
  const logger = {
    debug: mark,
    info: mark,
    warn: mark,
    error: mark,
    log: mark,
  }
  logger.finish = () => mark('prove-end')
  return logger
}

function runChild(bin, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stderr = ''
    let stdout = ''
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })
    child.on('error', reject)
    child.on('close', (code) => {
      if (code !== 0) {
        const detail = (stderr || stdout).slice(-2000)
        reject(new Error(`${path.basename(bin)} exited ${code}: ${detail}`))
        return
      }
      resolve()
    })
  })
}

function runRapidsnark(bin, zkeyPath, wtnsPath, proofPath, publicPath) {
  return runChild(bin, [zkeyPath, wtnsPath, proofPath, publicPath])
}

/**
 * Circom main.cpp loads `${argv[0]}.dat`, so witnessBinPath must be absolute
 * and zklogin_myso.dat must sit beside the binary.
 */
function runCppWitness(witnessBinPath, inputPath, wtnsPath) {
  const bin = path.resolve(witnessBinPath)
  return runChild(bin, [inputPath, wtnsPath])
}

async function proveGroth16({
  input,
  wasmPath,
  zkeyPath,
  witnessBinPath,
  witnessEngine: witnessEngineOpt,
}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zklogin-prove-'))
  const inputPath = path.join(dir, 'input.json')
  const wtnsPath = path.join(dir, 'witness.wtns')
  const proofPath = path.join(dir, 'proof.json')
  const publicPath = path.join(dir, 'public.json')
  const before = sampleResources()
  const phases = []
  let witnessMs = 0
  let proveMs = 0
  let engine = 'snarkjs'
  const witnessEngine = resolveWitnessEngine(witnessEngineOpt)
  const bin = rapidsnarkBinary()

  try {
    const witnessStart = Date.now()
    if (witnessEngine === 'cpp') {
      if (!witnessBinPath) {
        throw new Error('WITNESS_BIN / witnessBinPath is required when WITNESS_ENGINE=cpp')
      }
      fs.writeFileSync(inputPath, JSON.stringify(circuitInputForCpp(input)))
      await runCppWitness(witnessBinPath, inputPath, wtnsPath)
    } else {
      if (!wasmPath) {
        throw new Error('WASM_PATH is required when WITNESS_ENGINE=wasm')
      }
      await snarkjs.wtns.calculate(input, wasmPath, wtnsPath)
    }
    witnessMs = Date.now() - witnessStart
    const afterWitness = sampleResources()

    const proveStart = Date.now()
    let proof
    let publicSignals
    if (bin) {
      engine = 'rapidsnark'
      await runRapidsnark(bin, zkeyPath, wtnsPath, proofPath, publicPath)
      proof = JSON.parse(fs.readFileSync(proofPath, 'utf8'))
      publicSignals = JSON.parse(fs.readFileSync(publicPath, 'utf8'))
    } else {
      const logger = phaseLogger(phases)
      const result = await snarkjs.groth16.prove(zkeyPath, wtnsPath, logger)
      logger.finish()
      proof = result.proof
      publicSignals = result.publicSignals
    }
    proveMs = Date.now() - proveStart
    const afterProve = sampleResources()

    if (!proof || !proof.pi_a || !proof.pi_b || !proof.pi_c) {
      throw new Error(`${engine} returned a proof without pi_a, pi_b, and pi_c`)
    }

    return {
      proof,
      publicSignals,
      profile: {
        witnessMs,
        proveMs,
        engine,
        witnessEngine,
        witnessBin: witnessEngine === 'cpp' ? witnessBinPath : null,
        rapidsnarkBin: bin,
        phases,
        rssMbBefore: before.rssMb,
        rssMbAfterWitness: afterWitness.rssMb,
        rssMbAfterProve: afterProve.rssMb,
        heapMbAfterProve: afterProve.heapMb,
        freeMbAfterProve: afterProve.freeMb,
        totalMb: afterProve.totalMb,
        cores: afterProve.cores,
        cpuUserMs: Math.round((afterProve.cpuUserUs - before.cpuUserUs) / 1000),
        cpuSystemMs: Math.round((afterProve.cpuSystemUs - before.cpuSystemUs) / 1000),
      },
    }
  } catch (err) {
    console.error(
      '[prove-profile] failed',
      JSON.stringify({
        witnessMs,
        proveMs,
        engine,
        witnessEngine,
        witnessBin: witnessBinPath || null,
        rapidsnarkBin: bin,
        rssMb: sampleResources().rssMb,
        error: err.message,
      })
    )
    throw err
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
}

module.exports = { proveGroth16, rapidsnarkBinary, resolveWitnessEngine }
