const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawn } = require('child_process')
const snarkjs = require('snarkjs')

/**
 * Default: hot rapidsnark proverServer on loopback (same container).
 * PROVE_ENGINE=snarkjs uses local WASM witness + snarkjs Groth16 (dev escape only).
 * No cold CLI rapidsnark spawn — that remaps the 1.2GB zkey every prove.
 */

function resolveProveEngine() {
  const raw = (process.env.PROVE_ENGINE || 'proverServer').trim().toLowerCase()
  if (raw === 'snarkjs') return 'snarkjs'
  return 'proverServer'
}

function resolveProverServerUrl() {
  const url = (process.env.RAPIDSNARK_SERVER_URL || 'http://127.0.0.1:8080').trim()
  return url.replace(/\/$/, '')
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

/**
 * Circom main.cpp loads `${argv[0]}.dat`, so witnessBinPath must be absolute
 * and zklogin_myso.dat must sit beside the binary.
 */
function runCppWitness(witnessBinPath, inputPath, wtnsPath) {
  const bin = path.resolve(witnessBinPath)
  return runChild(bin, [inputPath, wtnsPath])
}

async function proveViaProverServer(input, serverUrl) {
  const body = JSON.stringify(circuitInputForCpp(input))
  const res = await fetch(`${serverUrl}/input`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  })
  const text = await res.text()
  if (!res.ok) {
    throw new Error(`proverServer ${res.status}: ${text.slice(0, 2000)}`)
  }
  let proof
  try {
    proof = JSON.parse(text)
  } catch {
    throw new Error(`proverServer returned non-JSON: ${text.slice(0, 500)}`)
  }
  if (!proof || !proof.pi_a || !proof.pi_b || !proof.pi_c) {
    throw new Error('proverServer returned a proof without pi_a, pi_b, and pi_c')
  }
  return proof
}

async function proveGroth16({
  input,
  wasmPath,
  zkeyPath,
  witnessBinPath,
  witnessEngine: witnessEngineOpt,
}) {
  const before = sampleResources()
  const phases = []
  let witnessMs = 0
  let proveMs = 0
  const engine = resolveProveEngine()
  const witnessEngine = resolveWitnessEngine(witnessEngineOpt)
  const serverUrl = resolveProverServerUrl()

  try {
    if (engine === 'proverServer') {
      // Witness + Groth16 run inside the hot process (zkey already resident).
      const proveStart = Date.now()
      const proof = await proveViaProverServer(input, serverUrl)
      proveMs = Date.now() - proveStart
      const afterProve = sampleResources()
      return {
        proof,
        publicSignals: [],
        profile: {
          witnessMs: 0,
          proveMs,
          engine: 'proverServer',
          witnessEngine: 'cpp',
          witnessBin: null,
          proverServerUrl: serverUrl,
          phases,
          rssMbBefore: before.rssMb,
          rssMbAfterWitness: before.rssMb,
          rssMbAfterProve: afterProve.rssMb,
          heapMbAfterProve: afterProve.heapMb,
          freeMbAfterProve: afterProve.freeMb,
          totalMb: afterProve.totalMb,
          cores: afterProve.cores,
          cpuUserMs: Math.round((afterProve.cpuUserUs - before.cpuUserUs) / 1000),
          cpuSystemMs: Math.round((afterProve.cpuSystemUs - before.cpuSystemUs) / 1000),
        },
      }
    }

    // PROVE_ENGINE=snarkjs — local escape hatch only (cold zkey in Node).
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zklogin-prove-'))
    const inputPath = path.join(dir, 'input.json')
    const wtnsPath = path.join(dir, 'witness.wtns')
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
      const logger = phaseLogger(phases)
      const result = await snarkjs.groth16.prove(zkeyPath, wtnsPath, logger)
      logger.finish()
      proveMs = Date.now() - proveStart
      const afterProve = sampleResources()

      if (!result.proof || !result.proof.pi_a || !result.proof.pi_b || !result.proof.pi_c) {
        throw new Error('snarkjs returned a proof without pi_a, pi_b, and pi_c')
      }

      return {
        proof: result.proof,
        publicSignals: result.publicSignals,
        profile: {
          witnessMs,
          proveMs,
          engine: 'snarkjs',
          witnessEngine,
          witnessBin: witnessEngine === 'cpp' ? witnessBinPath : null,
          proverServerUrl: null,
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
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
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
        proverServerUrl: engine === 'proverServer' ? serverUrl : null,
        rssMb: sampleResources().rssMb,
        error: err.message,
      })
    )
    throw err
  }
}

module.exports = {
  proveGroth16,
  resolveProveEngine,
  resolveProverServerUrl,
  resolveWitnessEngine,
  circuitInputForCpp,
}
