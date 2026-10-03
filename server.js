/**
 * Local /prove adapter. It only forwards to the native prover-fe on 127.0.0.1.
 * It does not call prover.mystenlabs.com or prover-dev.mystenlabs.com.
 */
const http = require('http')

const PORT = Number(process.env.PORT || 4000)
const TEST_URL = process.env.PROVER_TEST_URL || ''
const MAIN_URL = process.env.PROVER_MAIN_URL || ''

function assertLocal(url) {
  const host = new URL(url).hostname
  if (host !== '127.0.0.1' && host !== 'localhost') {
    throw new Error('Refusing to send a proof request off this host.')
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

function send(res, status, body) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body)
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(payload)
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    send(res, 200, {
      status: 'healthy',
      localnet: Boolean(TEST_URL),
      testnet: Boolean(MAIN_URL),
    })
    return
  }

  if (req.method !== 'POST' || (req.url !== '/prove' && req.url !== '/v1')) {
    send(res, 404, { error: 'Not found' })
    return
  }

  try {
    const body = JSON.parse(await readBody(req))
    const target = body.network === 'localnet' ? TEST_URL : body.network === 'testnet' || body.network === 'mainnet' ? MAIN_URL : ''
    if (!target) {
      send(res, 400, { error: 'network must be localnet, testnet, or mainnet, and that zkey must be mounted.' })
      return
    }
    assertLocal(target)
    const { network: _network, ...proofRequest } = body
    const response = await fetch(target, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(proofRequest),
    })
    send(res, response.status, await response.text())
  } catch (error) {
    send(res, 502, { error: error instanceof Error ? error.message : 'zkLogin prover request failed.' })
  }
})

server.listen(PORT, () => {
  console.log(`self-hosted zkLogin /prove listening on ${PORT}`)
})
