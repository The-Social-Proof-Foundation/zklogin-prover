const crypto = require('crypto')

const MAX_ISS_LEN_B64 = 4 * (1 + Math.floor(165 / 3))
const MAX_HEADER_LEN = 248
const MAX_MESSAGE_LEN = 1408
const ISS_SCAN = 64
const PACK_WIDTH = 248
const RSA_BYTES = 256
const LIMBS = 64
const LIMB_BITS = 32
const LIMB_MASK = (1n << BigInt(LIMB_BITS)) - 1n
const DIGEST_INFO = Buffer.from('3031300d060960864801650304020105000420', 'hex')

function bitsOf(value, width) {
  let current = value
  const little = []
  for (let i = 0; i < width; i += 1) {
    little.push(current & 1n)
    current >>= 1n
  }
  if (current !== 0n) throw new Error('zkLogin input does not fit its bit width')
  little.reverse()
  return little
}

function packBits(bits, outWidth) {
  const chunks = []
  for (let end = bits.length; end > 0; end -= outWidth) {
    chunks.push(bits.slice(Math.max(0, end - outWidth), end))
  }
  chunks.reverse()
  return chunks.map((chunk) => {
    let value = 0n
    for (const bit of chunk) value = (value << 1n) | bit
    return value.toString()
  })
}

function packedFieldElements(values, inWidth) {
  const bits = []
  for (const value of values) bits.push(...bitsOf(value, inWidth))
  const packed = packBits(bits, PACK_WIDTH)
  const expected = Math.ceil((values.length * inWidth) / PACK_WIDTH)
  if (packed.length !== expected) throw new Error('zkLogin packing length mismatch')
  return packed
}

function paddedCharCodes(value, length) {
  const codes = Array.from(value).map((char) => BigInt(char.codePointAt(0)))
  if (codes.some((code) => code > 255n)) throw new Error('zkLogin claim is not a byte string')
  if (codes.length > length) throw new Error('zkLogin claim is longer than the chain allows')
  while (codes.length < length) codes.push(0n)
  return codes
}

function splitExtendedPublicKey(base64Key) {
  const bytes = Buffer.from(base64Key, 'base64')
  const extended = bytes.length === 32 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes
  const first = BigInt(`0x${extended.subarray(0, extended.length - 16).toString('hex') || '0'}`)
  const second = BigInt(`0x${extended.subarray(extended.length - 16).toString('hex') || '0'}`)
  return { eph0: first.toString(), eph1: second.toString() }
}

function decodeBase64Url(value) {
  return Buffer.from(value, 'base64url')
}

function modulusBytes(base64UrlModulus) {
  const raw = decodeBase64Url(base64UrlModulus)
  let start = 0
  while (start < raw.length - 1 && raw[start] === 0) start += 1
  const stripped = raw.subarray(start)
  if (stripped.length > RSA_BYTES) throw new Error('JWK modulus is larger than 2048 bits')
  const bytes = Buffer.alloc(RSA_BYTES)
  stripped.copy(bytes, RSA_BYTES - stripped.length)
  return bytes
}

function exponentValue(base64UrlExponent) {
  const bytes = decodeBase64Url(base64UrlExponent)
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  if (value !== 65537n) throw new Error('JWK exponent must be 65537')
  return value
}

function bytesToBig(bytes) {
  return BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`)
}

function bigToLimbs(value, count = LIMBS) {
  const limbs = []
  let current = value
  for (let i = 0; i < count; i += 1) {
    limbs.push(current & LIMB_MASK)
    current >>= BigInt(LIMB_BITS)
  }
  if (current !== 0n) throw new Error('RSA value does not fit the limb width')
  return limbs
}

function limbsToBig(limbs) {
  let value = 0n
  for (let i = limbs.length - 1; i >= 0; i -= 1) value = (value << BigInt(LIMB_BITS)) | limbs[i]
  return value
}

function schoolbookLimbs(left, right) {
  const columns = Array.from({ length: LIMBS * 2 }, () => 0n)
  for (let i = 0; i < LIMBS; i += 1) {
    for (let j = 0; j < LIMBS; j += 1) columns[i + j] += left[i] * right[j]
  }
  let carry = 0n
  const out = []
  for (let k = 0; k < LIMBS * 2; k += 1) {
    const sum = columns[k] + carry
    out.push(sum & LIMB_MASK)
    carry = sum >> BigInt(LIMB_BITS)
  }
  if (carry !== 0n) throw new Error('RSA product overflowed 4096 bits')
  return out
}

function strictLessBorrow(left, right) {
  const borrow = [0n]
  let carry = 0n
  let different = false
  for (let i = 0; i < LIMBS; i += 1) {
    const need = left[i] + carry
    if (right[i] < need) {
      carry = 1n
      if (right[i] + (1n << BigInt(LIMB_BITS)) - need !== 0n) different = true
    } else {
      carry = 0n
      if (right[i] !== need) different = true
    }
    borrow.push(carry)
  }
  if (carry !== 0n || !different) throw new Error('RSA value is not strictly below the modulus')
  return borrow
}

function modmulWitness(left, right, modulus, modulusLimbs) {
  const product = left * right
  const quotient = product / modulus
  const remainder = product % modulus
  const remainderLimbs = bigToLimbs(remainder)
  const quotientLimbs = bigToLimbs(quotient)
  if (limbsToBig(schoolbookLimbs(bigToLimbs(left), bigToLimbs(right))) !== product) {
    throw new Error('RSA schoolbook product does not match the integer product')
  }
  return {
    q: quotientLimbs.map((limb) => limb.toString()),
    r: remainderLimbs,
    borrow: strictLessBorrow(remainderLimbs, modulusLimbs).map((bit) => bit.toString()),
  }
}

function rsaWitness(signature, modulus) {
  const modulusLimbs = bigToLimbs(modulus)
  strictLessBorrow(bigToLimbs(signature), modulusLimbs)
  let acc = signature % modulus
  const squares = []
  for (let round = 0; round < 16; round += 1) {
    const step = modmulWitness(acc, acc, modulus, modulusLimbs)
    squares.push(step)
    acc = limbsToBig(step.r)
  }
  const finalStep = modmulWitness(acc, signature, modulus, modulusLimbs)
  return {
    sigBorrow: strictLessBorrow(bigToLimbs(signature), modulusLimbs).map((bit) => bit.toString()),
    squareQ: squares.map((step) => step.q),
    squareR: squares.map((step) => step.r.map((limb) => limb.toString())),
    squareBorrow: squares.map((step) => step.borrow),
    finalQ: finalStep.q,
    finalR: finalStep.r.map((limb) => limb.toString()),
    finalBorrow: finalStep.borrow,
    encoded: limbsToBig(finalStep.r),
  }
}

function pkcs1Sha256(hash) {
  const encoded = Buffer.alloc(RSA_BYTES)
  encoded[0] = 0x00
  encoded[1] = 0x01
  const separator = RSA_BYTES - DIGEST_INFO.length - hash.length - 1
  encoded.fill(0xff, 2, separator)
  encoded[separator] = 0x00
  DIGEST_INFO.copy(encoded, separator + 1)
  Buffer.from(hash).copy(encoded, separator + 1 + DIGEST_INFO.length)
  return encoded
}

function decimalBytes(bytes, length) {
  const out = Array.from(bytes, (byte) => byte.toString())
  if (out.length > length) throw new Error('zkLogin byte string is too long')
  while (out.length < length) out.push('0')
  return out
}

function circuitInputsFromRequest(input) {
  const iss = input.issBase64Details
  if (!iss?.value || iss.indexMod4 == null) throw new Error('issBase64Details is required')
  if (!input.headerBase64) throw new Error('headerBase64 is required')
  if (!input.addressSeed) throw new Error('addressSeed is required')
  if (!input.jwtMessage) throw new Error('jwt signing input is required')
  if (!input.jwtSignature) throw new Error('jwt signature is required')
  if (!input.jwkModulus) throw new Error('jwk modulus is required')
  if (!input.jwkExponent) throw new Error('jwk exponent is required')

  const message = Buffer.from(input.jwtMessage, 'utf8')
  if (message.length > MAX_MESSAGE_LEN) throw new Error('JWT signing input is longer than 1408 bytes')
  if (input.headerBase64.length >= message.length || message[input.headerBase64.length] !== 46) {
    throw new Error('JWT header is not the signed prefix')
  }
  const payload = message.subarray(input.headerBase64.length + 1).toString('utf8')
  const issOffset = payload.indexOf(iss.value)
  if (issOffset < 0) throw new Error('Issuer claim is not inside the signed payload')
  if (issOffset % 4 !== Number(iss.indexMod4)) throw new Error('indexMod4 does not match the issuer offset')
  if (iss.value.length > ISS_SCAN) throw new Error('Issuer claim is longer than the circuit can bind')

  const signature = decodeBase64Url(input.jwtSignature)
  if (signature.length !== RSA_BYTES) throw new Error('JWT signature is not 2048 bits')
  const modulus = modulusBytes(input.jwkModulus)
  exponentValue(input.jwkExponent)
  const signatureInt = bytesToBig(signature)
  const modulusInt = bytesToBig(modulus)
  const witness = rsaWitness(signatureInt, modulusInt)
  const hash = crypto.createHash('sha256').update(message).digest()
  if (witness.encoded !== bytesToBig(pkcs1Sha256(hash))) {
    throw new Error('JWT RSA signature does not match the signed header and payload')
  }

  const nBits = message.length * 8
  const nBlocks = Math.floor((nBits + 64) / 512) + 1
  const padRem = (nBits + 64) % 512
  const key = splitExtendedPublicKey(input.extendedEphemeralPublicKey)
  return {
    eph0: key.eph0,
    eph1: key.eph1,
    addrSeed: BigInt(input.addressSeed).toString(),
    maxEpoch: BigInt(input.maxEpoch).toString(),
    indexMod4: BigInt(iss.indexMod4).toString(),
    messageLen: message.length.toString(),
    headerLen: input.headerBase64.length.toString(),
    issOffset: issOffset.toString(),
    issQuot: Math.floor(issOffset / 4).toString(),
    issLen: iss.value.length.toString(),
    nBlocks: nBlocks.toString(),
    padRem: padRem.toString(),
    messageBytes: decimalBytes(message, MAX_MESSAGE_LEN),
    modulusBytes: decimalBytes(modulus, RSA_BYTES),
    signatureBytes: decimalBytes(signature, RSA_BYTES),
    sigBorrow: witness.sigBorrow,
    squareQ: witness.squareQ,
    squareR: witness.squareR,
    squareBorrow: witness.squareBorrow,
    finalQ: witness.finalQ,
    finalR: witness.finalR,
    finalBorrow: witness.finalBorrow,
  }
}

module.exports = {
  ISS_SCAN,
  MAX_HEADER_LEN,
  MAX_ISS_LEN_B64,
  MAX_MESSAGE_LEN,
  circuitInputsFromRequest,
  packedFieldElements,
  paddedCharCodes,
  pkcs1Sha256,
}
