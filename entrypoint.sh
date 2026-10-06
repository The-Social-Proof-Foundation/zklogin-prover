#!/bin/sh
# Start hot rapidsnark proverServer (zkey loaded once into RAM), then Node.
# RAPIDSNARK_SERVER_URL is loopback inside this same container — not a second Railway service.
set -eu

KEYS_DIR="${ZKLOGIN_KEYS_DIR:-/app/keys}"
ZKEY_PATH="${ZKEY_PATH:-${KEYS_DIR}/zklogin_myso_final.zkey}"
WITNESS_BIN="${WITNESS_BIN:-${KEYS_DIR}/zklogin_myso_cpp/zklogin_myso}"
WITNESS_DAT="${WITNESS_BIN}.dat"
PROVER_SERVER_BIN="${PROVER_SERVER_BIN:-${KEYS_DIR}/rapidsnark/proverServer}"
WITNESS_LINK_DIR="${WITNESS_LINK_DIR:-/tmp/zklogin_bins}"
OMP_NUM_THREADS="${OMP_NUM_THREADS:-8}"
RAPIDSNARK_SERVER_URL="${RAPIDSNARK_SERVER_URL:-http://127.0.0.1:8080}"
PROVER_SERVER_WAIT_SEC="${PROVER_SERVER_WAIT_SEC:-180}"
LD_LIBRARY_PATH="${KEYS_DIR}/rapidsnark/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

export OMP_NUM_THREADS
export LD_LIBRARY_PATH
export ZKEY="${ZKEY_PATH}"
export WITNESS_BINARIES="${WITNESS_LINK_DIR}"
export RAPIDSNARK_SERVER_URL
export PROVER_SERVER_BIN
export ZKLOGIN_KEYS_DIR="${KEYS_DIR}"
export ZKEY_PATH
export WITNESS_BIN
export PROVE_ENGINE="${PROVE_ENGINE:-proverServer}"

echo "[zklogin-prover] entrypoint: OMP_NUM_THREADS=${OMP_NUM_THREADS}"
echo "[zklogin-prover] entrypoint: RAPIDSNARK_SERVER_URL=${RAPIDSNARK_SERVER_URL} (loopback, same container)"
echo "[zklogin-prover] entrypoint: PROVER_SERVER_BIN=${PROVER_SERVER_BIN}"
echo "[zklogin-prover] entrypoint: LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"

if [ ! -f "${PROVER_SERVER_BIN}" ]; then
  echo "[zklogin-prover] missing proverServer binary: ${PROVER_SERVER_BIN}" >&2
  exit 1
fi
if [ ! -f "${ZKEY_PATH}" ]; then
  echo "[zklogin-prover] missing zkey: ${ZKEY_PATH}" >&2
  exit 1
fi
if [ ! -f "${WITNESS_BIN}" ] || [ ! -f "${WITNESS_DAT}" ]; then
  echo "[zklogin-prover] missing C++ witness bin/dat under ${WITNESS_BIN}" >&2
  exit 1
fi

chmod 755 "${PROVER_SERVER_BIN}" "${WITNESS_BIN}" 2>/dev/null || true

# singleprover.cpp hardcodes WITNESS_BINARIES/zkLogin[+ .dat]
mkdir -p "${WITNESS_LINK_DIR}"
ln -sfn "${WITNESS_BIN}" "${WITNESS_LINK_DIR}/zkLogin"
ln -sfn "${WITNESS_DAT}" "${WITNESS_LINK_DIR}/zkLogin.dat"
echo "[zklogin-prover] entrypoint: witness links -> ${WITNESS_LINK_DIR}/zkLogin(.dat)"

echo "[zklogin-prover] entrypoint: starting proverServer (loads zkey once; boot may take a while)..."
"${PROVER_SERVER_BIN}" &
PROVER_SERVER_PID=$!

i=0
while [ "${i}" -lt "${PROVER_SERVER_WAIT_SEC}" ]; do
  if ! kill -0 "${PROVER_SERVER_PID}" 2>/dev/null; then
    echo "[zklogin-prover] proverServer exited before becoming ready (pid ${PROVER_SERVER_PID})" >&2
    exit 1
  fi
  # Any HTTP response means listen() ran after SingleProver ctor (zkey is hot).
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -X POST "http://127.0.0.1:8080/input" \
    -H "Content-Type: application/json" \
    -d '{}' || true)
  if [ -n "${code}" ] && [ "${code}" != "000" ]; then
    echo "[zklogin-prover] entrypoint: proverServer ready on :8080 (http ${code}) after ${i}s"
    exec node server.js
  fi
  i=$((i + 1))
  sleep 1
done

echo "[zklogin-prover] proverServer did not become ready within ${PROVER_SERVER_WAIT_SEC}s" >&2
kill "${PROVER_SERVER_PID}" 2>/dev/null || true
exit 1
