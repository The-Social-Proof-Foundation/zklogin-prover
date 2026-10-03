#!/bin/sh
# Starts the official mysten/zklogin native prover and prover-fe on this machine.
# Proof requests never leave the container. Zkeys must already match the chain.
set -eu

PORT="${PORT:-4000}"
KEYS_DIR="${ZKLOGIN_KEYS_DIR:-/app/keys}"

verify() {
  file="$1"
  expected="$2"
  if [ ! -f "$file" ]; then
    echo "missing $file" >&2
    return 1
  fi
  actual=$(b2sum "$file" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "$file hash $actual does not match the chain key" >&2
    exit 1
  fi
  echo "verified $file"
}

test_zkey="$KEYS_DIR/zkLogin-test.zkey"
main_zkey="$KEYS_DIR/zkLogin-main.zkey"
test_hash=686e2f5fd969897b1c034d7654799ee2c3952489814e4eaaf3d7e1bb539841047ae8ee5fdcdaca5f4ddd76abb5a8e8eb77b44b693a2ba9d4be57e94292b26ce2
main_hash=060beb961802568ac9ac7f14de0fbcd55e373e8f5ec7cc32189e26fb65700aa4e36f5604f868022c765e634d14ea1cd58bd4d79cef8f3cf9693510696bcbcbce

if [ -f "$test_zkey" ]; then
  verify "$test_zkey" "$test_hash"
fi
if [ -f "$main_zkey" ]; then
  verify "$main_zkey" "$main_hash"
fi
if [ ! -f "$test_zkey" ] && [ ! -f "$main_zkey" ]; then
  echo "Mount zkLogin-test.zkey and/or zkLogin-main.zkey at $KEYS_DIR" >&2
  exit 1
fi

start_native() {
  zkey="$1"
  listen="$2"
  ZKEY="$zkey" WITNESS_BINARIES=/app/binaries /app/run.prover.sh "$listen" &
}

start_fe() {
  prover_port="$1"
  fe_port="$2"
  if [ -x /opt/prover-fe/docker-entrypoint.sh ]; then
    starter=/opt/prover-fe/docker-entrypoint.sh
  elif [ -f /opt/prover-fe/package.json ]; then
    starter="node /opt/prover-fe"
  else
    echo "prover-fe files were not copied into the image" >&2
    exit 1
  fi
  PROVER_URI="http://127.0.0.1:${prover_port}/input" \
  PROVER_TIMEOUT=120 \
  NODE_ENV=production \
  DEBUG=zkLogin:info,jwks \
  $starter "$fe_port" &
}

if [ -f "$test_zkey" ]; then
  ln -sfn "$test_zkey" /tmp/zkLogin-test.zkey
  start_native /tmp/zkLogin-test.zkey 8081
  start_fe 8081 8091
  export PROVER_TEST_URL=http://127.0.0.1:8091/v1
fi
if [ -f "$main_zkey" ]; then
  ln -sfn "$main_zkey" /tmp/zkLogin-main.zkey
  start_native /tmp/zkLogin-main.zkey 8082
  start_fe 8082 8092
  export PROVER_MAIN_URL=http://127.0.0.1:8092/v1
fi

exec node /opt/router/server.js
