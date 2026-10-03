#!/bin/sh
set -eu

test_hash=686e2f5fd969897b1c034d7654799ee2c3952489814e4eaaf3d7e1bb539841047ae8ee5fdcdaca5f4ddd76abb5a8e8eb77b44b693a2ba9d4be57e94292b26ce2
main_hash=060beb961802568ac9ac7f14de0fbcd55e373e8f5ec7cc32189e26fb65700aa4e36f5604f868022c765e634d14ea1cd58bd4d79cef8f3cf9693510696bcbcbce

check() {
  file=$1
  expected=$2
  if [ ! -f "$file" ]; then
    echo "missing $file" >&2
    exit 1
  fi
  actual=$(b2sum "$file" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "$file hash $actual does not match $expected" >&2
    exit 1
  fi
  echo "$file ok"
}

check "${1:-keys}/zkLogin-test.zkey" "$test_hash"
check "${1:-keys}/zkLogin-main.zkey" "$main_hash"
