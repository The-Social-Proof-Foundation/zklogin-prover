# Railway deploy (hot proverServer + C++ witness)

The Railway image (`Dockerfile.railway`) starts `./entrypoint.sh`, which:

1. Starts **rapidsnark `proverServer`** from the volume (loads the ~1.2GB zkey **once into RAM**).
2. Waits until loopback `:8080` answers.
3. Starts Node `server.js` on `:4000`.

`RAPIDSNARK_SERVER_URL=http://127.0.0.1:8080` is **loopback inside the same container** — not a second Railway service and not an extra bill. Node `POST`s circuit JSON to that local process on each login.

Proving files come from the `keys-storage` volume mounted at `/app/keys`. Volumes mount at container start, not during image build. See [Railway volumes](https://docs.railway.com/guides/volumes).

Give the service enough memory to keep the zkey resident (**≥4GB recommended**).

## Required files

| Path inside the container | SHA-256 / notes |
| --- | --- |
| `/app/keys/zklogin_myso_final.zkey` | `0b892f2a26827ba5cf9fb0ad936596f940d04e5efb7c8f87d23566775865fc2e` |
| `/app/keys/zklogin_myso_cpp/zklogin_myso` | Linux ELF witness binary (executable); Circom `--c` build of `zklogin_myso.circom` |
| `/app/keys/zklogin_myso_cpp/zklogin_myso.dat` | `726dfc955b87009fc96c8bc8e445458f583a5377ac875e97d5b440f21b2ccc36` |
| `/app/keys/rapidsnark/proverServer` | OpenMP `proverServer` binary built on Linux (fullnode) |
| `/app/keys/rapidsnark/lib/*` | Shared libs from `ldd proverServer` not already in the Trixie image (usually `libpistache`) |

Optional (escape hatch `PROVE_ENGINE=snarkjs` + `WITNESS_ENGINE=wasm`):

| Path inside the container | SHA-256 |
| --- | --- |
| `/app/keys/zklogin_myso_js/zklogin_myso.wasm` | `758f63cb747e5fe8db8510de90856d4c6305fcb62e616801cacbe5e237f54e08` |

That zkey SHA is the localnet verifying key in myso-core (`zklogin-integration.mdx` and `crates/myso-types/src/localnet_zklogin_vk.rs`). Do not regenerate the ceremony.

The witness `.dat` SHA is pinned as `EXPECTED_WITNESS_DAT_SHA256` in `verify-prover-artifacts.js`. Circom’s witness binary loads `${argv[0]}.dat`. The entrypoint also creates `/tmp/zklogin_bins/zkLogin[.dat]` symlinks because `proverServer` hardcodes those names.

## Environment

| Variable | Default | Notes |
| --- | --- | --- |
| `PROVE_ENGINE` | `proverServer` | Hot path. Do not use cold CLI spawn. |
| `RAPIDSNARK_SERVER_URL` | `http://127.0.0.1:8080` | Loopback only (same container). |
| `PROVER_SERVER_BIN` | `/app/keys/rapidsnark/proverServer` | Volume path. |
| `OMP_NUM_THREADS` | `8` | Cap below host `os.cpus()` (often 48 on Railway). |
| `WITNESS_ENGINE` | `cpp` | Used by proverServer via `zkLogin` symlink. |
| `ZKLOGIN_KEYS_DIR` | `/app/keys` | Volume mount. |

## Build `proverServer` on fullnode (human)

```bash
cd /opt/rapidsnark
# After ffiasm/field sources are already good for the OpenMP CLI build:
npx task buildPistache
npx task buildProverServer
ldd build/proverServer
# Copy libpistache (and any other non-system .so) next to the binary for upload:
mkdir -p /tmp/zklogin-volume/rapidsnark/lib
cp build/proverServer /tmp/zklogin-volume/rapidsnark/proverServer
# Example — adjust paths from ldd output:
# cp depends/pistache/build/src/libpistache.so* /tmp/zklogin-volume/rapidsnark/lib/
chmod +x /tmp/zklogin-volume/rapidsnark/proverServer
```

Also stage zkey + C++ witness if not already on the volume:

```bash
mkdir -p /tmp/zklogin-volume/zklogin_myso_cpp
cp /path/to/zklogin_myso_final.zkey /tmp/zklogin-volume/zklogin_myso_final.zkey
cp /opt/zklogin-prover/circuits/zklogin_myso_cpp/zklogin_myso /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso
cp /opt/zklogin-prover/circuits/zklogin_myso_cpp/zklogin_myso.dat /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso.dat
chmod +x /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso
shasum -a 256 /tmp/zklogin-volume/zklogin_myso_final.zkey
shasum -a 256 /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso.dat
```

## Seed the volume

`railway run` does not mount the production volume. Use the volume file CLI:

```bash
railway link   # zklogin-prover service that owns keys-storage
railway volume files upload /tmp/zklogin-volume/zklogin_myso_final.zkey /zklogin_myso_final.zkey
railway volume files upload /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso /zklogin_myso_cpp/zklogin_myso
railway volume files upload /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso.dat /zklogin_myso_cpp/zklogin_myso.dat
railway volume files upload /tmp/zklogin-volume/rapidsnark/proverServer /rapidsnark/proverServer
# upload each lib under /rapidsnark/lib/...
railway volume files list /rapidsnark
railway volume files list /zklogin_myso_cpp
```

Paths after `upload` are relative to the volume root. With mount `/app/keys`, `/rapidsnark/proverServer` is `/app/keys/rapidsnark/proverServer` in the container.

Restart / redeploy after upload so entrypoint can chmod and start `proverServer`.

## Confirm it worked

Deploy logs should show:

1. `entrypoint: starting proverServer…` then `proverServer ready on :8080`
2. Artifact checks including `proverServer-bin ok`, `prove engine: proverServer`, `RAPIDSNARK_SERVER_URL: http://127.0.0.1:8080`
3. `zkLogin proving server running on port 4000`

A successful prove logs `[prove-profile]` with `"engine":"proverServer"`. Boot may be slow once (zkey load); each login should be much faster than ~50s cold CLI.

`GET /health` returns only:

```json
{ "status": "ok", "artifactsVerified": true }
```

`healthcheckTimeout` is 300s so Railway can wait through cold zkey load at boot.

## Deploy the image

`railway.toml` builds `Dockerfile.railway` and starts `./entrypoint.sh`.

After a green startup log, sign out and sign in again in the frontend so IndexedDB does not keep a proof from an older prover.
