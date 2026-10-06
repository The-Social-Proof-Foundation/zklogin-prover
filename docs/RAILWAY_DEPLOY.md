# Railway deploy (prebuilt zkey + C++ witness)

The Railway image (`Dockerfile.railway`) does not run a Groth16 trusted setup. It only installs Node dependencies and starts `server.js`. Proving files come from the `keys-storage` volume mounted at `/app/keys`.

Volumes are mounted when the container starts, not during the image build. See [Railway volumes](https://docs.railway.com/guides/volumes).

## Required files

| Path inside the container | SHA-256 / notes |
| --- | --- |
| `/app/keys/zklogin_myso_final.zkey` | `0b892f2a26827ba5cf9fb0ad936596f940d04e5efb7c8f87d23566775865fc2e` |
| `/app/keys/zklogin_myso_cpp/zklogin_myso` | Linux ELF witness binary (executable); Circom `--c` build of `zklogin_myso.circom` |
| `/app/keys/zklogin_myso_cpp/zklogin_myso.dat` | `726dfc955b87009fc96c8bc8e445458f583a5377ac875e97d5b440f21b2ccc36` |

Optional (escape hatch `WITNESS_ENGINE=wasm`):

| Path inside the container | SHA-256 |
| --- | --- |
| `/app/keys/zklogin_myso_js/zklogin_myso.wasm` | `758f63cb747e5fe8db8510de90856d4c6305fcb62e616801cacbe5e237f54e08` |

That zkey SHA is the localnet verifying key in myso-core (`zklogin-integration.mdx` and `crates/myso-types/src/localnet_zklogin_vk.rs`). Do not regenerate the ceremony.

The witness `.dat` SHA is pinned as `EXPECTED_WITNESS_DAT_SHA256` in `verify-prover-artifacts.js` (from `circuits/zklogin_myso_cpp/zklogin_myso.dat`). Circom’s witness binary loads `${argv[0]}.dat`, so the binary and `.dat` must share the same basename and directory.

Default witness engine is C++ (`WITNESS_ENGINE=cpp`). Set `WITNESS_ENGINE=wasm` to use snarkjs WASM instead. Override the binary with `WITNESS_BIN` if needed.

If you change the circuit, recompile with `./build-production.sh` (reuses `keys/zklogin_myso_final.zkey` when present), rebuild the Circom C++ witness (`circom zklogin_myso.circom --c` then `make` in `zklogin_myso_cpp`), hash the new `.dat`, and update `EXPECTED_WITNESS_DAT_SHA256`. Do not generate a new zkey.

## Prepare the files locally

```bash
# keys/zklogin_myso_final.zkey must already exist (the finalized key).
# Witness binary + .dat come from circuits/zklogin_myso_cpp/ (Linux build).
shasum -a 256 keys/zklogin_myso_final.zkey
shasum -a 256 circuits/zklogin_myso_cpp/zklogin_myso.dat
mkdir -p /tmp/zklogin-volume/zklogin_myso_cpp
cp keys/zklogin_myso_final.zkey /tmp/zklogin-volume/zklogin_myso_final.zkey
cp circuits/zklogin_myso_cpp/zklogin_myso /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso
cp circuits/zklogin_myso_cpp/zklogin_myso.dat /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso.dat
chmod +x /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso
```

Local check (does not talk to Railway):

```bash
ZKLOGIN_KEYS_DIR=/tmp/zklogin-volume \
node verify-prover-artifacts.js
```

## Seed the volume

`railway run` is not a seed path. It starts a local process with Railway environment variables. It does not mount the production volume at `/app/keys`.

Railway's documented way to write files onto an attached volume is the volume file CLI ([volumes guide](https://docs.railway.com/guides/volumes)):

```bash
railway link   # select the zklogin-prover service that owns keys-storage
railway volume files upload /tmp/zklogin-volume/zklogin_myso_final.zkey /zklogin_myso_final.zkey
railway volume files upload /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso /zklogin_myso_cpp/zklogin_myso
railway volume files upload /tmp/zklogin-volume/zklogin_myso_cpp/zklogin_myso.dat /zklogin_myso_cpp/zklogin_myso.dat
railway volume files list /
railway volume files list /zklogin_myso_cpp
```

Paths after `upload` are relative to the volume root. With mount `/app/keys`, `/zklogin_myso_cpp/zklogin_myso` is `/app/keys/zklogin_myso_cpp/zklogin_myso` inside the container.

Do not invent `scp`, `railway run cp`, or build-time `COPY` of the zkey/witness — `*.zkey`, `*.wasm`, and the compiled witness binary are gitignored, and the volume is not mounted during image build.

Restart the service after the upload so startup reads the new files.

## Confirm it worked

Read the **deploy logs of the running service** (last successful deployment, not a failed build). Startup must print zkey + witness-bin + witness-dat checks (and `witness engine: cpp`), then listen.

A successful prove logs `[prove-profile]` with `"witnessEngine":"cpp"`.

`GET /health` returns only:

```json
{ "status": "ok", "artifactsVerified": true }
```

It does not include paths or hashes. If the SHA does not match, the process exits before `app.listen`. Railway then shows a crash loop; the mismatch (path, expected SHA, actual SHA) is in the logs.

A failed image build does not replace the previous online deployment. Check which deployment is actually serving traffic.

## Deploy the image

`railway.toml` builds `Dockerfile.railway`. That image installs production `dependencies` only (`express`, `cors`, `axios`, `snarkjs`). `circomlib` stays a devDependency and is not required at runtime.

After a successful deploy and a green startup log, sign out and sign in again in the frontend so IndexedDB does not keep a proof from an older prover.
