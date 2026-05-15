# Aura paper artifact reproducibility

This document is the entry point for reproducing the claims used by the Aura
paper. It is intentionally operational: it names the files, commands, expected
scope, and current gaps.

## Quick start

```sh
./scripts/reproduce-paper-artifact.sh quick
```

The script writes logs under `artifact-output/<timestamp>-<mode>/`.

Modes:

| Mode | Command | Scope |
|---|---|---|
| Quick smoke | `./scripts/reproduce-paper-artifact.sh quick` | Fixed vectors, deterministic handshake transcript KAT, vector dump, attack-PoC regression tests |
| Rust tests | `./scripts/reproduce-paper-artifact.sh test` | Full `cargo test --release` with and without `ffi` |
| Formal models | `./scripts/reproduce-paper-artifact.sh formal` | Tamarin handshake, Tamarin ratchet, ProVerif |
| Paper build | `./scripts/reproduce-paper-artifact.sh paper` | Rebuild English and Ukrainian PDFs with `pdflatex` |
| Benchmarks | `./scripts/reproduce-paper-artifact.sh bench` | Criterion benchmark suite |
| Full artifact | `./scripts/reproduce-paper-artifact.sh full` | Tests, formal models, PDFs, benchmarks |

The `formal` and `full` modes require `tamarin-prover`, `proverif`, and
`pdflatex` to be installed. The quick mode only needs the Rust toolchain and
`protoc`.

## Fixed paper vectors

The fixed vectors live in:

- `tests/paper_vectors.rs` — regression tests for deterministic vectors.
- `examples/paper_vectors.rs` — prints the same vectors for artifact logs.

Current vectors cover deterministic components and a byte-stable handshake
transcript. The handshake vector is compiled only with the `test-vectors`
feature; production builds continue to use fresh OS randomness.

| Vector | What it checks |
|---|---|
| HKDF-SHA256 | Stable extract/expand behavior for the ratchet-style info label |
| AES-256-GCM-SIV | Stable encryption/decryption for fixed key, nonce, plaintext, and AAD |
| ML-KEM-768 seeded keygen | Stable public-key length and SHA-256 digest from a fixed seed |
| Master-key identity derivation | Stable Ed25519/X25519 public keys and ML-KEM public-key digests for Alice/Bob |
| Full handshake transcript | Fixed Alice/Bob identities, fixed initiator ephemeral X25519, fixed ML-KEM encapsulation seed, fixed clock, stable `HandshakeInit`, `HandshakeAck`, and session id |

Handshake transcript vector:

| Field | Value |
|---|---|
| `handshake_init_len` | `2485` |
| `handshake_init_sha256` | `dceaef8ef7f38a0c7a4f54e8139aa236eda6339d123a65b79699ad62f56d4151` |
| `handshake_ack_len` | `36` |
| `handshake_ack_sha256` | `5192f0e16fc61f1ea4c38e1737c93feb613075c2447ea711c76b53965bacf265` |
| `handshake_session_id` | `7775055d40940c50c28a6bac2edf50e6` |

## Claim-to-artifact map

| Paper claim | Files | Reproduction command |
|---|---|---|
| HKDF and AEAD deterministic behavior | `tests/paper_vectors.rs`, `examples/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| Deterministic identity derivation from a master key | `src/identity/identity_keys.rs`, `tests/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| ML-KEM seeded key generation remains stable | `src/crypto/kyber_interop.rs`, `tests/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| Deterministic full-handshake transcript KAT | `src/protocol/handshake.rs`, `src/identity/identity_keys.rs`, `src/crypto/kyber_interop.rs`, `tests/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| Replay rejection, rollback guards, malformed envelope recovery | `tests/attack_poc.rs`, `tests/integration_test.rs` | `cargo test --release --test attack_poc`; full: `cargo test --release` |
| FFI behavior | `src/ffi/api.rs`, `tests/ffi_test.rs`, `tests/ffi_channel_test.rs` | `cargo test --release --features ffi` |
| Tamarin handshake lemmas | `formal/tamarin/aura_handshake.spthy` | `make -C formal handshake` |
| Tamarin ratchet lemmas | `formal/tamarin/aura_ratchet.spthy` | `make -C formal ratchet` |
| ProVerif queries | `formal/proverif/aura.pv` | `make -C formal proverif` |
| Performance numbers | `benches/protocol_bench.rs` | `cargo bench` |
| Paper compilation | `docs/aura-paper.tex`, `docs/aura-paper-ua.tex` | `./scripts/reproduce-paper-artifact.sh paper` |
| Reference validity | `docs/reference-audit.md` | See commands inside `docs/reference-audit.md` |

## Expected formal-model status

The current formal status is:

| Tool | Expected result |
|---|---|
| Tamarin handshake model | 6/6 lemmas verified |
| Tamarin ratchet model | 4/4 lemmas verified |
| ProVerif model | 4/6 queries proven |

The two unproven ProVerif queries are not treated as machine-checked results.
They remain documented limitations caused by DH equational-theory
overapproximation; the corresponding claims are carried by the game-based proof
and Tamarin models.

## Environment capture

Every script mode writes `versions.txt` with:

- git commit and dirty-worktree summary;
- `rustc`, `cargo`, `protoc`;
- `pdflatex`;
- `tamarin-prover`;
- `proverif`.

For a paper artifact bundle, archive the entire `artifact-output/<timestamp>-full/`
directory together with the git commit hash.

## Current gaps before top-tier submission

The artifact is now runnable, but the following work would make it stronger:

| Gap | Required work |
|---|---|
| Post-handshake envelope KATs | Add byte-stable encrypt/decrypt vectors after the deterministic handshake without weakening production nonce generation. |
| Benchmark comparability | Add explicit benchmark groups for handshake-only PQ, sparse/periodic PQ, and per-ratchet-boundary PQ under the same traffic model. |
| Formal output archive | Store Tamarin/ProVerif stdout logs from a known toolchain in release artifacts. |
| CI artifact bundle | Upload `artifact-output` logs from GitHub Actions for tagged releases. |
| External review | Record third-party review of model assumptions and code/proof alignment. |
