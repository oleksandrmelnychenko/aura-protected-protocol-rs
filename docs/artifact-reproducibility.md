# Aura paper artifact reproducibility

This document is the entry point for reproducing the claims used by the Aura
paper. It is intentionally operational: it names the files, commands, expected
scope, and current gaps.

## Quick start

```sh
./scripts/reproduce-paper-artifact.sh quick
```

The script writes logs under `artifact-output/<timestamp>-<mode>/`. Every run
also writes `MANIFEST.txt` and `SHA256SUMS` in the same directory, including
failed runs where partial logs are useful for diagnosis.

Modes:

| Mode | Command | Scope |
|---|---|---|
| Quick smoke | `./scripts/reproduce-paper-artifact.sh quick` | Fixed vectors, deterministic handshake/envelope/cross-ratchet/multi-epoch KATs, vector dump, attack-PoC regression tests |
| Rust tests | `./scripts/reproduce-paper-artifact.sh test` | Full `cargo test --release` with and without `ffi` |
| Formal models | `./scripts/reproduce-paper-artifact.sh formal` | Tamarin handshake, Tamarin ratchet, ProVerif |
| Paper build | `./scripts/reproduce-paper-artifact.sh paper` | Rebuild English, Ukrainian, and companion proof PDFs with `pdflatex` |
| Reference audit | `./scripts/reproduce-paper-artifact.sh references` | Check bibliography/citation consistency and external URL reachability |
| Benchmarks | `./scripts/reproduce-paper-artifact.sh bench` | Criterion benchmark suite |
| Full artifact | `./scripts/reproduce-paper-artifact.sh full` | Tests, formal models, PDFs, reference audit, benchmarks |

The `formal` mode requires `tamarin-prover` and `proverif`. The `paper` mode
requires `pdflatex`; consequently `full` requires the Rust toolchain,
formal-verification tools, `pdflatex`, `protoc`, `curl`, network access, and
benchmark dependencies. The quick mode only needs the Rust toolchain and
`protoc`. The `references` mode also requires `curl` and network access.

## Fixed paper vectors

The fixed vectors live in:

- `tests/paper_vectors.rs` — regression tests for deterministic vectors.
- `examples/paper_vectors.rs` — prints the same vectors for artifact logs.

Current vectors cover deterministic components, a byte-stable handshake
transcript, the first post-handshake envelope, the first DH+KEM ratchet
boundary, and delayed delivery across multiple ratchet epochs. These vectors are
compiled only with the `test-vectors` feature; production builds continue to use
fresh OS randomness.

| Vector | What it checks |
|---|---|
| HKDF-SHA256 | Stable extract/expand behavior for the ratchet-style info label |
| AES-256-GCM-SIV | Stable encryption/decryption for fixed key, nonce, plaintext, and AAD |
| ML-KEM-768 seeded keygen | Stable public-key length and SHA-256 digest from a fixed seed |
| Master-key identity derivation | Stable Ed25519/X25519 public keys and ML-KEM public-key digests for Alice/Bob |
| Full handshake transcript | Fixed Alice/Bob identities, fixed initiator ephemeral X25519, fixed ML-KEM encapsulation seed, fixed clock, stable `HandshakeInit`, `HandshakeAck`, and session id |
| Post-handshake envelope | Fixed nonce prefix, fixed header nonce, fixed payload, and stable encrypted metadata/payload bytes after the deterministic handshake |
| Cross-ratchet envelope | Fixed ratchet X25519 seed, fixed ratchet ML-KEM keygen seed, fixed ratchet encapsulation seed, fixed post-ratchet nonce/header nonce, and stable ratchet header plus encrypted metadata/payload bytes |
| Multi-epoch delayed delivery | Fixed two-way ratchet bridge, fixed delayed epoch-0 and epoch-1 envelopes, stable `previous_chain_length=2`, and successful delayed decrypt after additional ratchets |

Handshake transcript vector:

| Field | Value |
|---|---|
| `handshake_init_len` | `2485` |
| `handshake_init_sha256` | `dceaef8ef7f38a0c7a4f54e8139aa236eda6339d123a65b79699ad62f56d4151` |
| `handshake_ack_len` | `36` |
| `handshake_ack_sha256` | `5192f0e16fc61f1ea4c38e1737c93feb613075c2447ea711c76b53965bacf265` |
| `handshake_session_id` | `7775055d40940c50c28a6bac2edf50e6` |

Post-handshake envelope vector:

| Field | Value |
|---|---|
| `envelope_len` | `158` |
| `envelope_sha256` | `a32fa29e3cb71093b294e7225aeb6a1a2aaeb54e04b9313166ae5b311e3ea799` |
| `envelope_metadata_sha256` | `ac8130223d5d655159914f9ce920be8c28f8b85d239d1eab2ab0315b38c6b867` |
| `envelope_payload_sha256` | `e142dbef61b3b62e92428585a61c7e79dc38bddec10004e073fff20be4ec801e` |

Cross-ratchet envelope vector:

| Field | Value |
|---|---|
| `cross_ratchet_envelope_len` | `2473` |
| `cross_ratchet_envelope_sha256` | `ee819dc868edce917aa464d82528b5262c3c8a78428ec9552e0dced6442b77e0` |
| `cross_ratchet_header_dh_sha256` | `a1ec4ad5c6a287e156ae4260c1602ffed192df3fd89c7b6376a268289bb7e703` |
| `cross_ratchet_header_kyber_ct_sha256` | `d258ff9e7d83d08aac73ffdf4e8401c16f794e9dec0f8446182f4a38afa2adc6` |
| `cross_ratchet_header_new_kyber_sha256` | `a1b885dbb1a27a0901d6265212a2a18ecae6e80a830cf61224aa4947276b0b3a` |
| `cross_ratchet_metadata_sha256` | `04386aa6b4d2fd60b3524948fc9179151085708da29a6f0e502bd843e38a4e3b` |
| `cross_ratchet_payload_sha256` | `d2a1cdd41eea0c36dad0d49a515385d7f95f196bc94308782f4d0b25b0c43baf` |

Multi-epoch delayed-delivery vector:

| Field | Value |
|---|---|
| `multi_epoch_e0_delayed_len` | `162` |
| `multi_epoch_e0_delayed_sha256` | `25887221bcb8a471b16c59d421513bf8840b63fcd2571b1173fe7f6cdbcac5f1` |
| `multi_epoch_bob_bridge_len` | `2476` |
| `multi_epoch_bob_bridge_sha256` | `dd3cc13ddf463339d192eaa98bc5407e585bb686e0553866f92c2ab2088740c0` |
| `multi_epoch_alice_bridge_len` | `2478` |
| `multi_epoch_alice_bridge_sha256` | `af3744e798eed2c437cee4d2af2275ab4db2a22dff81bb0fcc4a06f3786be95e` |
| `multi_epoch_alice_bridge_previous_chain_length` | `2` |
| `multi_epoch_e1_delayed_len` | `164` |
| `multi_epoch_e1_delayed_sha256` | `5cbb861f4f5a2a78a5682b46fa74eaae70682597c8df178ed4d8652234cf309b` |
| `multi_epoch_bob_second_len` | `2476` |
| `multi_epoch_bob_second_sha256` | `e964ddb54e56986332bb12cd4387bb68f55d51ae7de2acb00f304c6327acb7ac` |

## Claim-to-artifact map

| Paper claim | Files | Reproduction command |
|---|---|---|
| HKDF and AEAD deterministic behavior | `tests/paper_vectors.rs`, `examples/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| Deterministic identity derivation from a master key | `src/identity/identity_keys.rs`, `tests/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| ML-KEM seeded key generation remains stable | `src/crypto/kyber_interop.rs`, `tests/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| Deterministic full-handshake transcript KAT | `src/protocol/handshake.rs`, `src/identity/identity_keys.rs`, `src/crypto/kyber_interop.rs`, `tests/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| Post-handshake envelope KAT | `src/protocol/session.rs`, `tests/paper_vectors.rs`, `examples/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| Cross-ratchet envelope KAT | `src/protocol/session.rs`, `tests/paper_vectors.rs`, `examples/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| Multi-epoch delayed-delivery KAT | `src/protocol/session.rs`, `tests/paper_vectors.rs`, `examples/paper_vectors.rs` | `cargo test --release --features test-vectors --test paper_vectors` |
| Replay rejection, rollback guards, malformed envelope recovery | `tests/attack_poc.rs`, `tests/integration_test.rs` | `cargo test --release --test attack_poc`; full: `cargo test --release` |
| FFI behavior | `src/ffi/api.rs`, `tests/ffi_test.rs`, `tests/ffi_channel_test.rs` | `cargo test --release --features ffi` |
| Tamarin handshake lemmas | `formal/tamarin/aura_handshake.spthy` | `make -C formal handshake` |
| Tamarin ratchet lemmas | `formal/tamarin/aura_ratchet.spthy` | `make -C formal ratchet` |
| ProVerif queries | `formal/proverif/aura.pv` | `make -C formal proverif` |
| Performance numbers | `benches/protocol_bench.rs` | `cargo bench` |
| PQ traffic-profile comparability | `benches/protocol_bench.rs` | `cargo bench --bench protocol_bench pq_traffic_profiles` |
| Ablation and sensitivity ledger | `docs/ablation-study.md` | See commands inside `docs/ablation-study.md` |
| Paper compilation | `docs/aura-paper.tex`, `docs/aura-paper-ua.tex`, `docs/security-proof.tex` | `./scripts/reproduce-paper-artifact.sh paper` |
| Reference validity | `docs/reference-audit.md`, `scripts/audit-paper-references.sh` | `./scripts/reproduce-paper-artifact.sh references` |

## Expected formal-model status

The current formal status is:

| Tool | Expected result |
|---|---|
| Tamarin handshake model | 6/6 lemmas verified |
| Tamarin ratchet model | 4/4 lemmas verified |
| ProVerif model | 4/6 queries proven |

The two unproven ProVerif queries are not treated as machine-checked results.
They remain documented limitations caused by DH equational-theory
overapproximation. Q6 is covered by the Tamarin-style secrecy/PCS models and
game-based proofs; Q5 is carried by the game-based message-security proof and
implementation tests.

## Environment capture

Every script mode writes `versions.txt` with:

- git commit and dirty-worktree summary;
- `rustc`, `cargo`, `protoc`;
- `pdflatex`;
- `tamarin-prover`;
- `proverif`.

For a paper artifact bundle, archive the entire `artifact-output/<timestamp>-full/`
directory together with the git commit hash and verify it from inside the bundle
directory:

```sh
cd artifact-output/<timestamp>-full
sha256sum -c SHA256SUMS
```

## CI artifact bundle

The `Paper Artifact` GitHub Actions workflow runs the quick fixed-vector suite,
rebuilds the English, Ukrainian, and companion proof PDFs, and audits paper
references on pull requests that touch the artifact surface, source code,
formal models, or artifact scripts, on tagged releases, and on manual dispatch.
It uploads the full `artifact-output/**` tree as a reviewable workflow artifact,
including generated PDFs, `versions.txt`, `MANIFEST.txt`, and `SHA256SUMS` for
each mode. GitHub workflow artifacts are retention-limited; durable submission
or release bundles should be archived separately or attached to a tagged
release.

The main CI `Formal Verification` job uses the same artifact script in `formal`
mode after installing Tamarin Prover and ProVerif. It uploads the formal
stdout/stderr logs, tool-version capture, manifest, and checksums on pull
requests, main-branch pushes, and tagged releases, subject to the same workflow
artifact retention window.

## Current submission-hardening gaps

The artifact is now runnable, but the following work would make it stronger:

| Gap | Required work |
|---|---|
| External review | Use `docs/external-review-package.md` to record third-party review of model assumptions and code/proof alignment. |
