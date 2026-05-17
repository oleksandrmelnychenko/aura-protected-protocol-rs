# Aura Protected Protocol

[![CI](https://github.com/oleksandrmelnychenko/aura-protected-protocol-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/oleksandrmelnychenko/aura-protected-protocol-rs/actions/workflows/ci.yml)
[![Security Scan](https://github.com/oleksandrmelnychenko/aura-protected-protocol-rs/actions/workflows/security-scan.yml/badge.svg)](https://github.com/oleksandrmelnychenko/aura-protected-protocol-rs/actions/workflows/security-scan.yml)
[![Benchmarks](https://github.com/oleksandrmelnychenko/aura-protected-protocol-rs/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/oleksandrmelnychenko/aura-protected-protocol-rs/actions/workflows/benchmarks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Hybrid post-quantum secure messaging protocol combining **X25519 + ML-KEM-768** with a Double Ratchet, **AES-256-GCM-SIV**, and per-epoch metadata encryption. The crate also includes MLS-inspired group messaging modules with hybrid PQ TreeKEM, Shield mode, sealed messages, disappearing messages, and message franking; the paper proofs cover the 1:1 handshake and ratchet scope. Some Rust/FFI identifiers still use the historical `kyber` name for compatibility, but the implemented KEM is ML-KEM-768 via the `ml-kem` crate.

## Key Differentiators

| Feature | Signal X3DH | Signal PQXDH | **Aura** |
|---------|------------|-------------|--------------|
| Per-ratchet PQ protection | No | No | **Yes** (X25519 + ML-KEM-768) |
| Metadata encryption | Sealed Sender | Sealed Sender | **Per-epoch rotating key** |
| AEAD | AES-256-CBC + HMAC | AES-256-CBC + HMAC | **AES-256-GCM-SIV** (nonce-misuse resistant) |
| Post-compromise recovery | 1-step (DH) | 1-step (DH) | **1-step classical / 2-step hybrid** |
| Group module | N/A | N/A | **MLS-inspired hybrid PQ TreeKEM** (outside 1:1 proof scope) |
| Shield mode | No | No | **Yes** (enhanced key schedule, mandatory franking) |
| Message features | Basic | Basic | **Sealed, disappearing, frankable, edit, delete** |
| Formal proofs | eCK sketch | High-level | **6 theorems + 10 Tamarin lemmas** (1:1 handshake/ratchet) |

## Architecture

```
1:1 Messaging                         Group Messaging (MLS-inspired)
┌─────────────────────────┐           ┌──────────────────────────────────────┐
│ Handshake (Hybrid X3DH) │           │ TreeKEM (Hybrid PQ)                  │
│  4x X25519 DH            │           │  Left-balanced binary tree            │
│  1x ML-KEM-768 KEM        │           │  X25519 + ML-KEM-768 per node         │
│  HKDF-SHA256 combiner     │           │  parent_hash chain verification       │
│  HMAC key confirmation    │           │                                       │
│  Ed25519 SPK signature    │           │ Sender Keys                           │
└───────────┬───────────────┘           │  Per-member symmetric hash ratchet    │
            v                           │  O(1) encrypt/decrypt                 │
┌─────────────────────────┐           │                                       │
│ Session (Hybrid Ratchet) │           │ Epoch Advancement                     │
│  Per-direction ratchet:   │           │  Commit + Welcome                     │
│    X25519 DH + ML-KEM KEM │           │  External Join                        │
│  Chain KDF: HKDF-SHA256   │           │  PSK injection                        │
│  AEAD: AES-256-GCM-SIV   │           │  ReInit proposals                     │
│  Metadata: independent    │           └──────────────────────────────────────┘
│    AEAD layer             │
└─────────────────────────┘           Message Features (1:1 + Group)
                                       ┌──────────────────────────────────────┐
Shield Mode                            │ Sealed messages (anonymous sender)    │
┌─────────────────────────┐           │ Disappearing messages (TTL at proto)  │
│ Enhanced 2-pass KDF       │           │ Message franking (abuse reporting)    │
│ Mandatory franking        │           │ Edit / Delete messages                │
│ Block external join       │           │ Padding (ISO/IEC 7816-4, 64B blocks) │
│ Configurable limits       │           └──────────────────────────────────────┘
└─────────────────────────┘
```

## Shield Mode

Shield mode is an enhanced security policy for group sessions that enables stricter cryptographic guarantees:

| Parameter | Default | Shield |
|-----------|---------|--------|
| Enhanced key schedule (2-pass KDF) | Off | **On** |
| Mandatory franking | Off | **On** |
| Block external join | Off | **On** |
| Max messages per epoch | 1000 | 1000 |
| Effective max skipped keys per sender | 32 | 4 |

The implementation keeps a broader global skipped-key hard cap of 256 entries.

```swift
// Swift — create a shielded group
let group = try AuraGroupSession.createShielded(identity: identity, credential: cred)

// Or with custom policy
let policy = AuraGroupSecurityPolicy(
    maxMessagesPerEpoch: 500,
    blockExternalJoin: true,
    enhancedKeySchedule: true,
    mandatoryFranking: true
)
let group = try AuraGroupSession.create(identity: identity, credential: cred, policy: policy)
```

```rust
// Rust — create a shielded group
let group = AuraProtocol::group_create_shielded(&identity, &credential)?;

// Query shield status
let is_shielded = group.is_shielded();
let policy = group.security_policy();
```

## Security Properties

### 1:1 Session Properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-256-GCM-SIV with per-message keys |
| Authenticity | HMAC-SHA256 key confirmation + Ed25519 signatures |
| Forward secrecy | Classical FS from erased DH ephemerals and ratcheted chain keys; initial KEM is HNDL only unless its secret key remains undisclosed |
| Post-compromise security | 1-step classical PCS; 2-step hybrid PCS under the conservative both-endpoint compromise model |
| Replay protection | Bounded nonce cache (2048 entries) + monotonic counters |
| Metadata privacy | Envelope metadata encrypted with rotating per-epoch key |
| State integrity | HMAC-SHA256 anti-rollback over serialized state |
| Nonce-misuse resistance | AES-256-GCM-SIV degrades gracefully on nonce reuse |
| DoS guardrails | Hard limits on protobuf/envelope/plaintext sizes + handshake cache/bundle caps |
| Media attachments | Envelope encryption for large files; relay/storage sees ciphertext only |

**Operational hardening limits (current defaults):**

- `MAX_PROTOBUF_MESSAGE_SIZE`: 1 MiB
- `MAX_ENVELOPE_MESSAGE_SIZE`: 1 MiB
- `MAX_BUFFER_SIZE`: 10 MiB
- `MAX_ONE_TIME_PRE_KEYS_PER_BUNDLE`: 4096
- `MAX_INFLIGHT_HANDSHAKE_INITS`: 4096

For deployment guidance, see `SECURITY.md`, `docs/client-production-checklist.md`, and `docs/server-production-checklist.md`.

### Group Protocol Properties

These are implementation-level properties of the group module. They are not claimed as consequences of the paper's two-party theorems; a group-security claim requires a separate TreeKEM model, proof-to-code map, and concurrency analysis.

| Property | Mechanism |
|----------|-----------|
| Group forward secrecy | Epoch advancement via Commit; old epoch keys erased |
| Group post-compromise security | TreeKEM UpdatePath re-encrypts path with fresh X25519 + ML-KEM-768 |
| Sender authentication | Sender keys bound to leaf index; per-member symmetric ratchet |
| Tree integrity | parent_hash chain from root to leaf verified on each UpdatePath |
| External join security | KEM to deterministic external keys derived from init_secret |
| Anonymous sending | Sealed messages with derived seal_key hide sender identity |
| Abuse reporting | Message franking: franking_tag outside ciphertext, franking_key inside |
| Expiring content | Disappearing messages with TTL enforced at decrypt time |
| Shield enforcement | Enhanced key schedule, mandatory franking, external join blocking |

## Cryptographic Primitives

| Component | Choice | Standard |
|-----------|--------|----------|
| Key agreement (classical) | X25519 via x25519-dalek | RFC 7748 |
| Key agreement (PQ) | ML-KEM-768 via `ml-kem` | FIPS 203 |
| Digital signatures | Ed25519 via ed25519-dalek | RFC 8032 |
| AEAD | AES-256-GCM-SIV | RFC 8452 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Authentication | HMAC-SHA256 | RFC 2104 |
| Secure memory | pooled mlock + zeroize (MADV_DONTDUMP on Linux) | libc / zeroize |
| Secret sharing | Shamir GF(2^8) with HMAC auth | -- |

## Building

### Prerequisites

- Rust 1.86+ (stable)
- protobuf-compiler

#### macOS

```bash
brew install protobuf
```

#### Ubuntu/Debian

```bash
sudo apt-get install -y cmake ninja-build protobuf-compiler
```

### Build

```bash
cargo build --release
```

### Test

```bash
cargo test --release
cargo test --release --features ffi
cargo test --all-features
```

Coverage spans Rust API, integration, FFI, VoIP, attack-PoC, and property-based tests. The current local snapshot enumerates 750 default test scenarios and 889 scenarios with `--features ffi`.

### Paper Artifact Reproduction

```bash
./scripts/reproduce-paper-artifact.sh quick
```

The artifact entrypoint records tool versions and writes logs, `MANIFEST.txt`,
and `SHA256SUMS` under `artifact-output/<timestamp>-<mode>/`. See
[`docs/artifact-reproducibility.md`](docs/artifact-reproducibility.md) for the
claim-to-command map.

Useful modes:

| Mode | Scope |
|------|-------|
| `quick` | Fixed paper vectors, deterministic handshake/envelope/cross-ratchet/multi-epoch KATs, attack-PoC regression tests |
| `test` | Full Rust tests, with and without `ffi` |
| `formal` | Tamarin handshake/ratchet models + ProVerif |
| `paper` | Rebuild English, Ukrainian, and companion proof PDFs |
| `references` | Check bibliography/citation consistency and external URL reachability |
| `bench` | Criterion benchmark suite |
| `full` | Tests, formal models, PDFs, and benchmarks |

### Benchmarks

```bash
cargo bench
```

Key performance numbers (Apple M-series):

| Operation | Time |
|-----------|------|
| Full handshake (keygen + X3DH + Kyber + confirm) | ~1.1 ms |
| Hybrid ratchet step (X25519 + ML-KEM-768) | ~259 us |
| Encrypt 256 bytes | ~17 us |
| Decrypt 256 bytes | ~21 us |
| Burst throughput (no ratchet) | ~15 us/msg |

The Criterion suite also includes `pq_traffic_profiles`, a fixed
128-message/256-byte traffic model for comparing handshake-only PQ,
sparse chain-boundary PQ, periodic chain-boundary PQ, and per-reply PQ rekeying
under the same benchmark harness. Benchmark artifacts are produced on weekly
runs, main-branch pushes that touch benchmark/code paths, and release tags.

### Paper Review Package

Independent review scope, assumptions, commands, and sign-off fields are
defined in [`docs/external-review-package.md`](docs/external-review-package.md).
The ablation and sensitivity ledger is in
[`docs/ablation-study.md`](docs/ablation-study.md).

### Clippy

```bash
cargo clippy --all-targets --features ffi -- -D warnings   # 0 warnings
```

## Fuzzing

42 libfuzzer targets in `fuzz/fuzz_targets/`:

| Target | What it fuzzes |
|--------|---------------|
| `fuzz_handshake_init` | Handshake initiation with arbitrary input |
| `fuzz_handshake_ack` | Handshake ACK processing with arbitrary bytes |
| `fuzz_envelope_decrypt` | Envelope decryption with corrupted data |
| `fuzz_commit_processing` | Commit message deserialization and processing |
| `fuzz_commit_create` | Commit creation with arbitrary proposals |
| `fuzz_welcome_processing` | Welcome message deserialization and processing |
| `fuzz_welcome_roundtrip` | Welcome create/process roundtrip with fuzzed params |
| `fuzz_group_message_decrypt` | Group message decryption with malformed ciphertext |
| `fuzz_sealed_state_deserialize` | Sealed state deserialization with arbitrary bytes |
| `fuzz_session_state` | Session state serialize/deserialize roundtrip |
| `fuzz_protobuf_decode` | All 12 protobuf message types decode + roundtrip |
| `fuzz_e2e_proto` | End-to-end protocol flow with fuzzed messages |
| `fuzz_aes_gcm` | AES-256-GCM-SIV encrypt/decrypt with arbitrary keys |
| `fuzz_hkdf` | HKDF-SHA256 extract/expand with arbitrary IKM, salt, info |
| `fuzz_padding` | Message padding/unpadding with arbitrary bytes |
| `fuzz_shamir` | Shamir secret sharing split/reconstruct |
| `fuzz_dh_validator` | X25519 public key validation (small-order, field checks) |
| `fuzz_kyber` | ML-KEM-768 keygen, encapsulate, decapsulate, validation |
| `fuzz_secure_memory` | SecureMemoryHandle allocate/write/read/clone roundtrip |
| `fuzz_master_key_derivation` | Master key derivation (Ed25519, X25519, ML-KEM seeds) |
| `fuzz_identity` | Identity creation with fuzzed seeds |
| `fuzz_nonce` | NonceGenerator state restore, counter monotonicity |
| `fuzz_key_schedule` | Group key schedule epoch derivation, PSK injection |
| `fuzz_sender_key` | Sender key chain ratchet, advance_to, generation tracking |
| `fuzz_key_package_validate` | GroupKeyPackage signature and structure validation |
| `fuzz_relay` | Relay commit/message/welcome/envelope validation |
| `fuzz_tree_deserialize` | RatchetTree deserialization from protobuf nodes |
| `fuzz_tree_kem` | TreeKEM derive_node_keypairs, encrypt/decrypt path secret |
| `fuzz_tree_operations` | RatchetTree operations (add, remove, blank) |
| `fuzz_update_path` | UpdatePath creation and processing |
| `fuzz_membership` | Group membership proposal validation and application |
| `fuzz_voip_frame_header` | VoIP frame header parsing and serialization |
| `fuzz_voip_frame_roundtrip` | VoIP frame encode/decode roundtrip |
| `fuzz_voip_frame_decrypt` | VoIP frame decryption with malformed input |
| `fuzz_voip_header_decrypt` | VoIP header decryption and validation |
| `fuzz_voip_key_ratchet` | VoIP media key ratchet advancement |
| `fuzz_voip_protobuf` | VoIP protobuf decode and roundtrip behavior |
| `fuzz_voip_rekey_messages` | VoIP rekey message parsing and validation |
| `fuzz_voip_rekey_signature` | VoIP rekey signature handling |
| `fuzz_voip_relay` | VoIP relay envelope validation and routing |
| `fuzz_voip_replay_window` | VoIP replay-window behavior under arbitrary packets |
| `fuzz_ffi` | FFI function calls with arbitrary inputs |

Run with:

```bash
cargo +nightly fuzz run <target> -- -max_total_time=300
```

## Formal Verification

The formal claims below cover the two-party handshake and session ratchet analyzed in the paper. Group, VoIP, relay, and binding layers are tested and fuzzed implementation modules, but they require separate models before their security can be claimed under the same proof scope.

### Tamarin Prover (10/10 lemmas verified)

**Handshake model** (`formal/tamarin/aura_handshake.spthy`) — 6 lemmas:
- `session_key_secrecy` — hybrid root secret secure unless compromised
- `mutual_authentication` — bilateral key confirmation prevents UKS
- `responder_authentication` — symmetric authentication
- `forward_secrecy_hybrid` — classical-only compromise does not break key
- `key_confirmation` — same session derives identical keys
- `session_exists` — reachability

**Ratchet model** (`formal/tamarin/aura_ratchet.spthy`) — 4 lemmas:
- `pcs_sender_compromise` — 1-step PCS after sender state compromise
- `ratchet_key_secrecy` — ratchet key secret absent sender or receiver compromise
- `key_agreement` — both parties derive same root key
- `ratchet_exists` — reachability

### ProVerif (3/6 obligations discharged)

`formal/proverif/aura.pv` — KEM shared-secret secrecy, non-injective authentication, and message secrecy proven. Q3 is documented but disabled in the default artifact because the four-DH model does not terminate within the artifact budget. Q5/Q6 are negative stress obligations: Q5 is false for a broad unpartnered active trace, and Q6 is false for raw KEM-secret secrecy after KEM secret-key reveal.

### Game-Based Security Proofs

`docs/security-proof.tex` — 6 theorems with constructive reductions:

| Theorem | Property | Assumptions |
|---------|----------|-------------|
| 1 | Hybrid Combiner IND-CCA2 | Gap-CDH OR Kyber IND-CCA2 |
| 2 | eCK-style AKE security | Gap-CDH + IND-CCA2 + dual-PRF + ROM |
| 3 | Forward Secrecy | Gap-CDH + dual-PRF; initial KEM gives HNDL only absent later KEM-SK disclosure |
| 4 | Post-Compromise Security | 1-step classical (Gap-CDH); 2-step hybrid (Gap-CDH + IND-CCA2) under conservative both-endpoint compromise |
| 5 | Message Confidentiality + Integrity | eCK + PRF + MRAE |
| 6 | Replay Resistance | INT-CTXT + bounded nonce cache |

## Project Structure

```
src/
  core/           Constants, error types, shared protocol limits
  crypto/         AES-GCM-SIV, HKDF, ML-KEM-768, SecureMemory, Shamir SSS, padding
  identity/       Key generation, bundle creation, SPK signatures
  models/         Key material types (Ed25519, X25519, OPK)
  protocol/
    attachment.rs  Attachment manifest + chunk crypto validation
    handshake.rs  Hybrid X3DH handshake
    session.rs    Hybrid Double Ratchet session
    group/        MLS-inspired group messaging protocol
      mod.rs        GroupSession API + Shield mode (create, add, remove, update, encrypt/decrypt)
      tree.rs       RatchetTree (left-balanced binary, X25519 + ML-KEM-768 nodes)
      tree_kem.rs   Hybrid PQ TreeKEM (create/process UpdatePath)
      commit.rs     Commit creation/processing, epoch advancement, ExternalInit
      welcome.rs    Welcome message creation/processing
      key_schedule.rs  Epoch key derivation, external keypair derivation
      key_package.rs   Key package generation and validation
      membership.rs    Proposal validation/application (Add, Remove, Update, ExternalInit)
      sender_key.rs    Per-member symmetric hash ratchet (O(1) encrypt/decrypt)
  security/       DH validation (small-order point rejection)
  ffi/            C FFI layer, owned buffers/errors, lifecycle + rollback helpers
  api/
    mod.rs        Client Rust API facade
    relay.rs      Server relay API (validation + routing)
swift/
  Sources/AuraProtectedProtocol/
    Shim.swift          @_silgen_name symbol bindings + native struct mirrors
    AuraError.swift      Swift error mapping for native FFI codes
    AuraIdentity.swift   Identity (create, seed, keys, prekey bundle)
    AuraSession.swift    1:1 session (encrypt, decrypt, serialize, nonce)
    AuraHandshake.swift  Handshake (initiator, responder) + namespace
    AuraGroupSession.swift  Group session (full API + Shield mode)
    AuraTimeProvider.swift  Manual clock / trusted-time binding
    AuraSealedStateCounterTracker.swift  Managed anti-rollback tracker
    AuraSealedStateSlot.swift  Single-record sealed-state persistence helper
    AuraVoipSession.swift  VoIP call setup, media, rekey, persistence
    AuraAttachment.swift  Attachment/media manifests, chunk crypto, streaming
    AuraCrypto.swift     Shamir SSS + envelope validation
formal/
  tamarin/        Tamarin models (handshake 6/6, ratchet 4/4)
  proverif/       ProVerif model (3/6 obligations)
docs/
  security-proof.tex       Game-based proofs (6 theorems, 8 lemmas)
  attachment-flow.md       Attachment encryption and transport contract
  features/
    sealed-messages.md       Sealed messages design doc
    disappearing-messages.md Disappearing messages design doc
    message-franking.md      Message franking design doc
    shield-mode.md           Shield mode design doc
  ffi-swift.md            Swift FFI guide
  aura-relay-swift-alignment.md  Cross-repo contract (AURA <-> Relay <-> Swift)
  relay-server.md         Relay server guide
proto/
  protocol/       Protobuf message definitions
benches/
  protocol_bench.rs    Criterion benchmarks (1:1 + group protocol)
fuzz/
  fuzz_targets/        42 libfuzzer targets
tests/
  api_test.rs          Rust API regression coverage
  ffi_test.rs          FFI contract and lifecycle coverage
  integration_test.rs  End-to-end and protocol-state coverage
  attack_poc.rs        Attack proof-of-concept regressions
```

## Swift (iOS / macOS)

Use a tagged release that ships a matching XCFramework snapshot. The checked-in [`Package.swift`](Package.swift) is the source of truth for the current binary target URL, checksum, and minimum platform versions.

The Swift package manifest currently targets iOS 18+ and macOS 15+. The high-level Swift layer binds exported Rust symbols via `@_silgen_name`, while the XCFramework still ships `aura_api.h` / `module.modulemap` for C and Objective-C consumers.

### Quick Start

```swift
import AuraProtectedProtocol

// Initialize
try AuraProtectedProtocol.initialize()

// Create identities
let alice = try AuraIdentity.create()
let bob = try AuraIdentity.create()

// 1:1 handshake
let bobBundle = try bob.createPrekeyBundle()
let (initiator, handshakeInit) = try AuraHandshakeInitiator.start(identity: alice, peerPrekeyBundle: bobBundle)
let (responder, handshakeAck) = try AuraHandshakeResponder.start(identity: bob, localPrekeyBundle: bobBundle, handshakeInit: handshakeInit)
let aliceSession = try initiator.finishVerifyingPeer(
    handshakeAck: handshakeAck,
    expectedPeerEd25519PublicKey: bob.ed25519PublicKey,
    expectedPeerX25519PublicKey: bob.x25519PublicKey
)
let bobSession = try responder.finishVerifyingPeer(
    expectedPeerEd25519PublicKey: alice.ed25519PublicKey,
    expectedPeerX25519PublicKey: alice.x25519PublicKey
)

// Encrypt / Decrypt
let ciphertext = try aliceSession.encrypt(plaintext: "Hello".data(using: .utf8)!)
let plaintext = try bobSession.decrypt(encryptedEnvelope: ciphertext)

// Group session (shielded)
let group = try AuraGroupSession.createShielded(identity: alice, credential: "alice".data(using: .utf8)!)
let encrypted = try group.encrypt("Hello group".data(using: .utf8)!)

// Special message types
let sealed = try group.encryptSealed("Secret".data(using: .utf8)!, hint: hintData)
let disappearing = try group.encryptDisappearing("Temp".data(using: .utf8)!, ttlSeconds: 60)
let frankable = try group.encryptFrankable("Reportable".data(using: .utf8)!)
let edit = try group.encryptEdit(newContent: "Edited".data(using: .utf8)!, targetMessageId: msgId)
let delete = try group.encryptDelete(targetMessageId: msgId)
```

### Swift API Coverage

| Category | Methods |
|----------|---------|
| **Identity** | create, create(fromSeed:), create(fromSeed:membershipId:), x25519/ed25519/kyberPublicKey, createPrekeyBundle |
| **1:1 Handshake** | AuraHandshakeInitiator.start/finish, AuraHandshakeResponder.start/finish |
| **1:1 Session** | encrypt, decrypt, serialize, deserialize, nonceRemaining |
| **Group Session** | create, createShielded, create(policy:), join, joinExternal |
| **Group Membership** | addMember, removeMember, update, processCommit, generateKeyPackage |
| **Group Messaging** | encrypt, decrypt, decryptEx (full metadata) |
| **Special Messages** | encryptSealed, encryptDisappearing, encryptFrankable, encryptEdit, encryptDelete |
| **Crypto Verification** | computeMessageId, revealSealed, verifyFranking |
| **Group State** | groupId, epoch, myLeafIndex, memberCount, memberLeafIndices, isShielded, securityPolicy |
| **Serialization** | serialize/deserialize (group + 1:1), exportPublicState |
| **Shield Mode** | AuraGroupSecurityPolicy, .shield preset, createShielded, isShielded |
| **Managed State** | AuraSealedStateCounterTracker, AuraSealedStateSlot, persisted-state export/restore |
| **Time Provider** | AuraTimeProvider.manual, setNowUnix, identity/session/VoIP trusted-time binding |
| **VoIP** | call init/accept/finish, media encrypt/decrypt, rekey, sealed/persisted state |
| **Attachments** | manifest/chunk helpers, thumbnails, TTL, collages, streaming encrypt/decrypt |
| **Utilities** | initialize, shutdown, version, deriveRootKey, secureWipe, validateEnvelope, shamirSplit/Reconstruct |

## Relay (Server)

The server never decrypts traffic — it validates format, routes by `group_id`, and stores/delivers events.

All relay functions are in `aura_protected_protocol::api::relay`:

- `validate_crypto_envelope()` — validate 1:1 envelope structure
- `validate_commit_for_relay_strict()` — structural group-commit validation + sender identity binding from auth context
- `validate_group_message_for_relay_strict()` — validate group message + sender signature + auth-context identity binding
- `apply_commit_to_roster_tentative()` — update tentative relay membership state
- `extract_welcome_target()` — find welcome recipient
- `commit_recipients()` / `message_recipients()` / `crypto_envelope_recipients()` — delivery targets
- `validate_voip_envelope()` / `process_voip_signal()` — VoIP relay validation and call-state-safe routing via atomic `VoipCallStore::compare_exchange_call()`
- `PendingEventStore` trait — event persistence (store/fetch/ack by device_id)

See [docs/relay-server.md](docs/relay-server.md) for full guide.
Cross-repo integration contract is documented in [docs/aura-relay-swift-alignment.md](docs/aura-relay-swift-alignment.md).

## CI

CI and scheduled workflows cover these categories:

| Job | What it does |
|-----|-------------|
| **Check & Clippy** | `cargo check` + `cargo clippy -- -D warnings` (with and without `ffi` feature) |
| **Test** | Release and feature-matrix test runs on Linux, macOS, Windows; local snapshot: 750 default scenarios, 889 with `--features ffi` |
| **Formal Verification** | Tamarin Prover (10 lemmas) + ProVerif (3/6 obligations discharged), with uploaded formal artifact logs |
| **MSRV** | Minimum supported Rust version (1.86) |
| **Fuzz Smoke Test** | All 42 libfuzzer targets (10s each) |
| **Security Audit** | `cargo audit` for known vulnerabilities |
| **Security Scan** | cargo-deny, TruffleHog secret scanning, license compliance |
| **Benchmarks** | Criterion benchmarks on Linux, macOS, Windows (weekly + on push) |

The separate `Paper Artifact` workflow runs fixed paper vectors, rebuilds the
English, Ukrainian, and companion proof PDFs, audits paper references, and
uploads the complete `artifact-output/**` bundle on release tags, manual
dispatch, and artifact-related pull requests.

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
