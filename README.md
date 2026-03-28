# Ecliptix Protected Protocol

[![CI](https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/actions/workflows/ci.yml)
[![Security Scan](https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/actions/workflows/security-scan.yml/badge.svg)](https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/actions/workflows/security-scan.yml)
[![Benchmarks](https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/actions/workflows/benchmarks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Hybrid post-quantum secure messaging protocol combining **X25519 + Kyber-768** with a Double Ratchet, **AES-256-GCM-SIV**, per-epoch metadata encryption, and an **MLS-inspired group messaging protocol** with hybrid PQ TreeKEM — featuring **Shield mode**, sealed messages, disappearing messages, and message franking.

## Key Differentiators

| Feature | Signal X3DH | Signal PQXDH | **Ecliptix** |
|---------|------------|-------------|--------------|
| Per-ratchet PQ protection | No | No | **Yes** (X25519 + Kyber-768) |
| Metadata encryption | Sealed Sender | Sealed Sender | **Per-epoch rotating key** |
| AEAD | AES-256-CBC + HMAC | AES-256-CBC + HMAC | **AES-256-GCM-SIV** (nonce-misuse resistant) |
| Post-compromise recovery | 1-step (DH) | 1-step (DH) | **1-step classical / 2-step hybrid** |
| Group protocol | N/A | N/A | **Hybrid PQ TreeKEM** (X25519 + Kyber-768) |
| Shield mode | No | No | **Yes** (enhanced key schedule, mandatory franking) |
| Message features | Basic | Basic | **Sealed, disappearing, frankable, edit, delete** |
| Formal proofs | eCK sketch | High-level | **6 theorems + 10 Tamarin lemmas** |

## Architecture

```
1:1 Messaging                         Group Messaging (MLS-inspired)
┌─────────────────────────┐           ┌──────────────────────────────────────┐
│ Handshake (Hybrid X3DH) │           │ TreeKEM (Hybrid PQ)                  │
│  4x X25519 DH            │           │  Left-balanced binary tree            │
│  1x Kyber-768 KEM         │           │  X25519 + Kyber-768 per node          │
│  HKDF-SHA256 combiner     │           │  parent_hash chain verification       │
│  HMAC key confirmation    │           │                                       │
│  Ed25519 SPK signature    │           │ Sender Keys                           │
└───────────┬───────────────┘           │  Per-member symmetric hash ratchet    │
            v                           │  O(1) encrypt/decrypt                 │
┌─────────────────────────┐           │                                       │
│ Session (Hybrid Ratchet) │           │ Epoch Advancement                     │
│  Per-direction ratchet:   │           │  Commit + Welcome                     │
│    X25519 DH + Kyber KEM  │           │  External Join                        │
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
| Max skipped keys per sender | 256 | 256 |

```swift
// Swift — create a shielded group
let group = try EppGroupSession.createShielded(identity: identity, credential: cred)

// Or with custom policy
let policy = EppGroupSecurityPolicy(
    maxMessagesPerEpoch: 500,
    blockExternalJoin: true,
    enhancedKeySchedule: true,
    mandatoryFranking: true
)
let group = try EppGroupSession.create(identity: identity, credential: cred, policy: policy)
```

```rust
// Rust — create a shielded group
let group = EcliptixProtocol::group_create_shielded(&identity, &credential)?;

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
| Forward secrecy | Ephemeral keys erased after use; chain keys ratcheted |
| Post-compromise security | Direction-change triggers hybrid ratchet (fresh DH + KEM) |
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

| Property | Mechanism |
|----------|-----------|
| Group forward secrecy | Epoch advancement via Commit; old epoch keys erased |
| Group post-compromise security | TreeKEM UpdatePath re-encrypts path with fresh X25519 + Kyber-768 |
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
| Key agreement (PQ) | Kyber-768 via liboqs | FIPS 203 (ML-KEM) |
| Digital signatures | Ed25519 via ed25519-dalek | RFC 8032 |
| AEAD | AES-256-GCM-SIV | RFC 8452 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Authentication | HMAC-SHA256 | RFC 2104 |
| Secure memory | mlock + zeroize (guard pages on Linux) | libc / zeroize |
| Secret sharing | Shamir GF(2^8) with HMAC auth | -- |

## Building

### Prerequisites

- Rust 1.86+ (stable)
- CMake + Ninja (for liboqs build)
- protobuf-compiler

#### macOS

```bash
brew install cmake ninja protobuf
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
cargo test --release                # 391 tests (server context)
cargo test --release --features ffi # 421 tests (client + FFI)
```

421 tests covering: crypto primitives, protocol correctness, adversarial inputs, replay protection, post-compromise security, out-of-order delivery, property-based testing (proptest), concurrent stress tests, group protocol (TreeKEM, Commit/Welcome, External Join, sender keys, epoch advancement, Shield mode), FFI bindings, sealed/disappearing/frankable/edit/delete messages, attack PoCs.

### Benchmarks

```bash
cargo bench
```

Key performance numbers (Apple M-series):

| Operation | Time |
|-----------|------|
| Full handshake (keygen + X3DH + Kyber + confirm) | ~1.1 ms |
| Hybrid ratchet step (X25519 + Kyber-768) | ~259 us |
| Encrypt 256 bytes | ~17 us |
| Decrypt 256 bytes | ~21 us |
| Burst throughput (no ratchet) | ~15 us/msg |

### Clippy

```bash
cargo clippy --all-targets --features ffi -- -D warnings   # 0 warnings
```

## Fuzzing

32 libfuzzer targets in `fuzz/fuzz_targets/`:

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
| `fuzz_master_key_derivation` | Master key derivation (Ed25519, X25519, Kyber seeds) |
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
| `fuzz_ffi` | FFI function calls with arbitrary inputs |

Run with:

```bash
cargo +nightly fuzz run <target> -- -max_total_time=300
```

## Formal Verification

### Tamarin Prover (10/10 lemmas verified)

**Handshake model** (`formal/tamarin/ecliptix_handshake.spthy`) — 6 lemmas:
- `session_key_secrecy` — hybrid root secret secure unless compromised
- `mutual_authentication` — bilateral key confirmation prevents UKS
- `responder_authentication` — symmetric authentication
- `forward_secrecy_hybrid` — classical-only compromise does not break key
- `key_confirmation` — same session derives identical keys
- `session_exists` — reachability

**Ratchet model** (`formal/tamarin/ecliptix_ratchet.spthy`) — 4 lemmas:
- `pcs_sender_compromise` — 1-step PCS after sender state compromise
- `ratchet_key_secrecy` — ratchet key secret unless both parties compromised
- `key_agreement` — both parties derive same root key
- `ratchet_exists` — reachability

### ProVerif (4/6 queries proven)

`formal/proverif/ecliptix.pv` — session key secrecy, authentication (non-injective + injective), forward secrecy. Q4/Q5 (message secrecy/integrity) are known ProVerif DH overapproximation limitations, covered by game-based proofs.

### Game-Based Security Proofs

`docs/security-proof.tex` — 6 theorems with constructive reductions:

| Theorem | Property | Assumptions |
|---------|----------|-------------|
| 1 | Hybrid Combiner IND-CCA2 | Gap-CDH OR Kyber IND-CCA2 |
| 2 | eCK-AKE Security | Gap-CDH + IND-CCA2 + dual-PRF + ROM |
| 3 | Forward Secrecy | Gap-CDH + IND-CCA2 + dual-PRF |
| 4 | Post-Compromise Security | 1-step classical (Gap-CDH); 2-step hybrid (+IND-CCA2) |
| 5 | Message Confidentiality + Integrity | eCK + PRF + MRAE |
| 6 | Replay Resistance | INT-CTXT + bounded nonce cache |

## Project Structure

```
src/
  core/           Constants (92), error types (14 variants)
  crypto/         AES-GCM-SIV, HKDF, Kyber-768, SecureMemory, Shamir SSS, padding
  identity/       Key generation, bundle creation, SPK signatures
  models/         Key material types (Ed25519, X25519, OPK)
  protocol/
    attachment.rs  Attachment manifest + chunk crypto validation
    handshake.rs  Hybrid X3DH handshake
    session.rs    Hybrid Double Ratchet session
    group/        MLS-inspired group messaging protocol
      mod.rs        GroupSession API + Shield mode (create, add, remove, update, encrypt/decrypt)
      tree.rs       RatchetTree (left-balanced binary, X25519 + Kyber-768 nodes)
      tree_kem.rs   Hybrid PQ TreeKEM (create/process UpdatePath)
      commit.rs     Commit creation/processing, epoch advancement, ExternalInit
      welcome.rs    Welcome message creation/processing
      key_schedule.rs  Epoch key derivation, external keypair derivation
      key_package.rs   Key package generation and validation
      membership.rs    Proposal validation/application (Add, Remove, Update, ExternalInit)
      sender_key.rs    Per-member symmetric hash ratchet (O(1) encrypt/decrypt)
  security/       DH validation (small-order point rejection)
  ffi/            C FFI layer (69 epp_* functions, feature-gated)
  api/
    mod.rs        Client Rust API facade
    relay.rs      Server relay API (validation + routing)
swift/
  Sources/EcliptixProtectedProtocol/
    Shim.swift          @_silgen_name declarations (69 FFI bindings)
    EppError.swift      Error types (26 cases)
    EppIdentity.swift   Identity (create, seed, keys, prekey bundle)
    EppSession.swift    1:1 session (encrypt, decrypt, serialize, nonce)
    EppHandshake.swift  Handshake (initiator, responder) + namespace
    EppGroupSession.swift  Group session (full API + Shield mode)
    EppCrypto.swift     Shamir SSS + envelope validation
formal/
  tamarin/        Tamarin models (handshake 6/6, ratchet 4/4)
  proverif/       ProVerif model (4/6 queries)
docs/
  security-proof.tex       Game-based proofs (6 theorems, 8 lemmas)
  attachment-flow.md       Attachment encryption and transport contract
  features/
    sealed-messages.md       Sealed messages design doc
    disappearing-messages.md Disappearing messages design doc
    message-franking.md      Message franking design doc
    shield-mode.md           Shield mode design doc
  ffi-swift.md            Swift FFI guide
  epp-relay-swift-alignment.md  Cross-repo contract (EPP <-> Relay <-> Swift)
  relay-server.md         Relay server guide
proto/
  protocol/       Protobuf message definitions
benches/
  protocol_bench.rs    Criterion benchmarks (1:1 + group protocol)
fuzz/
  fuzz_targets/        32 libfuzzer targets
tests/
  api_test.rs          Rust API tests (46)
  ffi_test.rs          FFI tests (30, feature-gated)
  integration_test.rs  Integration tests (307)
  attack_poc.rs        Attack proof-of-concept tests (38)
```

## Swift (iOS / macOS)

Swift Package Manager — add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs.git", from: "1.1.1")
]
```

The Swift wrapper uses `@_silgen_name` to call Rust FFI exports directly — no C headers or modulemaps needed at compile time. All 69 FFI functions are wrapped with full documentation.

### Quick Start

```swift
import EcliptixProtectedProtocol

// Initialize
try EcliptixProtectedProtocol.initialize()

// Create identities
let alice = try EppIdentity.create()
let bob = try EppIdentity.create()

// 1:1 handshake
let bobBundle = try bob.createPrekeyBundle()
let (initiator, handshakeInit) = try EppHandshakeInitiator.start(identity: alice, peerPrekeyBundle: bobBundle)
let (responder, handshakeAck) = try EppHandshakeResponder.start(identity: bob, localPrekeyBundle: bobBundle, handshakeInit: handshakeInit)
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
let group = try EppGroupSession.createShielded(identity: alice, credential: "alice".data(using: .utf8)!)
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
| **1:1 Handshake** | EppHandshakeInitiator.start/finish, EppHandshakeResponder.start/finish |
| **1:1 Session** | encrypt, decrypt, serialize, deserialize, nonceRemaining |
| **Group Session** | create, createShielded, create(policy:), join, joinExternal |
| **Group Membership** | addMember, removeMember, update, processCommit, generateKeyPackage |
| **Group Messaging** | encrypt, decrypt, decryptEx (full metadata) |
| **Special Messages** | encryptSealed, encryptDisappearing, encryptFrankable, encryptEdit, encryptDelete |
| **Crypto Verification** | computeMessageId, revealSealed, verifyFranking |
| **Group State** | groupId, epoch, myLeafIndex, memberCount, memberLeafIndices, isShielded, securityPolicy |
| **Serialization** | serialize/deserialize (group + 1:1), exportPublicState |
| **Shield Mode** | EppGroupSecurityPolicy, .shield preset, createShielded, isShielded |
| **Utilities** | initialize, shutdown, version, deriveRootKey, secureWipe, validateEnvelope, shamirSplit/Reconstruct |

## Relay (Server)

The server never decrypts traffic — it validates format, routes by `group_id`, and stores/delivers events.

All relay functions are in `ecliptix_protocol::api::relay`:

- `validate_crypto_envelope()` — validate 1:1 envelope structure
- `validate_commit_for_relay_strict()` — structural group-commit validation + sender identity binding from auth context
- `validate_group_message_for_relay_strict()` — validate group message + sender signature + auth-context identity binding
- `apply_commit_to_roster_tentative()` — update tentative relay membership state
- `extract_welcome_target()` — find welcome recipient
- `commit_recipients()` / `message_recipients()` / `crypto_envelope_recipients()` — delivery targets
- `validate_voip_envelope()` / `process_voip_signal()` — VoIP relay validation and call-state-safe routing via atomic `VoipCallStore::compare_exchange_call()`
- `PendingEventStore` trait — event persistence (store/fetch/ack by device_id)

See [docs/relay-server.md](docs/relay-server.md) for full guide.
Cross-repo integration contract is documented in [docs/epp-relay-swift-alignment.md](docs/epp-relay-swift-alignment.md).

## CI

GitHub Actions pipeline with 8 jobs:

| Job | What it does |
|-----|-------------|
| **Check & Clippy** | `cargo check` + `cargo clippy -- -D warnings` (with and without `ffi` feature) |
| **Test** | `cargo test --release` on Linux, macOS, Windows (421 tests with FFI) |
| **Formal Verification** | Tamarin Prover (10 lemmas) + ProVerif (6 queries) |
| **MSRV** | Minimum supported Rust version (1.86) |
| **Fuzz Smoke Test** | All 32 libfuzzer targets (10s each) |
| **Security Audit** | `cargo audit` for known vulnerabilities |
| **Security Scan** | cargo-deny, TruffleHog secret scanning, license compliance |
| **Benchmarks** | Criterion benchmarks on Linux, macOS, Windows (weekly + on push) |

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
