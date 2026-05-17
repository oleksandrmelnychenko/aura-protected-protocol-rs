# Aura Protocol vs Signal Protocol vs PQXDH — Comparative Analysis

> For inclusion as supplementary material or Section 6 (Related Work / Comparison) in the Aura protocol publication.
>
> Data sources: Signal specifications (signal.org/docs/specifications/{pqxdh,doubleratchet,x3dh}), Aura source code, NIST PQC standards, published benchmarks.
>
> Status: legacy high-level comparison. The LaTeX papers are the authoritative submission text; this file is only orientation material and must not be read as a full post-quantum-authentication claim. Aura's current artifact targets hybrid post-quantum confidentiality of session secrets under classical Ed25519 authentication.

---

## 1. Protocol Architecture Overview

| Aspect | Signal (X3DH + DR) | Signal PQXDH (2023) | **Aura** |
|--------|-------------------|---------------------|--------------|
| Handshake | X3DH (3–4 ECDH) | PQXDH (3–4 ECDH + 1 KEM) | Hybrid X3DH (3–4 ECDH + 1 KEM) |
| Ratchet | Double Ratchet (X25519 DH) | Double Ratchet (X25519 DH) | **Hybrid Double Ratchet (X25519 + ML-KEM-768)** |
| PQ scope | None | Handshake only | **Handshake + every ratchet step** |
| AEAD | AES-256-CBC + HMAC-SHA256 | AES-256-CBC + HMAC-SHA256 | **AES-256-GCM-SIV** |
| Metadata encryption | Sealed Sender (sender identity) | Sealed Sender | **Per-message metadata AEAD (rotating key)** |
| Wire format | Protobuf | Protobuf | Protobuf |
| Implementation | libsignal (Rust/Java/Swift) | libsignal | **aura-protocol-rs (Rust + C FFI)** |

---

## 2. Cryptographic Primitives

| Primitive | Signal / PQXDH | **Aura** | Notes |
|-----------|----------------|--------------|-------|
| Key agreement (classical) | X25519 | X25519 | Identical |
| Key agreement (PQ) | ML-KEM-1024 (Kyber-1024) | **ML-KEM-768** | Aura: NIST Security Level 3; Signal: Level 5 |
| Digital signatures | Ed25519 | Ed25519 | Identical |
| Symmetric encryption | AES-256-CBC | **AES-256-GCM-SIV** | GCM-SIV: nonce-misuse resistant |
| Authentication (messages) | HMAC-SHA256 (Encrypt-then-MAC) | AEAD tag (GCM-SIV) | Signal: separate MAC; Aura: integrated |
| Key derivation | HKDF-SHA256 | HKDF-SHA256 | Identical primitive |
| Master key derivation | — | **BLAKE2b** (keyed, length-prefixed) | Aura: deterministic key hierarchy from master key |
| Secret sharing | — | **Shamir GF(2^8)** (HMAC-authenticated) | Aura: key backup/recovery |
| Secure memory | Platform-dependent | **mlock + zeroize** (guard pages on Linux) | Aura: explicit secure memory API |

### Why ML-KEM-768 vs ML-KEM-1024?

Signal chose ML-KEM-1024/Kyber-1024 (NIST Level 5) for maximum security margin at the handshake. Aura uses ML-KEM-768 (Level 3) because:

1. **Ratchet frequency**: Aura runs ML-KEM on every direction-change ratchet, not just the handshake. This improves state recovery after compromise, but it is not a claim that Level 3 ratcheting is categorically equivalent to one Level 5 exchange.
2. **Performance**: ML-KEM-768 is smaller and faster than ML-KEM-1024 for keygen/encap/decap, which matters when PQ operations occur on ratchet boundaries.
3. **Bandwidth**: ML-KEM-768 public keys are 1,184 bytes vs 1,568 bytes for ML-KEM-1024 — relevant for mobile/IoT.

---

## 3. Post-Quantum Protection Depth

This is the most significant architectural difference between the three protocols.

| Property | Signal X3DH | Signal PQXDH | **Aura** |
|----------|------------|--------------|--------------|
| PQ-protected handshake | No | **Yes** (1× KEM) | **Yes** (1× KEM) |
| PQ-protected ratchet | No | No (X25519 only) | **Yes** (ML-KEM-768 per directed ratchet step) |
| Harvest-now-decrypt-later defense | None | Handshake only | **Handshake + all ratchet epochs** |
| PQ forward secrecy | None | Initial session key only | **Per-epoch** (each ratchet wipes PQ material) |
| PQ post-compromise security | None | None (ratchet is classical) | **Hybrid recovery after the next directed step using a post-compromise KEM key** |

### Signal PQXDH Gap

Signal's PQXDH protects the initial key exchange against quantum adversaries, but the ongoing Double Ratchet uses only X25519 DH. A quantum adversary who stores ciphertexts and later obtains quantum computing capability can:

1. Break all X25519 DH ratchet steps
2. Derive all chain keys and message keys from the root chain forward
3. Decrypt all messages in the session

The PQXDH handshake key is only the initial seed — once the ratchet evolves past it using classical DH, the PQ protection is lost.

Signal has published **Sparse Post-Quantum Ratchet (SPQR)** and **Triple Ratchet** material (running Double Ratchet + SPQR in parallel). Those designs are the modern Signal-family baseline for ongoing PQ state evolution; Aura's paper does not claim broad priority over them.

### Aura Approach

Aura integrates ML-KEM-768 into every hybrid ratchet step:

```
hybrid_ikm = DH(new_x25519_priv, peer_x25519_pub) || KEM.Decap(ct, sk)
salt        = old_root_key || "Aura-PQ-Hybrid::" || kem_shared_secret
ratchet_out = HKDF(hybrid_ikm, 96, salt, "Aura-Hybrid-Ratchet")
  → new_root_key(32) || new_chain_key(32) || new_metadata_key(32)
```

Each direction change generates a fresh ML-KEM-768 keypair locally and sends the public key + ciphertext to the peer. Old KEM secret keys are wiped immediately after decapsulation. This provides:

- **Per-epoch PQ forward secrecy absent later KEM-SK disclosure**: Compromising epoch N's KEM key reveals nothing about independent epochs N-1 or N+1.
- **Hybrid post-compromise recovery**: After a conservative two-endpoint compromise, classical recovery occurs after the next honest directed step, and hybrid recovery occurs after the next directed step that uses a post-compromise KEM public key.

---

## 4. Security Properties Comparison

| Property | Signal X3DH+DR | Signal PQXDH | **Aura** |
|----------|---------------|--------------|--------------|
| **Confidentiality** | AES-256-CBC + HMAC | AES-256-CBC + HMAC | AES-256-GCM-SIV |
| **Forward secrecy (classical)** | Yes (DH ratchet) | Yes (DH ratchet) | Yes (DH ratchet) |
| **Forward secrecy (PQ)** | No | Handshake only | **Per-epoch** |
| **Post-compromise security** | Yes (DH ratchet) | Yes (DH ratchet, classical only) | **1-step classical / 2-step hybrid in the directed KEM schedule** |
| **Replay protection** | Message counter + key consumption | Same | **Bounded nonce cache (2048) + key consumption** |
| **Nonce misuse resistance** | No (CBC mode) | No | **Yes (GCM-SIV)** |
| **Metadata privacy** | Sealed Sender (sender identity) | Sealed Sender | **Encrypted envelope metadata (rotating key)** |
| **Deniability (offline)** | Yes (symmetric MACs) | Yes | Yes (symmetric MACs) |
| **Deniability (online)** | Weak | Weak | **No** (by design — auth > deniability) |
| **State integrity** | Database encryption (SQLCipher) | Same | **State HMAC plus external monotonic counter for rollback freshness** |
| **Session teardown** | No explicit ceremony | No | **Explicit `destroy()` — 9-step key wipe** |
| **Secure memory** | Platform-dependent | Same | **mlock + zeroize (guard pages on Linux)** |
| **Small-order point rejection** | Yes | Yes | **Yes (constant-time, branchless)** |
| **Reflexion attack protection** | Not specified | Not specified | **Yes (constant-time identity comparison)** |

### Nonce Misuse Resistance

Signal uses AES-256-CBC, which requires unique IVs but does not provide nonce-misuse resistance. If an IV is accidentally reused, CBC leaks information about plaintext blocks.

Aura uses AES-256-GCM-SIV (RFC 8452), which maintains authenticity even under nonce reuse and only leaks whether two plaintexts are identical (not their content). This is a strictly stronger security property.

### Metadata Privacy

Signal's Sealed Sender hides the sender's identity from the server but does not encrypt per-message metadata (message index, payload nonce, envelope type). This metadata is visible in the outer envelope.

Aura encrypts all envelope metadata with a dedicated metadata key that rotates on each ratchet step, providing forward secrecy for metadata. Old-epoch metadata keys are cached (up to 100 entries) for out-of-order delivery.

---

## 5. Performance Comparison

### Aura Benchmarks (Apple M1 Pro, Rust, Criterion)

| Operation | Aura | Notes |
|-----------|----------|-------|
| Identity creation (5 OPKs) | ~450 µs | Ed25519 + X25519 + ML-KEM-768 keygen |
| Full handshake (keygen + X3DH + confirm) | ~1.5 ms | Hybrid: 4× DH + 1× ML-KEM encap/decap |
| Encrypt (256 B) | ~17 µs | AES-256-GCM-SIV + metadata AEAD |
| Decrypt (256 B) | ~21 µs | + replay check + metadata AEAD |
| Encrypt/decrypt roundtrip (64 B) | ~14 µs | Minimal payload |
| Encrypt/decrypt roundtrip (4 KB) | ~57 µs | Larger payload |
| Direction-change ratchet | ~430 µs | X25519 DH + ML-KEM-768 encap/decap + HKDF |
| Burst throughput (256 B, same chain) | ~15 µs | No ratchet, chain key advance only |
| Alternating throughput (256 B) | ~524 µs | Full hybrid ratchet per message |
| Out-of-order decrypt (20 msgs) | ~292 µs | Skipped key lookup + decrypt |
| Cross-epoch decrypt | ~13 µs | Cached chain key lookup |
| Session export (sealed) | ~105 µs | AES-GCM-SIV sealed-state encryption |
| Session import (sealed) | ~185 µs | Decrypt + HMAC verify + deserialize |
| HKDF-SHA256 derive | ~1.6 µs | Single derivation |
| ML-KEM-768 keygen | ~80 µs | deterministic/vector provider in the historical benchmark |
| ML-KEM-768 encap+decap | ~94 µs | Combined |
| AES-256-GCM-SIV (256 B) | ~6 µs | Encrypt only |
| AES-256-GCM-SIV (16 KB) | ~170 µs | Encrypt only |
| Shamir split (3-of-5, 32 B) | ~44 µs | GF(2^8) with log/exp tables |
| Shamir reconstruct (3-of-5, 32 B) | ~4.4 µs | Lagrange interpolation |

### Hybrid Ratchet Overhead Breakdown

| Component | Time | % of Hybrid Ratchet |
|-----------|------|---------------------|
| X25519 DH scalarmult | ~34 µs | 13% |
| ML-KEM-768 encap+decap | ~94 µs | 36% |
| HKDF + key derivation + state update | ~131 µs | 51% |
| **Total hybrid ratchet** | **~259 µs** | 100% |

**Cost of PQ protection per ratchet step**: ~94 µs (~36% overhead). This is the price for per-epoch PQ forward secrecy and PCS — acceptable for messaging applications where ratchet steps occur once per direction change, not per message.

### Estimated Signal Performance (from public benchmarks and literature)

| Operation | Signal (estimated) | Source |
|-----------|--------------------|--------|
| X3DH handshake | ~0.5–1.0 ms | Classical only (4× X25519 DH + HKDF) |
| PQXDH handshake | ~1.5–2.0 ms | + Kyber-1024 encap/decap |
| Encrypt (256 B) | ~5–15 µs | AES-256-CBC + HMAC-SHA256 |
| Decrypt (256 B) | ~5–15 µs | Verify HMAC + AES-256-CBC |
| DH ratchet step | ~35–50 µs | X25519 DH + HKDF (classical only) |

> **Note**: a classical-only ratchet step is faster because it performs only X25519 DH (no ML-KEM). Aura pays this cost to refresh KEM material at directed ratchet boundaries.

---

## 6. Wire Format and Bandwidth

| Metric | Signal | Signal PQXDH | **Aura** |
|--------|--------|-------------|--------------|
| Handshake init size | ~130 B | ~1,250 B (+Kyber-1024 CT) | ~1,170 B (+ML-KEM-768 CT) |
| Pre-key bundle size | ~200 B | ~1,800 B (+Kyber-1024 PK) | ~1,400 B (+ML-KEM-768 PK) |
| Message overhead | ~57 B (key + counters + MAC) | ~57 B | ~80 B (key + metadata AEAD + nonce) |
| Ratchet message (with PQ key) | ~57 B | ~57 B (no PQ in ratchet) | ~1,300 B (+ML-KEM-768 PK + CT) |
| Max envelope size | Not specified | Not specified | 1 MiB (enforced) |
| Max handshake size | Not specified | Not specified | 16 KiB (enforced) |

### Bandwidth Trade-off

Aura's ratchet messages are ~1,300 bytes larger than Signal's due to the embedded ML-KEM-768 public key and ciphertext. This overhead occurs only on direction changes (when one party starts responding after receiving), not on every message in a burst. For typical messaging patterns (alternating messages), the overhead is:

- **~1.3 KB per direction change** (ML-KEM-768 PK: 1,184 B + CT: 1,088 B, partially compressed by protobuf)
- Versus **0 B per direction change** for Signal (classical DH key only: 32 B)

For bandwidth-constrained environments, KEM material could be sent out-of-band or compressed, but the default includes it inline for simplicity and security.

---

## 7. Key Hierarchy Comparison

### Signal X3DH / PQXDH

```
Identity Key (Ed25519 + X25519, long-term)
├── Signed Pre-Key (X25519, medium-term, rotated periodically)
├── One-Time Pre-Keys (X25519, ephemeral, one-use)
├── [PQXDH] Last-Resort PQ Key (Kyber-1024, medium-term)
│
└── X3DH / PQXDH  →  Master Secret (SK)
    └── HKDF  →  Root Key
        ├── DH Ratchet  →  Chain Key (sending)
        │   └── HMAC  →  Message Key  →  (enc_key, mac_key, IV)
        └── DH Ratchet  →  Chain Key (receiving)
            └── HMAC  →  Message Key  →  (enc_key, mac_key, IV)
```

Levels: **4** (SK → Root → Chain → Message)
Distinct HKDF info strings: ~3–4

### Aura

```
Master Key (BLAKE2b, optional — for deterministic derivation)
├── Ed25519 Identity Seed
├── X25519 Identity Seed
├── Signed Pre-Key Seed
├── ML-KEM-768 seed (2× BLAKE2b for 64-byte seed)
├── One-Time Pre-Key Seeds (indexed)
│
└── Hybrid X3DH  →  Root Key + Chain Key + Metadata Key
    ├── Hybrid Ratchet (X25519 + ML-KEM-768)  →  new Root + Chain + Metadata
    │   ├── Chain HKDF  →  Message Key
    │   ├── Metadata Key  →  Envelope metadata AEAD
    │   └── State HMAC Key  →  Anti-rollback HMAC
    └── Session ID (HKDF from root)
        └── Identity Binding Hash (BLAKE2b of sorted identity keys)
```

Levels: **5** (Master → Identity/Pre-keys → Root → Chain → Message)
Distinct HKDF info strings: **15**
Key separation: encryption / authentication / metadata / HMAC / identity — all separate derivations

---

## 8. State Management

| Feature | Signal | **Aura** |
|---------|--------|--------------|
| State persistence | Platform session store (abstract interface) | **Sealed export/import** (AES-GCM-SIV + state HMAC) |
| State integrity | Database-level (SQLCipher) | **State HMAC plus external counter freshness** |
| Multi-device | Sesame protocol (per-device sessions) | Single device (exportable state) |
| Session teardown | No explicit ceremony | **`destroy()` — 9-step documented key wipe** |
| Secure memory | Platform-dependent | **mlock + zeroize (guard pages on Linux)** |
| Key zeroization | Implementation-dependent | **Explicit `secure_wipe` on all error paths** |
| Export protection | N/A | KEK → DEK → state (double encryption) |
| Rollback detection | None at protocol level | HKDF-derived HMAC key, verified on import |

---

## 9. Feature Matrix Summary

| Feature | Signal X3DH | PQXDH | **Aura** |
|---------|------------|-------|--------------|
| Classical key exchange | ✅ | ✅ | ✅ |
| Post-quantum handshake | ❌ | ✅ | ✅ |
| Post-quantum ratchet | ❌ | ❌ | ✅ |
| Nonce-misuse resistant AEAD | ❌ | ❌ | ✅ |
| Metadata key rotation | ❌ | ❌ | ✅ |
| Encrypted envelope metadata | ❌ | ❌ | ✅ |
| State integrity HMAC + external counter | ❌ | ❌ | ✅ |
| Session teardown ceremony | ❌ | ❌ | ✅ |
| Secure memory (mlock) | ❌¹ | ❌¹ | ✅ |
| Shamir secret sharing | ❌ | ❌ | ✅ |
| C FFI layer | ❌² | ❌² | ✅ |
| Replay nonce cache (bounded) | ❌³ | ❌³ | ✅ |
| Constant-time DH validation | ✅ | ✅ | ✅ |
| Out-of-order delivery | ✅ | ✅ | ✅ |
| Forward secrecy (classical) | ✅ | ✅ | ✅ |
| Forward secrecy (quantum) | ❌ | ✅⁴ | ✅ |
| Post-compromise security (quantum) | ❌ | ❌ | ✅ |
| Offline deniability | ✅ | ✅ | ✅ |
| Multi-device support | ✅ | ✅ | ❌ |
| Production deployment | ✅ | ✅ | ❌⁵ |

¹ libsignal relies on platform memory management; no explicit mlock.
² libsignal has Java/Swift/TypeScript bindings but not a standalone C API.
³ Signal uses message counter + key consumption, not a separate nonce cache.
⁴ PQXDH forward secrecy against quantum applies to handshake session key only; ratchet keys are classical.
⁵ Aura is a research protocol; Signal is deployed to billions of users.

---

## 10. Threat Model Comparison

| Threat | Signal X3DH | PQXDH | **Aura** |
|--------|------------|-------|--------------|
| Passive eavesdropper (classical) | ✅ Protected | ✅ Protected | ✅ Protected |
| Active MITM (classical) | ✅ Protected (identity keys) | ✅ Protected | ✅ Protected |
| Harvest-now-decrypt-later (quantum) | ❌ Vulnerable | ⚠️ Handshake protected | ✅ **Session-secret confidentiality refreshed at directed KEM ratchets** |
| Quantum adversary (real-time) | ❌ Vulnerable | ⚠️ Handshake protected | ⚠️ **Confidentiality hedged; authentication remains Ed25519** |
| Compromised session state | ⚠️ PCS via DH ratchet | ⚠️ PCS (classical only) | ✅ **1-step classical / 2-step hybrid PCS in this schedule** |
| Nonce reuse by implementation bug | ❌ CBC leaks data | ❌ CBC leaks data | ✅ **GCM-SIV: safe** |
| State rollback attack | ❌ No detection | ❌ No detection | ✅ **State integrity plus external counter freshness** |
| Metadata traffic analysis | ⚠️ Sealed Sender (partial) | ⚠️ Sealed Sender | ⚠️ **Encrypted envelope fields + rotation; no anonymity claim** |
| Device fingerprinting (timestamps) | ❌ Not addressed | ❌ Not addressed | ✅ **Nanoseconds zeroed** |

---

## 11. Summary and Positioning

### Aura's Contributions

1. **Hybrid post-quantum confidentiality ratchet**: A compact two-party design point that adds ML-KEM-768 on direction-change ratchets, with a formal 1-step classical / 2-step hybrid PCS boundary for this schedule. Signal SPQR/Triple Ratchet and Apple PQ3 are broader modern baselines with different trade-offs.

2. **Nonce-misuse resistant AEAD**: AES-256-GCM-SIV provides a strictly stronger security guarantee than AES-256-CBC for symmetric encryption.

3. **Metadata forward secrecy**: Rotating metadata encryption keys on ratchet steps, with an old-epoch cache for out-of-order delivery. Signal's Sealed Sender addresses a different aspect of metadata privacy (sender anonymity from the server).

4. **Cryptographic state integrity**: HMAC-SHA256 over serialized state plus an external monotonic counter freshness contract, verified on import. Signal relies on database-level encryption.

5. **Explicit session teardown**: Documented 9-step key wipe ceremony with post-destroy guards on all operations.

### Trade-offs

| Aura advantage | Aura cost |
|---|---|
| Per-epoch PQ protection | ~94 µs overhead per ratchet step |
| Nonce-misuse resistance (GCM-SIV) | Slightly larger ciphertext (16-byte tag, same as GCM) |
| Metadata encryption + rotation | ~80 B per-message overhead (metadata AEAD) |
| ML-KEM-768 in ratchet | ~1.3 KB bandwidth per direction change |
| State HMAC + external counter | ~32 B storage + HMAC computation on export/import |
| Non-deniable (by design) | Loss of online deniability (deliberate) |

### Positioning Statement

Aura targets a narrow **post-quantum confidentiality gap**: moving KEM material from the initial handshake into ongoing two-party ratchet state. While Signal PQXDH protects the initial handshake, Aura studies a hybrid Double Ratchet profile with ML-KEM-768 at directed ratchet boundaries; authentication remains classical in the current artifact.

---

## References

1. Marlinspike, M. and Perrin, T. "The X3DH Key Agreement Protocol." Signal, 2016. https://signal.org/docs/specifications/x3dh/
2. Perrin, T. and Marlinspike, M. "The Double Ratchet Algorithm." Signal, 2016. https://signal.org/docs/specifications/doubleratchet/
3. Kret, E. and Schmidt, R. "The PQXDH Key Agreement Protocol." Signal, 2023. https://signal.org/docs/specifications/pqxdh/
4. NIST. "Module-Lattice-Based Key-Encapsulation Mechanism Standard (FIPS 203)." 2024.
5. Gueron, S. and Lindell, Y. "AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption." RFC 8452, 2019.
6. Shamir, A. "How to Share a Secret." Communications of the ACM, 1979.
7. Signal. "Quantum Resistance and the Signal Protocol." Blog post, September 2023.
