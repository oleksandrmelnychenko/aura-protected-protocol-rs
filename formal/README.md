# Aura Protocol — Formal Verification Models

Machine-checked formal verification of the Aura Protection Protocol,
complementing the game-based security proofs in `docs/security-proof.tex`.

## Verification Results

### Tamarin Prover — Handshake Model (6/6 verified, 7.07s)

| Lemma | Result | Steps |
|-------|--------|-------|
| `session_key_secrecy` | **verified** | 27 |
| `mutual_authentication` | **verified** | 10 |
| `responder_authentication` | **verified** | 20 |
| `forward_secrecy_hybrid` | **verified** | 33 |
| `key_confirmation` | **verified** | 6 |
| `session_exists` | **verified** | 11 |

### Tamarin Prover — Ratchet Model (4/4 verified, 0.42s)

| Lemma | Result | Steps |
|-------|--------|-------|
| `pcs_sender_compromise` | **verified** | 11 |
| `ratchet_key_secrecy` | **verified** | 8 |
| `key_agreement` | **verified** | 11 |
| `ratchet_exists` | **verified** | 5 |

### ProVerif — Active Proof-Scope Model (4/4 discharged)

| Query | Result | Notes |
|-------|--------|-------|
| `kem_shared_secret_secrecy` | **true** | Phase-0 query bound to the fresh KEM shared secret feeding the hybrid root |
| `authentication` | **true** | Initiator completion implies responder acceptance on the same root |
| `message_secrecy` | **true** | Phase-0 encrypted-payload secrecy |
| `honest_message_integrity` | **true** | If the honest challenge plaintext is received, it was sent under the same endpoints and root |

Two stress obligations are documented but not counted as discharged claims:
injective authentication does not terminate in the default four-DH ProVerif
model within the artifact budget, and raw KEM-secret secrecy after KEM-SK
reveal is false by KEM decapsulation semantics. Hybrid-root forward secrecy is
covered by the reduction proof and Tamarin abstraction rather than by that raw
secret query.

### ProVerif — Group Scoped Model (6/6 discharged)

| Query | Result | Notes |
|-------|--------|-------|
| `path_secret` secrecy | **true** | Fresh TreeKEM path secret is not learned from the hybrid path wrapper |
| `prev_init_secret` secrecy | **true** | Previous init-secret contribution remains secret in the scoped epoch transition |
| `app_secret` secrecy | **true** | In-epoch application challenge remains confidential |
| `CommitAccepted => CommitCreated` | **true** | Accepted commit matches an honest policy-bound commit event |
| `MessageAccepted => MessageSent` | **true** | Accepted challenge message matches an honest send under the same epoch key |
| `FrankingVerified => FrankingIssued` | **true** | Verified disclosure corresponds to an issued franking tag |

The group model is deliberately scoped to one accepted epoch transition and one
application message. It is not a full asynchronous MLS proof: proposal
concurrency, arbitrary tree schedules, delivery-service interleavings, and
multi-device state remain separate proof work.

## Models

| File | Tool | What it verifies |
|------|------|------------------|
| `tamarin/aura_handshake.spthy` | Tamarin | Hybrid X3DH: secrecy, mutual auth, forward secrecy, key confirmation |
| `tamarin/aura_ratchet.spthy` | Tamarin | Hybrid ratchet: PCS, key agreement, secrecy |
| `tamarin/aura.spthy` | Tamarin | Full combined model (reference only — non-terminating due to DH complexity) |
| `proverif/aura.pv` | ProVerif | Handshake KEM-secret secrecy, non-injective authentication, message secrecy, honest-message delivery integrity; injective-auth/raw-KEM stress limits documented |
| `proverif/aura_group.pv` | ProVerif | Scoped group epoch/message model: hybrid path wrapping, policy-bound confirmation, message integrity, and franking accountability |

## Design Decisions

### Tamarin Model Decomposition

The full combined model (`aura.spthy`) with 13+ custom functions and
the DH equational theory causes intractable source saturation in Tamarin
(>170 min without progress). Following the approach of Signal (EUROCRYPT 2020)
and Apple PQ3 (USENIX Security 2025), we decompose into:

1. **Handshake model** — Uses `builtins: diffie-hellman` with 2 DH operations
   (IK×SPK + EK×IK) modeling the core X3DH. Combined `!Keys` fact prevents
   cross-instance mismatches. Compromise hierarchy: `Reveal_Classical` (DH keys
   only) and `Reveal_All` (all keys including Kyber SK).

2. **Ratchet model** — Abstracts DH as a classical KEM (same PCS semantics).
   Terminal single-step model avoids unbounded backward search. Setup-time
   compromise eliminates state-loop non-termination. Session ID binding
   ensures key agreement within same session.

### Forward Secrecy

The `forward_secrecy_hybrid` lemma captures the model's hybrid secrecy
scenario: classical-only compromise (DH keys) after a session does not reveal
the session key while the Kyber secret key remains undisclosed. The paper's
forward-secrecy theorem is narrower for later disclosure of long-term KEM
secret keys: classical FS is carried by erased DH ephemerals, while the initial
KEM component is HNDL protection unless its secret key is later disclosed.

## Prerequisites

### Tamarin Prover (>= 1.10)

Pre-built binaries are available at https://github.com/tamarin-prover/tamarin-prover/releases

```bash
# macOS
brew install tamarin-prover

# Linux (pre-built binary)
sudo apt-get install -y maude
curl -fsSL https://github.com/tamarin-prover/tamarin-prover/releases/download/1.10.0/tamarin-prover-1.10.0-linux64-ubuntu.tar.gz \
  -o /tmp/tamarin.tar.gz
tar xzf /tmp/tamarin.tar.gz -C /tmp
sudo install /tmp/tamarin-prover /usr/local/bin/

# Or see https://tamarin-prover.com/manual/master/book/002_installation.html
```

### ProVerif (>= 2.05)

```bash
# macOS
brew install proverif

# Linux
opam install proverif
```

## Running

```bash
# Verify all models
make all

# Tamarin handshake only (6 lemmas, ~7s)
make handshake

# Tamarin ratchet only (4 lemmas, <1s)
make ratchet

# ProVerif (4/4 proof-scope queries discharged; stress obligations documented)
make proverif

# Group ProVerif (6/6 scoped queries discharged)
make proverif-group
```

## Security Properties

### Handshake Properties (Theorems 2-3)

- **Handshake secrecy** — Fresh KEM shared secret feeding the hybrid root in the no-compromise phase
- **Mutual authentication** — Initiator-responder bilateral authentication
- **Responder authentication** — Symmetric authentication guarantee
- **Hybrid forward secrecy** — Classical-only compromise after session doesn't reveal key
- **Key confirmation** — Same-session parties derive identical session key
- **Session exists** — Reachability / sanity check

### Ratchet Properties (Theorems 4-6)

- **PCS sender compromise** — Ratchet key secure despite sender state compromise
- **Ratchet key secrecy** — Ratchet key secret absent any compromise
- **Key agreement** — Both parties derive same ratchet root key
- **Ratchet exists** — Reachability / sanity check

### Group Scoped Properties

- **Hybrid path secrecy** — Fresh path material remains hidden under the hybrid X25519 + ML-KEM wrapper
- **Policy-bound commit authentication** — Accepted commits correspond to matching honest policy-bound commit events
- **Message integrity** — Accepted in-epoch challenge messages correspond to honest sends under the same epoch key
- **Franking accountability** — A verified franking disclosure corresponds to an issued franking tag

## References

- Cohn-Gordon et al., "A Formal Security Analysis of the Signal Messaging Protocol" (EUROCRYPT 2020)
- Brendel et al., "Post-quantum Security of the Signal Protocol" (PQCrypto 2020)
- Hashimoto, "Post-quantum Authenticated Key Exchange from X3DH" (ASIACRYPT 2021)
- Apple, "iMessage with PQ3: Formal Verification" (USENIX Security 2025)
- Bhargavan et al., "Post-Quantum Signal: PQXDH Formal Analysis" (USENIX Security 2024)
