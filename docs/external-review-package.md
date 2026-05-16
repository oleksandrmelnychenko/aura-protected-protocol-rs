# Aura external review package

This document defines the review package for an independent cryptographic,
formal-methods, and implementation review of the Aura paper artifact. It is not
a substitute for an external review; it is the checklist that makes such a
review concrete and repeatable.

## Review scope

Review the two-party Aura protocol as described by:

- `docs/aura-paper.tex` and `docs/aura-paper.pdf`
- `docs/security-proof.tex`
- `formal/tamarin/aura_handshake.spthy`
- `formal/tamarin/aura_ratchet.spthy`
- `formal/proverif/aura.pv`
- `src/protocol/handshake.rs`
- `src/protocol/session.rs`
- `src/crypto/kyber_interop.rs`
- `tests/paper_vectors.rs`
- `tests/attack_poc.rs`
- `benches/protocol_bench.rs`
- `docs/artifact-reproducibility.md`
- `docs/ablation-study.md`
- `docs/reference-audit.md`

The group protocol, VoIP path, Swift wrapper, and relay integration are useful
implementation context, but they are outside the main paper theorem scope unless
a review explicitly opts into them.

## Non-claims

The paper and implementation do not claim:

- post-quantum signature security; identity and signed pre-key signatures use
  Ed25519;
- protection against malicious or compromised key distribution without
  out-of-band identity verification;
- a machine-checked proof for the byte-level Rust implementation;
- side-channel resistance beyond the guarantees of the selected primitives and
  provider APIs;
- FIPS validation of the concrete cryptographic provider;
- deployed operational maturity comparable to Signal or Apple iMessage;
- group-protocol security under the two-party theorems;
- ProVerif proofs for Q5 and Q6, which are documented as DH-overapproximation
  limitations and covered by Tamarin plus game-based arguments instead.

## Claims to review

| Claim | Evidence |
|---|---|
| Hybrid X3DH derives a shared root under the either-or classical/PQ combiner argument. | `docs/aura-paper.tex`, `docs/security-proof.tex`, `src/protocol/handshake.rs`, Tamarin handshake lemmas |
| The KEM public key used for the next ratchet epoch is bound into HKDF `info`. | `src/protocol/session.rs`, `docs/aura-paper.tex`, paper equations and proof-to-code map |
| A receiver rejects partial ratchet headers and rolls back state on malformed ratchet envelopes. | `src/protocol/session.rs`, `tests/attack_poc.rs` |
| Classical PCS is recovered after one honest DH ratchet step; full hybrid PCS takes two directed hybrid steps after compromise. | Theorem 4 in the paper, `docs/security-proof.tex`, Tamarin ratchet model |
| Metadata encryption uses an independent per-epoch key rather than reusing payload message keys. | `src/protocol/session.rs`, paper AEAD equations, tests covering encrypted metadata |
| Replay protection, skipped-key handling, and sealed-state rollback constraints match the security claims. | `src/protocol/session.rs`, `tests/attack_poc.rs`, artifact vectors |
| Benchmark comparisons use one traffic model for handshake-only, sparse, periodic, and per-reply PQ profiles. | `benches/protocol_bench.rs`, `pq_traffic_profiles` Criterion group |
| Ablation claims do not rely on production downgrade switches. | `docs/ablation-study.md`, negative ratchet/metadata/sealed-state tests |
| References and URLs are real, cited, and not bibliography padding. | `docs/reference-audit.md` |

## Assumption ledger

| Assumption | Where used | Reviewer question |
|---|---|---|
| Gap-CDH over X25519-style DH | Hybrid combiner, AKE, FS, PCS | Are the reductions and abstractions stated at the right level for the implemented X25519 use? |
| ML-KEM-768 IND-CCA2 | Handshake KEM and hybrid ratchet KEM | Is the code using the KEM API in a way consistent with the proof model? |
| HKDF dual-PRF behavior | Classical/PQ combiner and ratchet key schedule | Is the salt/IKM asymmetry justified and consistently implemented? |
| AES-256-GCM-SIV MRAE/INT-CTXT | Payload and metadata AEAD | Are nonce construction and associated data sufficient for the stated bounds? |
| Ed25519 SUF-CMA | Identity and signed pre-key authentication | Are PQ-signature limitations clearly separated from KEM security claims? |
| Out-of-band identity verification | TOFU/safety-number trust model | Is the key-distribution boundary explicit enough for the claims? |
| Secure local randomness and state storage | Key generation, nonces, sealed state | Are implementation limitations stated without overstating proof coverage? |

## Required reproduction commands

Run from the repository root:

```sh
git rev-parse HEAD
./scripts/reproduce-paper-artifact.sh quick
./scripts/reproduce-paper-artifact.sh paper
cargo bench --bench protocol_bench pq_traffic_profiles
```

If Tamarin Prover and ProVerif are installed:

```sh
./scripts/reproduce-paper-artifact.sh formal
```

For any generated artifact directory:

```sh
cd artifact-output/<timestamp>-<mode>
sha256sum -c SHA256SUMS
```

## Review output

Record the review result in a GitHub issue using the `External Review` template
or in release notes with equivalent fields:

| Field | Required content |
|---|---|
| Reviewer | Name, affiliation or independent status, and review area |
| Commit | Exact git commit reviewed |
| Artifact logs | CI artifact links or local artifact directory hashes |
| Scope | Cryptographic proof, formal models, implementation, benchmark methodology, references, or a subset |
| Findings | Blocking issues, non-blocking issues, questions, and accepted limitations |
| Resolution | Follow-up commits, rejected findings with rationale, or accepted future work |

## Completion criterion

The remaining submission-hardening gap is closed only when at least one
independent reviewer has examined the scope above and the repository records:

- the reviewed commit;
- the artifact hashes or CI artifact links;
- the review findings;
- the author response or follow-up commits.
