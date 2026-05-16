# Aura ablation and sensitivity ledger

This document records the ablations that matter for the Aura paper claims. It
separates three kinds of evidence:

- implemented benchmark profiles that are safe to run in the normal codebase;
- negative/security tests that demonstrate why a component is required;
- insecure design variants that should only be evaluated in an explicit fork or
  feature-gated research branch, never as production switches.

## Summary

| Ablation / sensitivity axis | Current evidence | Status |
|---|---|---|
| KEM frequency: handshake-only, sparse, periodic, per-reply PQ | `pq_traffic_profiles` Criterion group in `benches/protocol_bench.rs` | Implemented benchmark profile |
| Missing partial ratchet material | `attack_partial_ratchet_header`, `incomplete_ratchet_header_rejected` | Negative test coverage |
| Corrupted DH/KEM ratchet material | `attack_ratchet_dh_key_forgery_rejected`, `attack_ratchet_kyber_ciphertext_forgery_rejected`, `attack_kyber_ciphertext_bitflip_ratchet` | Negative test coverage |
| Metadata-key rotation | `metadata_key_rotates_on_ratchet`, `metadata_key_differs_across_epochs`, `old_epoch_metadata_decrypts_after_rotation`, `export_import_preserves_cached_metadata_keys` | Positive invariant coverage |
| Metadata AEAD tampering | `attack_metadata_bitflip_rejected`, `attack_header_nonce_tamper_rejected`, `attack_epoch_decrement_on_advanced_session` | Negative test coverage |
| Sealed-state anti-rollback | `sealed_state_rollback_rejected_by_external_counter`, `vuln_state_rollback_forward_decryption`, sealed-state tamper/wrong-key tests | Negative and regression coverage |
| Replay persistence across sealed state | `replay_nonces_persist_across_sealed_export_import`, `replay_nonces_persist_multiple` | Positive invariant coverage |

## Safe benchmark ablation: KEM frequency

The normal benchmark suite includes a fixed 128-message, 256-byte traffic model:

```sh
cargo bench --bench protocol_bench pq_traffic_profiles
```

It compares:

- `handshake_only_pq/128x256B_unidirectional`
- `sparse_pq_chain64/128x256B_unidirectional`
- `periodic_pq_chain16/128x256B_unidirectional`
- `per_reply_pq/128x256B_alternating`

This is a sensitivity study of KEM frequency under one traffic model. It does
not claim to reproduce Signal SPQR or Apple PQ3 internals; it gives a local
protocol-family comparison with the same message count, payload size, harness,
and implementation environment.

## Security ablations that must stay negative

### Removing `new_kyber_public` from the ratchet transcript

The implementation binds the next KEM public key into the ratchet HKDF `info`
string on both send and receive. This is part of the security argument, not a
performance option.

Evidence:

- `src/protocol/session.rs` builds `augmented_info = HYBRID_RATCHET_INFO || new_kyber_pk`
  on both send and receive paths.
- `tests/attack_poc.rs::attack_partial_ratchet_header` rejects DH-only,
  KEM-ciphertext-only, and missing-new-KEM-key ratchet headers.
- `tests/integration_test.rs::incomplete_ratchet_header_rejected` rejects
  missing `new_kyber_public`.
- `tests/integration_test.rs::attack_ratchet_kyber_ciphertext_forgery_rejected`
  and `tests/attack_poc.rs::attack_kyber_ciphertext_bitflip_ratchet` verify
  rollback and recovery after forged KEM material.

An insecure fork that removes the HKDF binding may be useful for a paper
appendix, but it must not be merged as a runtime flag. A runtime flag would
create a downgrade surface.

### Reusing payload keys for metadata

Aura derives a separate metadata key per ratchet epoch. Removing this layer
would collapse protocol metadata protection into the payload layer and would
weaken the claim that message contents and envelope metadata have independent
keys.

Evidence:

- metadata ciphertext is authenticated independently from payload ciphertext;
- metadata keys rotate across ratchet epochs;
- old metadata keys are cached for delayed old-epoch delivery;
- export/import preserves cached metadata keys;
- metadata/header nonce/epoch tampering is rejected.

Primary tests:

```sh
cargo test --release --test integration_test metadata_key_rotates_on_ratchet
cargo test --release --test integration_test metadata_key_differs_across_epochs
cargo test --release --test integration_test old_epoch_metadata_decrypts_after_rotation
cargo test --release --test integration_test export_import_preserves_cached_metadata_keys
cargo test --release --test integration_test attack_metadata_bitflip_rejected
```

### Removing sealed-state anti-rollback

Sealed state is not just encrypted serialization. The rollback counter is part
of the operational security boundary: an old but authentic state snapshot must
not silently replace a newer one.

Evidence:

- `sealed_state_rollback_rejected_by_external_counter` rejects older snapshots
  under a newer counter floor;
- `vuln_state_rollback_forward_decryption` documents the prior failure mode and
  its fixed behavior;
- replay-nonce persistence tests verify that restored state does not forget
  already accepted messages.

Primary tests:

```sh
cargo test --release --test integration_test sealed_state_rollback_rejected_by_external_counter
cargo test --release --test integration_test replay_nonces_persist_across_sealed_export_import
cargo test --release --test integration_test replay_nonces_persist_multiple
cargo test --release --test attack_poc vuln_state_rollback_forward_decryption
```

## How to publish a full ablation appendix

A full appendix can be produced without weakening the production crate:

1. Create a temporary research branch with explicit feature names such as
   `insecure-ablation-no-kem-pk-info` or `insecure-ablation-shared-metadata-key`.
2. Ensure each insecure feature is compile-time only and cannot be enabled by
   downstream applications accidentally.
3. Run the same command set as the production artifact:

```sh
./scripts/reproduce-paper-artifact.sh quick
cargo bench --bench protocol_bench pq_traffic_profiles
```

4. Publish the branch name, commit hash, failing/passing test delta, benchmark
   logs, and `SHA256SUMS`.
5. Keep the production paper claims tied to the normal branch only.

## Current publication status

The production repository now contains:

- one safe KEM-frequency benchmark family;
- negative tests for ratchet downgrades and KEM/DH forgery;
- positive tests for metadata-key rotation and old-epoch delivery;
- sealed-state and replay persistence tests;
- a clear rule that intentionally insecure ablations belong in isolated
  research branches, not production configuration.

The remaining optional work is to publish a separate appendix with measured
results from intentionally insecure forks. That appendix would be useful for
reviewers, but it is not required for the production artifact to be internally
consistent.
