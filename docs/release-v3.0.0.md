# Aura Protected Protocol v3.0.0

**Status:** Breaking change release — security remediation.

**Not wire-compatible with v2.x.** `PROTOCOL_VERSION` and `GROUP_PROTOCOL_VERSION`
both move from 1 to 2, so a v2 peer is rejected with an explicit version error
rather than an opaque decryption failure. There is no in-place migration: v2
sessions, envelopes, group commits and sealed state do not load on v3.

## Why this release exists

A deep security review found two remotely-exploitable defects, both reproduced
with working proof-of-concept tests, plus nine smaller issues. Every fix ships
with a regression test that fails when the fix is reverted.

## Security fixes

### The ratchet tree hash now binds leaf identity

`compute_node_hash_inner` covered only a node's index, a populated flag and its
X25519/Kyber public keys. The occupant of a leaf — credential and long-term
Ed25519/X25519/Kyber identity keys — was not hashed at all, and `from_proto`
accepts any key package that is merely self-signed and whose leaf keys match the
node's.

A relay forwarding `GroupPublicState` (which carries no signature) could
therefore mint a key package over a victim's public leaf keys, substitute its own
identity keys under the victim's credential, and leave `tree_hash` byte-identical
— so `group_context_hash` matched, the issuer's external-join authorization still
verified, and the joiner installed the forged roster. A malicious committer doing
the same inside a Welcome additionally gains message-attribution forgery.

Leaf nodes now absorb the credential, all three identity keys and the key package
signature, mirroring RFC 9420's `LeafNodeHashInput`. Node and parent hashes
length-prefix every variable-length field, and each node hash carries a
leaf/parent/blank domain label.

### `previous_chain_length` is authenticated, and a saturated key cache heals

The field was cleartext, excluded from both AEAD associated-data blocks, and
consumed by `skip_old_chain_keys` before authentication. A relay could raise it
to 1000 on a genuine ratchet envelope; the receiver derived and cached that many
keys and the message still authenticated, so nothing rolled back. The cache was
then pinned at `MAX_SKIPPED_MESSAGE_KEYS`, and that was terminal: every later gap
and every later genuine ratchet failed with "Message key cache overflow", and
`export_sealed_state` persisted the state so a restart did not clear it. A
well-behaved peer could reach the same state by sending a chain that never
arrived.

Both AADs now carry the field as a presence byte plus value — the presence byte
matters because `Some(0)` is a real wire value. Skipped keys gained the epoch-age
eviction the metadata cache already had, and capacity reservation evicts
oldest-first instead of erroring.

### Other fixes

- **Franking** commitments are framed unambiguously (domain label, version,
  content type, length-prefixed fields) and now bind the seal key and nonce, so a
  report for a sealed message can actually open the payload. Previously a
  reporter could re-split `content || sealed_content` and "prove" the sender sent
  any prefix.
- **Relay** external-join commits are validated against the authorization blob —
  format version, group id, epoch, joiner binding and the authorizer's Ed25519
  signature — instead of only checking that the field was non-empty.
- **One-time prekeys** no longer collide: `replenish` used to restart its ID
  counter at 2 and re-issue IDs already in the pool under different public keys.
- **`aura_group_join`** consumes the key-package secrets handle as its header
  always promised; it previously leaked two mlock'd private keys per join.
- **VoIP** shield-mode sealed state restores correctly; the shielded root was
  being stored and then re-shielded on restore, silently killing the call.
  `VOIP_PROTOCOL_VERSION` moves to 2 and `VoipSessionState` gained a
  `state_version`, because the meaning of the stored root changed and the blob
  previously carried no discriminator at all.
- **Attachments** bound `chunk_count` at manifest validation, and chunk progress
  is a bitmap rather than an O(n²) vector scan.
- **Sealed-state export** zeroizes the staged skipped-message and cached-metadata
  keys instead of freeing ~35 KB of cleartext key material onto the general heap.

## API changes

- `aura_group_verify_franking` takes `content_type`, `sealed_nonce` and
  `seal_key`. All three come straight off `AuraGroupDecryptResult`.
- `aura_group_get_member_role` / `aura_group_set_member_role` are **removed**.
  They always returned an error — roles were never protocol-authoritative.
- `aura_group_get_member_key_package` is **added**: the authenticated KeyPackage
  at an active member leaf. Its documented guarantee only became true with the
  tree-hash fix above.
- `aura_protocol_version()` and `aura_group_protocol_version()` are **added**, so
  a host can pre-flight wire compatibility instead of discovering a mismatch as a
  decrypt failure. `aura_version()` still reports the semver string.
- Eleven functions that were already exported but undeclared are now documented
  in the public headers, and `ffi_exports_match_public_headers` fails the build on
  any future drift.
- `ChunkProgress.completed_chunks` is replaced by `completed_bitmap`; the old
  field number is reserved.
- `AURA_API_VERSION_MAJOR` is 3 and `AURA_LIBRARY_VERSION` is `"3.0.0"`.

## Migration

There is none, by design. Rebuild clients against the new package; they will
generate incompatible session, group and VoIP state. Delete persisted v2 blobs —
they are rejected with an explicit version error, not silently misread.
