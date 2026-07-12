# Security

## Reporting vulnerabilities

Please report security-sensitive issues privately (e.g. to the maintainers) rather than in public issue trackers.

## Design trade-offs and obligations

The protocol is designed for production use with clear cryptographic guarantees. The following are intentional trade-offs or application-layer obligations that auditors and integrators should be aware of.

### Sealed state anti-rollback (external counter)

Sealed session state is bound to an **external monotonic counter** in AAD, but a single persisted number is not enough to use it safely. The correct state model needs **two counters per persisted slot**:

1. `max_restored_counter`
   The highest sealed-state counter that has already been successfully restored/imported. This is the value passed as `min_external_counter` on the next restore.
2. `latest_issued_counter`
   The highest counter already used for a local sealed export. The next export must use `latest_issued_counter + 1`.

Why this matters:

- If you persist only one counter and set it equal to the newest blob's counter, you can no longer restore that newest blob because imports require `sealed_counter > min_external_counter`.
- If you persist only the previous accepted counter, you can restore the newest blob, but you no longer know what the next export counter should be after restart.

The safe pattern is therefore:

1. On export, issue `next = latest_issued_counter + 1`, seal the state with that counter, then persist the blob and update `latest_issued_counter = next`.
2. On restore, pass `max_restored_counter` as `min_external_counter`. If restore succeeds, update `max_restored_counter = sealed_counter` and also raise `latest_issued_counter` to at least that value.

The public Rust API now exposes `api::SealedStateCounterTracker` plus managed helpers for session/group/VoIP sealed-state flows, and the C/Swift surfaces expose the same model via `aura_sealed_state_counter_tracker_*` and tracker-based `*_with_tracker` sealed-state APIs, so applications do not have to hand-roll this state machine.

For crash consistency, the API also exposes a higher-level `SealedStateSlot` / `aura_sealed_state_slot_*` abstraction that stores the tracker and sealed blob together in one serialized record. This removes the "blob and tracker persisted separately" footgun.

That higher-level slot improves atomicity, but it does **not** eliminate the fundamental rollback assumption by itself. If an attacker can replace the entire serialized slot with an older serialized slot, the library still cannot distinguish that from a legitimate older snapshot unless the application also relies on trusted monotonic storage outside the slot.

Import is accepted only when `sealed_counter > min_external_counter` (strictly greater; equality is rejected as rollback) across session/group/VoIP sealed-state paths.

If the application does not enforce this, an attacker could replace the current state with an older sealed snapshot; the HMAC is valid for that snapshot, so the protocol alone cannot distinguish it. See `export_sealed_state` / `from_sealed_state` doc comments in `src/protocol/session.rs`.

### Disappearing messages (TTL)

Expiry is enforced as: `sent_timestamp + ttl_seconds > recipient SystemTime::now()`. Thus:

- A recipient who can set their system clock backward can read “disappeared” messages indefinitely.
- A sender can backdate `sent_timestamp` so that messages expire before being read, or set a far-future timestamp for a de facto infinite TTL.

This is a fundamental limitation of any disappearing-message design without a trusted time source. The protocol provides the check; the environment (clock trust) is the integrator’s responsibility.

The Rust API now exposes an injectable `interfaces::ITimeProvider`, and the core session/group/VoIP entrypoints have `*_with_time_provider` variants plus `api::AuraProtocol::new_with_time_provider(...)`. The C/Swift surfaces now expose the same capability via `aura_time_provider_manual_*`, `aura_identity_set_time_provider(...)`, and explicit `*_with_time_provider` sealed-state restore APIs. Integrators that have a server-synchronized or otherwise trusted time source should pass it explicitly instead of relying on local wall-clock reads inside the protocol.

### External join authorization freshness

External join authorizations are cryptographically bound to the exported public state and are short-lived. Freshness is enforced by the **joiner bootstrap** path as: `issued_at_unix <= now + MAX_FUTURE_TIMESTAMP_SKEW_SECS` and `now <= expires_at_unix`.

- A joiner with a badly skewed clock can reject a still-valid authorization or accept one slightly earlier/later than intended.
- The short validity window limits relay replay of previously valid `public_state + authorization` pairs, but the environment still needs a reasonably correct clock for that guarantee to hold.
- Existing members do **not** re-apply wall-clock freshness when processing an already-created `ExternalInit` Commit. They validate the commit against the exact pre-commit group state (`group_id`, `epoch`, `group_context_hash`, external init public keys, joiner identity, and authorizer signature), which preserves asynchronous/offline commit delivery.
- Operationally, ExternalInit should be treated as a same-version feature during rollout: the authorization payload now carries an explicit signed auth-format version plus additional signed bindings/timestamps, so mixed-version deployments can reject external joins until all participants are upgraded.

As with TTL enforcement, Rust integrators can inject a trusted `ITimeProvider` into the protocol/session/group/VoIP constructors, and C/Swift integrators can bind identities/restores to explicit time-provider handles, so freshness checks use a product-defined time source rather than hidden `SystemTime::now()` reads.

### Group protocol: post-compromise security per epoch

Group messages use a **sender key chain** (symmetric hash ratchet). Unlike 1:1 sessions, where each direction change runs a full X25519 + Kyber ratchet, group sender keys provide **forward secrecy** along the chain but **post-compromise security only on epoch advancement** (Commit). If a sender’s chain is compromised, all subsequent messages from that sender until the next epoch can be decrypted until a new Commit is processed. This is the same trade-off as in Signal groups and MLS (O(1) encrypt/decrypt vs per-message PCS).

### 1:1 ratchet: PCS on direction change

Post-compromise security is triggered on **direction change** (and when the message chain is exhausted). If one party sends many messages in a row without a reply (e.g. 999 messages), they all share the same ratchet epoch. Compromise of a chain key in the middle would expose subsequent messages in that batch. This matches the Signal Protocol; “per-ratchet” PQ protection is per ratchet step, not per individual message.

### Padding and traffic analysis

Payloads are padded to **64-byte blocks** (ISO/IEC 7816-4 style). Ciphertext length therefore reveals plaintext length up to a 64-byte granularity (e.g. short text vs file vs image, or language-length distributions). Stronger traffic-analysis resistance would require fixed-size cells or padding to a large fixed maximum, at a bandwidth/storage cost the protocol does not impose by default.

### Resource-exhaustion / DoS hardening limits

The library applies explicit size and cache caps to reduce CPU/memory amplification from untrusted input:

- `MAX_PROTOBUF_MESSAGE_SIZE` (1 MiB): hard cap for protobuf blobs such as `PreKeyBundle` and sealed state payloads.
- `MAX_ENVELOPE_MESSAGE_SIZE` (1 MiB): hard cap for encrypted envelope payloads before decode.
- `MAX_BUFFER_SIZE` (10 MiB): cap for large plaintext buffers (e.g. session encrypt path).
- `MAX_ONE_TIME_PRE_KEYS_PER_BUNDLE` (4096): cap on OPK count validated in a single `PreKeyBundle`.
- `MAX_INFLIGHT_HANDSHAKE_INITS` (4096): cap for uncommitted handshake replay reservations.
- FFI paths may apply additional API-level caps for specific call sites (for example, handshake message size guards), so effective limits are endpoint-dependent.

Notes for integrators:

1. Multiple limits are cumulative. A value accepted by one limit can still be rejected by another (for example, OPK count may be under `MAX_ONE_TIME_PRE_KEYS_PER_BUNDLE` while total encoded protobuf size exceeds `MAX_PROTOBUF_MESSAGE_SIZE`).
2. These limits harden the protocol layer but do not replace edge protections. Production services should still enforce transport-level body limits, timeouts, and rate limiting.

### Attachments / media encryption model

Large media is expected to use envelope encryption:

1. Generate a per-file DEK (`file_key`).
2. Encrypt file chunks with AEAD using attachment context-bound AAD.
3. Deliver only wrapped `encrypted_file_key` through the chat channel.
4. Relay/storage keeps ciphertext-only blobs and never receives plaintext DEK.

Integrator obligations:

- enforce per-file and per-chunk size limits at transport edge;
- validate manifest/chunk structure before storage/forwarding;
- avoid logging plaintext media, file keys, or decrypted thumbnails.

### Secure-memory (mlock) policy

All long-term keys (identity X25519 / Ed25519, Kyber secret keys, root keys,
sealed-state AEAD keys) are stored in `SecureMemoryHandle` allocations that
pin their pages in physical RAM via `mlock(2)` on Linux/macOS. This prevents
secrets from being written to swap and surviving a reboot on disk.

**Fail-closed policy:** If `mlock` fails (commonly: `EPERM` without
`CAP_IPC_LOCK`, `ENOMEM` exceeding `RLIMIT_MEMLOCK`, or unsupported on the
target) `SecureMemoryHandle::allocate` returns `CryptoError::AllocationFailed`
and the allocation never contains secret material. This is intentional —
silently falling back to pageable memory is a security regression.

**Deployment notes for Linux containers:**

- The pool is initialized once, on the first secure allocation. Its portable
  defaults are 16,384 × 64-byte slots plus 1,024 × 4-KiB slots (5 MiB total).
  Set `AURA_SECURE_POOL_SMALL_SLOTS` and `AURA_SECURE_POOL_LARGE_SLOTS` before
  that first allocation for the measured deployment concurrency. Pool capacity
  is fixed for the remaining process lifetime and exhaustion fails closed.
- Grant the capability: `docker run --cap-add IPC_LOCK ...` (or the k8s
  `securityContext` equivalent), or raise `RLIMIT_MEMLOCK` above the configured
  slot bytes plus page-alignment overhead.
- To explicitly opt out of the mlock requirement (for test harnesses or
  environments where swap is disabled / known-safe), build with
  `--features no-secure-memory`. This is a **compile-time** opt-in and is
  blocked in release builds by a `compile_error!`.

**Platforms:** iOS and Windows use a non-mlock inner module (iOS does not
expose `mlock`; Windows would require `VirtualLock` which is not wired up
yet). On those targets `SecureMemoryHandle` still zeroizes on drop and
benefits from platform-level memory-protection defaults, but there is no
explicit swap-prevention guarantee at the library level.
