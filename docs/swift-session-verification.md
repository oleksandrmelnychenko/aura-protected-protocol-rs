# Swift Session Verification

Цей файл описує рекомендований verification flow для Swift wrapper-ів Ecliptix Protected Protocol після встановлення 1:1 сесії.

## Що перевіряти після handshake

Після успішного handshake у вас є криптографічно валідна сесія, але застосунок все одно має вирішити:

- хто саме є peer;
- чи цей peer збігається з очікуваним контактом;
- чи треба запінити / порівняти / показати fingerprint користувачу.

Для цього Swift API тепер надає:

- `EppSession.peerIdentity()`
- `EppSession.localIdentity()`
- `EppSession.identityBindingHash()`
- `EppSession.sessionId()`
- `EppSession.verificationSnapshot()`
- `EppHandshakeInitiator.finishVerifyingPeer(...)`
- `EppHandshakeResponder.finishVerifyingPeer(...)`

## Рекомендований flow

### Варіант 1: Верифікація в одному кроці

Якщо застосунок уже знає очікувану identity peer-а поза handshake:

```swift
let (initiator, handshakeInit) = try EppHandshakeInitiator.start(
    identity: aliceIdentity,
    peerPrekeyBundle: bobBundle
)

// ... send handshakeInit, receive handshakeAck ...

let expectedPeer = try bobIdentity.sessionIdentity()
let session = try initiator.finishVerifyingPeer(
    handshakeAck: handshakeAck,
    expectedPeerIdentity: expectedPeer
)
```

Це safest path для застосунку, бо peer verification не забувається після `finish()`.

### Варіант 2: Завершити handshake, потім окремо перевірити

```swift
let session = try initiator.finish(handshakeAck: handshakeAck)

let peer = try session.peerIdentity()
let binding = try session.identityBindingHash()
let sessionId = try session.sessionId()

if !peer.matches(
    ed25519PublicKey: expectedEd25519,
    x25519PublicKey: expectedX25519
) {
    throw EppError.handshake("Peer identity verification failed")
}
```

Цей варіант корисний, якщо застосунок хоче:

- окремо показати verification UI;
- зберегти fingerprint;
- побудувати TOFU flow;
- логувати `sessionId` або `identityBindingHash`.

## Що таке fingerprint

У Swift wrapper-і fingerprint зараз представлений через hex-рядки публічних ключів:

- `EppSessionIdentity.ed25519FingerprintHex`
- `EppSessionIdentity.x25519FingerprintHex`
- `EppIdentity.ed25519FingerprintHex()`
- `EppIdentity.x25519FingerprintHex()`

Це зручно для:

- TOFU;
- pinning;
- ручного compare між пристроями;
- security/settings screen.

Приклад:

```swift
let peer = try session.peerIdentity()
print("Peer Ed25519:", peer.ed25519FingerprintHex)
print("Peer X25519:", peer.x25519FingerprintHex)
```

## Що таке identityBindingHash

`identityBindingHash()` повертає 32-байтовий authenticated binding між локальною та віддаленою identity, сформований native протоколом.

Це не заміна peer identity fingerprint, а додатковий артефакт для:

- audit logging;
- TOFU metadata;
- session-level verification;
- перевірки, що обидві сторони бачать ту саму established identity relation.

## Verification Snapshot

Якщо застосунку зручно дістати все в одному виклику:

```swift
let snapshot = try session.verificationSnapshot()

print(snapshot.sessionId as NSData)
print(snapshot.identityBindingHash as NSData)
print(snapshot.peerIdentity.ed25519FingerprintHex)
```

`EppSessionVerificationSnapshot` збирає:

- `sessionId`
- `identityBindingHash`
- `localIdentity`
- `peerIdentity`

## Metadata після decrypt

Якщо потрібна не тільки plaintext, а й envelope metadata:

```swift
let result = try session.decryptWithMetadata(encryptedEnvelope: envelope)
print(result.metadata.envelopeType)
print(result.metadata.envelopeId)
print(result.metadata.messageIndex)
```

Це preferred path замість ручного розбору raw metadata bytes.

## External Join у Swift

Для group external join тепер потрібен authorization artifact від чинного учасника:

```swift
let authorization = try group.authorizeExternalJoin(
    joinerIdentity: joinerIdentity,
    credential: credential
)

let (joinedGroup, commit) = try EppGroupSession.joinExternal(
    identity: joinerIdentity,
    publicState: publicState,
    authorization: authorization,
    credential: credential
)
```

Тобто одного `publicState` більше недостатньо.

## Важливе зауваження про shutdown

`EcliptixProtectedProtocol.shutdown()` збережений для API symmetry, але поточна native реалізація не робить значущого teardown.

Не треба будувати критичну логіку безпеки навколо цього виклику.

## Що ще треба для production build

Нижче не про сам cryptographic core, а про речі, які треба зробити навколо нього перед реальним релізом застосунку.

### 1. Зафіксувати app-level policy verification

Потрібно вирішити, який саме trust model використовує застосунок:

- TOFU
- explicit pinning
- compare safety codes між пристроями
- directory-backed identity verification

Сам протокол тепер дає:

- `peerIdentity()`
- `identityBindingHash()`
- fingerprint helpers
- `finishVerifyingPeer(...)`

Але продакшен застосунок має сам визначити:

- коли peer вважається trusted;
- де зберігати pinned identity;
- що робити при зміні ключа;
- який UX показувати користувачу при mismatch.

### 2. Зберігати rollback counter поза session state

Для sealed session/group state обов'язково потрібне зовнішнє монотонне значення:

- `externalCounter` при serialize
- `minExternalCounter` при deserialize

У production це значення треба зберігати в durable storage окремо від sealed blob.

Не можна:

- завжди передавати `0`;
- скидати counter при перевстановленні app state;
- зберігати counter тільки в RAM.

### 3. Використати безпечне сховище ключів у застосунку

Потрібно визначити, де саме зберігаються:

- sealed session state key
- sealed group state key
- identity seed / master key, якщо він є

Для Apple platform production path зазвичай означає:

- Keychain для секретів
- optional Secure Enclave / access control policy
- окремі правила для backup / device migration

### 4. Підтвердити server-side policy для external join

Тепер external join вимагає authorization artifact від чинного учасника.

Перед релізом треба вирішити:

- хто саме має право видавати authorization;
- як relay/backend перевіряє допустимість такого workflow;
- чи external join взагалі дозволений у продукті;
- чи треба додатково логувати/ревокати authorizations.

Якщо продукту external join не потрібен, найкращий production path:

- не використовувати його в app flow;
- залишити тільки `Welcome`-based onboarding.

### 5. Перезібрати release artifacts

Після hardening треба заново згенерувати й перевірити:

- Rust library release build
- C headers, які реально ship-яться
- XCFramework / staticlib artifacts
- Swift package / app integration

Особливо важливо переконатися, що release artifact не використовує старі checked-in generated files.

### 6. Додати app-level integration tests

Repo-level Rust/FFI tests уже зелені, але для production build ще бажано мати:

- Swift integration tests для verified handshake flow
- app-level tests для TOFU/pinning
- tests для sealed-state restore з реальним persisted counter
- tests для group external join authorization flow
- tests для upgrade/migration зі старих локальних даних, якщо такий сценарій підтримується

### 7. Зробити release-mode verification у CI

Бажано мати окремий pipeline, який проганяє:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- release build артефактів
- Swift/Xcode build smoke test

Якщо ship-иться XCFramework, CI має перевіряти саме його, а не тільки Rust crate локально.

### 8. Задокументувати breaking changes для інтеграторів

Через hardening змінилась модель використання:

- default group behavior тепер hardened
- external join тепер вимагає authorization
- Swift verification flow тепер має recommended post-handshake steps
- FFI contracts для частини функцій змінені

Перед production rollout це треба винести в release notes / migration notes для всіх клієнтів, які інтегрують бібліотеку.

## Мінімальний production checklist

- Вибрати trust model: TOFU / pinning / manual verify.
- Реально використовувати `finishVerifyingPeer(...)` або еквівалентну перевірку.
- Persist-ити rollback counter окремо від sealed state.
- Зберігати state encryption keys у production-grade secure storage.
- Вирішити, чи external join дозволений у продукті.
- Перезібрати XCFramework / headers / release artifacts.
- Прогнати release CI для Rust + Swift integration.
- Описати breaking changes для інтеграторів.
