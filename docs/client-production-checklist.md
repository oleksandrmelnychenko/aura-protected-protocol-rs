# Client Production Checklist

Цей файл описує, що ще треба зробити на стороні клієнта перед production rollout поверх `ecliptix-protocol-rs`.

## Identity Verification

- Визначити trust model:
  - TOFU
  - explicit pinning
  - manual safety-code compare
  - directory-backed verification
- Після кожного handshake перевіряти peer, а не лише вважати сесію автоматично trusted.
- Використовувати один із двох flows:
  - `finishVerifyingPeer(...)`
  - `finish(...)` + `peerIdentity()` + `identityBindingHash()`
- Вирішити, що робити при зміні peer identity:
  - блокувати
  - попереджати
  - вимагати повторне підтвердження

## Key And State Storage

- Зберігати session/group sealed-state encryption keys у production-grade secure storage.
- Для Apple platform:
  - Keychain як базовий мінімум
  - за потреби Secure Enclave / access control
- Якщо є master seed / recovery seed:
  - окремо визначити backup policy
  - окремо визначити restore policy
  - не зберігати його поруч із звичайним app cache

## Rollback Protection

- Persist-ити `externalCounter` окремо від sealed state blob.
- Не передавати `0` в `minExternalCounter` у production restore path.
- Не скидати counter при restart/reinstall, якщо продукт підтримує trusted restore.
- На кожен новий sealed snapshot:
  - збільшити counter
  - записати blob
  - записати counter

## Session UX

- Додати screen або internal diagnostics для:
  - `peerIdentity`
  - `sessionId`
  - `identityBindingHash`
  - fingerprint display
- Визначити, чи показувати fingerprint користувачу:
  - у профілі контакта
  - у security settings
  - тільки в debug/admin mode

## Group UX

- Вирішити, чи потрібен `external join` у продукті взагалі.
- Якщо потрібен:
  - клієнт не має самостійно створювати “join by public state” без authorization artifact
  - authorization повинен бути явно отриманий від чинного учасника або через backend workflow
- Якщо не потрібен:
  - використовувати тільки `Welcome`-based onboarding
  - не expose-ити external join у product UX

## Error Handling

- Не прокидати сирі protocol errors прямо в UI.
- Мапити окремо:
  - peer verification failed
  - rollback rejected
  - session expired
  - group reinit pending
  - external join not authorized

## App Testing

- Додати app-level integration tests для:
  - verified handshake
  - peer identity mismatch
  - sealed-state restore with persisted counter
  - group add/join/update/remove
  - external join authorization flow, якщо він підтримується
- Додати smoke tests для app upgrade path, якщо є вже збережені старі state blobs.

## Minimum Client Gate

- Є production policy для peer verification.
- Є secure storage для state keys.
- Є persisted rollback counter.
- Є UX на випадок key mismatch.
- Є integration tests для handshake restore/group flows.
