# AURA / Relay / Swift Alignment Contract

Цей документ фіксує інваріанти інтеграції між:

- `aura-protected-protocol-rs` (AURA core + FFI),
- `aura-auth-relay` (gateway/relay),
- iOS Swift клієнтом (`Aura-iOS`).

Мета: щоб production інтеграція не мала "тихих" розходжень між протоколом, relay та клієнтом.

## 1) Handshake + replay guard (critical ordering)

Для responder flow діє обов'язковий порядок:

1. decode `HandshakeInit`;
2. резерв replay guard;
3. commit replay guard;
4. лише потім consume OPK.

Чому це важливо:

- якщо distributed replay commit падає, OPK не має "згоріти";
- повторна спроба тим самим `handshake_init` після recovery інфраструктури лишається можливою;
- клієнт і relay не розходяться в очікуваннях щодо prekey lifecycle.

Цей інваріант покритий інтеграційним тестом у `tests/integration_test.rs`.

## 2) Relay validation path must be strict

Для групового ingress рекомендований і узгоджений шлях:

- `validate_crypto_envelope(...)`
- `validate_commit_for_relay_strict(...)` і `validate_group_message_for_relay_strict(...)` (з обов'язковим sender identity binding з auth-контексту)

`*_strict`-виклики обов'язково біндять sender identity до автентифікованого transport/session контексту, а не до незахищених полів payload.

Це must-have для:

- anti-spoof sender binding,
- коректного roster enforcement,
- узгодженого Shield mode behavior у групових контекстах.

## 3) Sealed state anti-rollback contract (AURA <-> Relay <-> Swift)

Для `session/group serialize sealed` діє єдиний контракт:

- `external_counter` при serialize має бути `> 0`;
- `min_external_counter` при deserialize є мінімально дозволеним durable значенням; рівність дозволена для ідемпотентного re-restore того самого blob;
- counter зберігається окремо від sealed blob;
- rollback на менший counter має фейлити як replay.

На стороні Swift це означає:

- не скидати counter на cold start/foreground;
- не тримати counter лише в RAM.

На стороні relay/gateway це означає:

- не відновлювати сесію зі старішого snapshot;
- persist-ити progression ratchet/session state без "тихого" downgrade шляху.

## 4) Handshake verification expectations in Swift

Клієнтська інтеграція має завершувати handshake з peer verification policy:

- або `finishVerifyingPeer(...)`,
- або `finish(...)` + explicit check через `peerIdentity()` / `identityBindingHash()`.

Криптографічно валідний handshake без app-level identity policy не вважається production-complete.

Деталі: `docs/swift-session-verification.md`.

## 5) Group/Shield scope consistency

Shield mode є властивістю групової сесії та roster/policy контексту.

Отже integration policy:

- не проєктувати shield semantics на non-group або unbound контексти;
- у relay валідувати group payload лише після `group_id`/epoch/roster binding;
- у client UI/API показувати shield state тільки там, де є валідний group binding.

## 6) VoIP relay hardening alignment

Для legacy VoIP signaling relay має йти через:

- `validate_voip_envelope(...)`,
- `process_voip_signal(...)` з `VoipCallStore`.

Це узгоджує behavior з клієнтським очікуванням:

- state transitions валідні,
- адресація peer не підміняється,
- прострочені/неконсистентні сигнали не форвардяться.
- `VoipCallStore` робить atomic compare-exchange per `call_id`, щоб lifecycle не роз'їжджався між конкурентними relay workers / instances.

## 7) Release sync checklist (short)

Перед release/merge перевірити:

- README та `docs/relay-server.md` не містять legacy API назв замість strict path;
- Swift guide і FFI guide описують `external_counter` invariant;
- Swift guide і FFI guide описують `AURA_ERROR_BUSY`, forward-only manual clock та nulling destroy semantics для low-level handle-ів;
- relay integration не оминає strict validation виклики;
- handshake replay/OPK invariant не порушено.
- для VoIP relay у multi-instance режимі є пер-`call_id` атомарність у store (lock/CAS/transaction).
