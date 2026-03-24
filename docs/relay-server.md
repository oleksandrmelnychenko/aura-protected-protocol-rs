# Relay (сервер) — API та що викликати

Сервер (relay) не дешифрує вміст повідомлень. Він перевіряє формат, маршрутизує по `group_id` та зберігає/доставляє події. Усі функції relay API знаходяться в модулі `ecliptix_protocol::api::relay` (Rust).

## Що передає клієнт на сервер

- **1:1:** зашифрований envelope (SecureEnvelope) — непрозорий blob; сервер лише пересилає його одержувачу.
- **Групи:** CryptoEnvelope з полями:
  - `sender_device_id` — ідентифікатор пристрою відправника (не порожній, до 16 байт)
  - `payload_type` — тип: 1:1 повідомлення, GroupMessage, GroupCommit тощо
  - `encrypted_payload` — зашифрований вміст (для груп — GroupMessage або GroupCommit)
  - `group_id` — для групових повідомлень/комітів (обов’язковий)

Сервер приймає байти CryptoEnvelope (protobuf), валідує їх і далі використовує функції нижче.

## Валідація вхідних даних

### 1. Перевірка CryptoEnvelope (обгортка всіх типів)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `relay::validate_crypto_envelope(envelope_bytes)` | `envelope_bytes: &[u8]` — сирі байти CryptoEnvelope | `Result<CryptoEnvelope, ProtocolError>` |

Перевіряє: розмір, наявність `sender_device_id`, вказаний `payload_type`, непорожній `encrypted_payload`, для груп — наявність `group_id`. Після успіху можна використовувати `envelope` для маршрутизації та отримання одержувачів.

### 2. Валідація Commit (зміна складу групи)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `relay::validate_commit_for_relay_strict(commit_bytes, roster, expected_sender_identity_ed25519)` | `commit_bytes` — сирі байти GroupCommit, `roster` — поточний `GroupRoster`, `expected_sender_identity_ed25519` — ідентичність з auth-контексту (обовʼязково) | `Result<RelayCommitInfo, ProtocolError>` |

Перевіряє: epoch = roster.epoch + 1, committer є членом, `group_id` збігається з roster, є `update_path`, а також Ed25519 підпис комітера. У `RelayCommitInfo`: `committer_leaf_index`, `new_epoch`, `added_identities`, `removed_leaves`.

**Що передавати:** Сервер зберігає по одному `GroupRoster` на групу (group_id, epoch, список членів). Перед прийняттям коміту викликає `validate_commit_for_relay_strict`; після успіху застосовує зміни до roster (див. нижче).

### 3. Валідація групового повідомлення (Application)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `relay::validate_group_message_for_relay_strict(message_bytes, roster, sender_leaf_index, expected_sender_identity_ed25519)` | `message_bytes` — сирі байти GroupMessage (application content), `roster` — поточний roster групи, `sender_leaf_index` та `expected_sender_identity_ed25519` — з auth-контексту (обовʼязково) | `Result<(), ProtocolError>` |

Перевіряє: версію протоколу, `group_id` та `epoch` збігаються з roster, контент — application, Ed25519 підпис відправника і (за потреби) binding до очікуваної identity.

### 4. Валідація Key Package (зберігання / Add)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `relay::validate_key_package_for_storage(key_package_bytes)` | `key_package_bytes: &[u8]` | `Result<GroupKeyPackage, ProtocolError>` |

Перевіряє версію протоколу та розміри ключів. Викликати перед збереженням key package (наприклад, для пропозиції Add у Commit).

## Маршрутизація та одержувачі

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `relay::route_crypto_envelope(envelope, roster)` | розшифрований `CryptoEnvelope`, `roster` групи | `Result<Vec<u8>, ProtocolError>` — `group_id` для роутингу |
| `relay::commit_recipients(roster, committer_leaf_index)` | поточний roster, leaf комітера | `Vec<u32>` — leaf indices усіх, крім комітера (кому надіслати Commit) |
| `relay::message_recipients(roster)` | roster | `Vec<u32>` — усі leaf indices (кому надіслати групове повідомлення) |
| `relay::crypto_envelope_recipients(envelope, roster)` | `envelope`, `roster` | `Vec<u32>` — leaf indices одержувачів (виключає відправника за `sender_device_id` / credential) |

Сервер використовує ці списки leaf indices (або device_id), щоб визначити, яким клієнтам доставити Commit / Welcome / GroupMessage.

## Оновлення roster після Commit

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `relay::apply_commit_to_roster(roster, info, added_members)` | `roster` (mut), `RelayCommitInfo` з валідації, `added_members: Vec<GroupMemberRecord>` (з Welcome/key packages) | `Result<(), ProtocolError>` |

Видаляє `removed_leaves`, додає нових членів, встановлює `roster.epoch = info.new_epoch`.

### Типи

**`GroupMemberRecord`** — запис одного учасника:

| Поле | Тип | Опис |
|------|-----|------|
| `leaf_index` | `u32` | Leaf index у дереві |
| `identity_ed25519_public` | `Vec<u8>` | Ed25519 публічний ключ ідентичності |
| `identity_x25519_public` | `Vec<u8>` | X25519 публічний ключ ідентичності |
| `credential` | `Vec<u8>` | Довільний credential (напр. device_id) |

**`GroupRoster`** — стан групи на сервері:

| Поле | Тип | Опис |
|------|-----|------|
| `group_id` | `Vec<u8>` | Ідентифікатор групи |
| `epoch` | `u64` | Поточна epoch |
| `members` | `Vec<GroupMemberRecord>` | Список учасників |

**`GroupRoster` — допоміжні методи:**

| Метод | Що передавати | Повертає |
|-------|---------------|----------|
| `GroupRoster::new(group_id, creator)` | `group_id: Vec<u8>`, `creator: GroupMemberRecord` | Новий roster з одним учасником |
| `roster.find_member(leaf_index)` | `leaf_index: u32` | `Option<&GroupMemberRecord>` |
| `roster.find_member_by_identity(identity_ed25519)` | `identity_ed25519: &[u8]` | `Option<&GroupMemberRecord>` |
| `roster.leaf_indices()` | — | `Vec<u32>` — усі leaf indices |
| `roster.member_count()` | — | `usize` — кількість учасників |

**`RelayCommitInfo`** — результат валідації коміту:

| Поле | Тип | Опис |
|------|-----|------|
| `committer_leaf_index` | `u32` | Leaf index автора коміту |
| `new_epoch` | `u64` | Нова epoch після коміту |
| `added_identities` | `Vec<Vec<u8>>` | Ed25519 ключі доданих учасників |
| `removed_leaves` | `Vec<u32>` | Leaf indices видалених учасників |

## Welcome та зовнішній join

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `relay::extract_welcome_target(welcome_bytes)` | сирі байти GroupWelcome | `Result<(group_id, epoch, target_leaf_index), ProtocolError>` |

Сервер використовує це, щоб знати, кому доставити Welcome (одному клієнту за `target_leaf_index`).

## VoIP relay (legacy signaling hardening)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `relay::validate_voip_envelope(envelope_bytes)` | сирі байти `VoipEnvelope` | `Result<VoipEnvelope, ProtocolError>` |
| `relay::process_voip_signal(envelope, store, server_timestamp)` | валідований `VoipEnvelope`, реалізація `VoipCallStore`, unix timestamp | `Result<VoipRelayAction, ProtocolError>` |

`process_voip_signal` виконує stateful перевірки для call lifecycle:

- не дозволяє підміни `recipient_device_id`;
- блокує сигнали від не-учасників дзвінка;
- контролює дозволені переходи станів (`Initiated -> Active -> Rekeying -> Ended`);
- блокує replay/invalid sequencing для rekey/rekey-ack;
- дропає прострочені дзвінки за timeout/lifetime policy.

Практично: для VoIP ingress спочатку викликайте `validate_voip_envelope`, потім `process_voip_signal`, і лише після успіху форвардьте payload цільовому пристрою.

## Зберігання подій (PendingEventStore)

Сервер реалізує трейт `PendingEventStore` і передає його туди, де потрібна черга подій для пристроїв:

| Метод | Що передавати | Призначення |
|-------|---------------|-------------|
| `store_event(device_id, event_id, server_timestamp, envelope_bytes)` | device_id, унікальний event_id, час сервера, байти CryptoEnvelope | Зберегти подію для доставки пристрою |
| `fetch_events(device_id, after_event_id, max_events)` | device_id, курсор, ліміт | Отримати наступні події для цього пристрою |
| `ack_events(device_id, event_ids)` | device_id, список event_id | Підтвердити доставку; повертає кількість підтверджених |

**`StoredPendingEvent`** — тип події:

| Поле | Тип | Опис |
|------|-----|------|
| `event_id` | `String` | Унікальний ідентифікатор події |
| `server_timestamp` | `u64` | Час сервера (unix timestamp) |
| `envelope_bytes` | `Vec<u8>` | Байти CryptoEnvelope |

## Типові кроки сервера

1. Отримати від клієнта байти CryptoEnvelope.
2. Викликати `validate_crypto_envelope(envelope_bytes)`.
3. За `payload_type` та `group_id` визначити групу; завантажити її `GroupRoster`.
4. Якщо це Commit: `validate_commit_for_relay_strict(commit_bytes, roster, expected_sender_identity_ed25519)` → `RelayCommitInfo`; `commit_recipients(roster, committer)` → список одержувачів; для кожного одержувача можна зберегти/відправити Commit; потім `apply_commit_to_roster` + доставка Welcome цільовому leaf.
5. Якщо це GroupMessage: `validate_group_message_for_relay_strict(message_bytes, roster, sender_leaf_index, expected_sender_identity_ed25519)`; `message_recipients(roster)` або `crypto_envelope_recipients(envelope, roster)` → кому доставити; `store_event` для кожного одержувача або відправка в реальному часі.
6. Для 1:1 envelope сервер лише пересилає blob одержувачу за його ідентифікатором (наприклад, за session/device).
7. `sender_device_id`, `sender_leaf_index` та identity для strict-валідації мають братися з автентифікованого transport/session контексту, а не довірятися напряму полям у payload.

Уся криптографія (дешифрування, перевірка підписів всередині payload) виконується на клієнті; сервер лише валідує формат і маршрутизує.

Див. також узгоджений контракт `protocol <-> relay <-> Swift`: [docs/epp-relay-swift-alignment.md](epp-relay-swift-alignment.md).
