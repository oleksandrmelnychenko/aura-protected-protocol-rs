# Swift FFI — виклики та параметри

Swift-обгортка над C FFI бібліотеки Aura Protocol. Публічний Swift package споживає XCFramework binary target, а високорівневий Swift layer біндить exported Rust symbols через `@_silgen_name`. Поточний `Package.swift` таргетить iOS 18+, macOS 15+.

## Ініціалізація

Перед будь-якими викликами протоколу викликайте ініціалізацію; при завершенні роботи — shutdown.

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `AuraProtectedProtocol.initialize()` | — | `throws` — викликати один раз при старті додатку |
| `AuraProtectedProtocol.shutdown()` | — | — — викликати при виході |
| `AuraProtectedProtocol.version` | — | `String` — версія бібліотеки |

## Manual Time Provider

Swift wrapper надає `AuraTimeProvider` для deterministic tests і trusted-time restore flow.

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `AuraTimeProvider.manual(initialNowUnix:)` | `UInt64` Unix timestamp | `AuraTimeProvider` |
| `timeProvider.setNowUnix(_:)` | новий Unix timestamp | `throws`; clock можна рухати тільки вперед |
| `identity.setTimeProvider(_:)` | `AuraTimeProvider?` | `throws`; `nil` повертає identity до системного часу |

Важливо: rewind manual clock тепер відхиляється з `AURA_ERROR_INVALID_INPUT` / `AuraError.invalidInput`.

## 1:1 сесія — повний цикл

### Крок 1: Identity (обидві сторони)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `AuraIdentity.create()` | — | `AuraIdentity` |
| `AuraIdentity.create(fromSeed: Data)` | `seed` — 32+ байт | `AuraIdentity` |
| `AuraIdentity.create(fromSeed: Data, membershipId: String)` | `seed`, `membershipId` | `AuraIdentity` |
| `identity.createPrekeyBundle()` | — | `Data` — PreKey bundle для відправки peer |
| `identity.x25519PublicKey` | — | `Data` (32 байти) |
| `identity.ed25519PublicKey` | — | `Data` (32 байти) |
| `identity.kyberPublicKey` | — | `Data` (1184 байти) |

**Важливо:** Респондер (сервер/отримувач) має зберегти свій `AuraIdentity` і один раз згенерувати PreKey bundle; ініціатор отримує цей bundle по каналу (HTTPS тощо).

### Крок 2: Handshake — ініціатор (клієнт)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `AuraHandshakeInitiator.start(identity:peerPrekeyBundle:config:)` | `identity` — локальна, `peerPrekeyBundle` — `Data` (bundle респондера), `config` — опційно `AuraSessionConfig(maxMessagesPerChain: 1000)` | `(initiator, handshakeInit: Data)` |
| `initiator.finish(handshakeAck: Data)` | `handshakeAck` — відповідь від респондера | `AuraSession` |

**Що передати:** Ініціатор надсилає `handshakeInit` респондеру; респондер повертає `handshakeAck`; ініціатор викликає `finish(handshakeAck)` і отримує сесію.

### Крок 3: Handshake — респондер (сервер)

Swift-обгортка надає `AuraHandshakeResponder` (аналогічно `AuraHandshakeInitiator`):

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `AuraHandshakeResponder.start(identity:localPrekeyBundle:handshakeInit:config:)` | `identity` — локальна, `localPrekeyBundle` — свій bundle, `handshakeInit` — байти від ініціатора, `config` — опційно | `(responder, handshakeAck: Data)` |
| `responder.finish()` | — | `AuraSession` |

**Що передати:** Респондер отримує `handshakeInit` від ініціатора, надсилає `handshakeAck` назад, викликає `finish()` і отримує сесію.

C FFI еквівалент (для прямої інтеграції без Swift-обгортки): `aura_handshake_responder_start` (вхід: `identity`, `local_prekey_bundle`, `handshake_init`, `config`; вихід: `handshake_ack`) → `aura_handshake_responder_finish` → `AuraSessionHandle`.

### Крок 4: Шифрування / дешифрування (1:1)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `session.encrypt(plaintext:envelopeType:envelopeId:correlationId:)` | `plaintext: Data`, `envelopeType` (за замовчуванням `AURA_ENVELOPE_REQUEST`), `envelopeId: 0`, `correlationId: ""` | `Data` — зашифрований envelope |
| `session.decrypt(encryptedEnvelope: Data)` | `encryptedEnvelope` — байти отриманого повідомлення | `Data` — plaintext |

**Що передавати в `encrypt`:** payload (наприклад, JSON), тип конверта (Request/Response/Notification/Heartbeat/ErrorResponse), опційно id і correlation_id для зв'язки запит–відповідь.

### Крок 5: Nonce exhaustion warning (моніторинг вичерпання nonce)

Кожна сесія має обмежений send budget у поточному ланцюгу (за замовчуванням 1 000 повідомлень). 65 535 є жорсткою межею 16-бітного nonce-кодування. Коли залишок падає нижче 10%, спрацьовує callback `on_nonce_exhaustion_warning`. Додатково можна опитувати залишок вручну.

| Що викликати (C FFI) | Що передавати | Повертає |
|----------------------|---------------|----------|
| `aura_session_nonce_remaining` | `handle`, `out_remaining` (`*mut u64`), `out_error` | код помилки; кількість залишкових nonce у `out_remaining` |

Для отримання callback реалізуйте трейт `IProtocolEventHandler` і передайте через `session.set_event_handler(handler)`. Метод `on_nonce_exhaustion_warning(remaining, max_capacity)` викликається на кожному `encrypt()`, поки залишок ≤ 10% від max. Клієнт має ініціювати re-handshake до повного вичерпання.

### Крок 6: Збереження / відновлення сесії (sealed, рекомендовано)

Щоб уникнути rollback, використовуйте **sealed** state з монотонним лічильником (зберігайте його у себе).

| Що викликати (C FFI) | Що передавати | Повертає |
|----------------------|---------------|----------|
| `aura_session_serialize_sealed` | `handle`, `key` (32 байти), `external_counter` (зростаюче число, напр. з БД), `out_state`, `out_error` | код помилки; state в `out_state` |
| `aura_session_deserialize_sealed` | `state_bytes`, `key`, `min_external_counter` (мінімально дозволений counter), `out_external_counter`, `out_handle`, `out_error` | код помилки; сесія в `out_handle`; записати `out_external_counter` для наступного `min_external_counter` |

Swift-обгортка:

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `session.serialize(key: Data, externalCounter: UInt64)` | `key` — 32 байти, `externalCounter` — зростаюче число | `Data` — sealed state |
| `AuraSession.deserialize(sealedState: Data, key: Data, minExternalCounter: UInt64)` | `sealedState`, `key`, `minExternalCounter` | `(session: AuraSession, externalCounter: UInt64)` |

Правила anti-rollback:

- імпорт вважається валідним лише якщо `sealed_counter >= minExternalCounter`; якщо інтегратор зберігає саме останній прийнятий counter і хоче відхиляти рівність, передавайте `lastAccepted + 1`;
- managed tracker restore використовує watermark `max(maxRestoredCounter, latestIssuedCounter)`, тобто відхиляє blob, старіший за вже прийнятий restore або вже виданий export counter;
- для C FFI `out_external_counter` використовувати тільки коли код повернення `AURA_SUCCESS`.

**Що передавати на Relay/сервер:** Клієнт може надсилати зашифрований envelope як є (binary). Сервер лише пересилає байти; дешифрування робить одержувач на своїй сесії.

## Current Snapshot Contract

Оновилась поведінка існуючих викликів — вони суворіше відхиляють oversized input:

- `session.encrypt(...)` — payload size policy enforced.
- `session.decrypt(...)` — envelope size policy enforced до decode.
- handshake/bundle paths — stricter size and validation guardrails.
- `AuraTimeProvider.setNowUnix(_:)` — лише forward-only clock updates.
- `AuraError.busy(String)` — конкурентне використання одного native handle.

Low-level VoIP destroy сигнатури стали pointer-to-pointer, але для Swift-клієнта це прозоро: `deinit` у `AuraVoipCallInitiator` та `AuraVoipSession` вже викликає правильний nulling destroy.

Що робити в Swift-клієнті:

1. Додати preflight size checks перед викликами (особливо для вкладень/великих payload).
2. Мапити size-violations (`AURA_ERROR_INVALID_INPUT`) у окремий UX/classified error (`payload_too_large`, `envelope_too_large`), без retry-loop.
3. Не використовувати один і той самий session/group/VoIP object одночасно з кількох потоків без зовнішньої синхронізації.
4. В telemetry логувати тільки код/тип помилки та розмір payload, але не самі дані.

## Attachments / Media (через C FFI)

Attachment/media path реалізований як FFI crypto/validation ядро. Transport/upload/download не входять у бібліотеку.

Рекомендований flow:

1. `aura_attachment_generate_id` + `aura_attachment_generate_file_key`
2. Для кожного чанка: `aura_attachment_encrypt_chunk`
3. Після шифрування файлу: `aura_attachment_manifest_create`
4. На прийомі: `aura_attachment_manifest_validate` + `aura_attachment_chunk_validate`
5. Для контенту: `aura_attachment_decrypt_chunk`

Практично:

- `encrypted_file_key` в manifest має приходити з chat channel (1:1/group), а не у відкритому вигляді;
- optional `collage_index` у manifest використовуйте для порядку вкладень у collage Threads;
- великі файли не передавати через `session.encrypt(...)` payload напряму;
- на помилках validate/decrypt не робити blind retry без зміни вхідних даних.

## Групова сесія

Swift wrapper надає `AuraGroupSession` та `AuraGroupKeyPackageSecrets`. Таблиці нижче залишають C FFI назви як low-level reference для дебагу й інтеграційного звіряння.

### Key Package (підготовка до вступу в групу)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `aura_group_generate_key_package` | `identity_handle`, `credential`, `credential_length`, `out_key_package`, `out_secrets`, `out_error` | Key package для Add-пропозиції; секрети зберегти для `aura_group_join` |
| `aura_group_key_package_secrets_destroy` | `handle_ptr` | Знищити секрети key package |

### Створення / приєднання до групи

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `aura_group_create` | `identity_handle`, `credential`, `credential_length`, `out_handle`, `out_error` | Нова група (автор — єдиний член) |
| `aura_group_join` | `identity_handle`, `welcome_bytes`, `welcome_length`, `secrets_handle`, `out_group_handle`, `out_error` | Приєднатися через Welcome (після Add комміту) |
| `aura_group_authorize_external_join` | member handle + joiner identity/public-state inputs, `out_authorization`, `out_error` | Чинний член видає authorization artifact для joiner-а |
| `aura_group_join_external` | `identity_handle`, `public_state`, `public_state_length`, `authorization`, `authorization_length`, `credential`, `credential_length`, `out_group_handle`, `out_commit`, `out_error` | Зовнішній join через публічний стан і authorization; commit надіслати групі |

### Управління учасниками

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `aura_group_add_member` | `handle`, `key_package_bytes`, `key_package_length`, `out_commit`, `out_welcome`, `out_error` | Commit (надіслати групі) + Welcome (надіслати новому учаснику) |
| `aura_group_remove_member` | `handle`, `leaf_index`, `out_commit`, `out_error` | Commit (надіслати групі) |
| `aura_group_update` | `handle`, `out_commit`, `out_error` | Update-commit (оновити свої ключі) |
| `aura_group_process_commit` | `handle`, `commit_bytes`, `commit_length`, `out_error` | Застосувати чужий Commit |

### Шифрування / дешифрування (групове)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `aura_group_encrypt` | `handle`, `plaintext`, `plaintext_length`, `out_ciphertext`, `out_error` | Зашифрований GroupMessage |
| `aura_group_decrypt` | `handle`, `ciphertext`, `ciphertext_length`, `out_plaintext`, `out_sender_leaf`, `out_generation`, `out_error` | Plaintext + `sender_leaf` + `generation` |
| `aura_group_encrypt_sealed` | `handle`, `plaintext`, `plaintext_length`, `hint`, `hint_length`, `out_ciphertext`, `out_error` | Sealed inner payload; sender metadata still comes from group decrypt result |
| `aura_group_encrypt_disappearing` | `handle`, `plaintext`, `plaintext_length`, `ttl_seconds`, `out_ciphertext`, `out_error` | Повідомлення, що зникає (TTL) |
| `aura_group_encrypt_frankable` | `handle`, `plaintext`, `plaintext_length`, `out_ciphertext`, `out_error` | Frankable-повідомлення (можна довести автентичність третій стороні) |
| `aura_group_reveal_sealed` | `hint`, `hint_length`, `encrypted_content`, `encrypted_content_length`, `nonce`, `nonce_length`, `seal_key`, `seal_key_length`, `out_plaintext`, `out_error` | Розшифрувати sealed-повідомлення за ключем |
| `aura_group_verify_franking` | `franking_tag`, `franking_tag_length`, `franking_key`, `franking_key_length`, `content`, `content_length`, `sealed_content`, `sealed_content_length`, `out_valid`, `out_error` | Перевірити franking-тег |

### Серіалізація групової сесії (sealed)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `aura_group_serialize` | `handle`, `key` (32 байти), `key_length`, `external_counter`, `out_state`, `out_error` | Sealed-стан групи |
| `aura_group_deserialize` | `state_bytes`, `state_length`, `key`, `key_length`, `min_external_counter`, `out_external_counter`, `identity_handle`, `out_handle`, `out_error` | Відновити групову сесію; зберегти `out_external_counter` |
| `aura_group_export_public_state` | `handle`, `out_public_state`, `out_error` | Публічний стан (для `aura_group_join_external`) |

### PSK та стан групи

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `aura_group_set_psk` | `handle`, `psk_id`, `psk_id_length`, `psk`, `psk_length`, `out_error` | Встановити Pre-Shared Key для наступного коміту |
| `aura_group_get_pending_reinit` | `handle`, `out_new_group_id`, `out_new_version`, `out_error` | Отримати дані reinit (якщо є) |

### Геттери групи

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `aura_group_get_id` | `handle`, `out_group_id`, `out_error` | `group_id` групи |
| `aura_group_get_epoch` | `handle` | `u64` — поточна epoch |
| `aura_group_get_my_leaf_index` | `handle` | `u32` — мій leaf index |
| `aura_group_get_member_count` | `handle` | `u32` — кількість учасників |
| `aura_group_get_member_leaf_indices` | `handle`, `out_indices`, `out_error` | Буфер з leaf indices усіх членів (масив `u32` LE) |
| `aura_group_destroy` | `handle_ptr` | Знищити групову сесію |

## Shamir Secret Sharing (C FFI)

Розщеплення та відновлення секретів за схемою Shamir (threshold-of-n).

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `aura_shamir_split` | `secret`, `secret_length`, `threshold` (мін. шарів), `share_count` (загальна к-ть), `auth_key`, `auth_key_length`, `out_shares`, `out_share_length`, `out_error` | Масив шарів у `out_shares`; розмір одного шару в `out_share_length` |
| `aura_shamir_reconstruct` | `shares`, `shares_length`, `share_length`, `share_count`, `auth_key`, `auth_key_length`, `out_secret`, `out_error` | Відновлений секрет у `out_secret` |

## Допоміжні функції (C FFI)

| Що викликати | Що передавати | Призначення |
|--------------|---------------|-------------|
| `aura_derive_root_key` | `opaque_session_key`, `user_context`, буфер для `out_root_key` (64 байти) | Похідний ключ з непрозорого ключа сесії та контексту |
| `aura_secure_wipe` | `data` (pointer), `length` | Знищення секрету в пам'яті |
| `aura_envelope_validate` | `encrypted_envelope`, `length` | Перевірка формату envelope без дешифрування |
| `aura_buffer_release` | `AuraBuffer*` | Звільнити DATA всередині буфера (не сам struct) |
| `aura_buffer_alloc` | `size` | Алокувати буфер заданого розміру |
| `aura_buffer_free` | `AuraBuffer*` | Звільнити буфер цілком (struct + data) |
| `aura_error_free` | `AuraError*` | Звільнити повідомлення про помилку |
| `aura_error_string` | `AuraErrorCode` | Отримати рядок помилки для коду |

Прості `AuraBuffer*` і `out_handle` слоти FFI перезаписує без читання старого
значення. Swift wrapper має тримати їх як короткоживучі локальні змінні або
явно викликати `aura_buffer_release` / відповідний `_destroy` перед повторним
використанням того самого слота. Compound structs (`AuraEncryptedFrame`,
`AuraDecryptedFrame`, group decrypt result, metadata) zero-initialize перед
першим викликом і звільняйте їхні вкладені буфери після використання.

## Помилки

Усі функції, що повертають `AuraErrorCode`, заповнюють `AuraError` (code + message). У Swift це перетворено на `AuraError` (enum/тип з кодами).

Окремо зверніть увагу на:

- `AuraError.invalidInput` для oversize input, malformed payload і rewind manual clock;
- `AuraError.busy` для конкурентного доступу до одного native handle;
- `voipCall` / `voipMedia` / `voipRekey` для VoIP-specific помилок.

## Збірка Swift-пакету

1. Зібрати XCFramework з Rust через локальний release flow або CI workflow.
2. Release artifact має назву `aura-protected-protocol.xcframework.zip`.
3. Оновити root `Package.swift` binary target URL + checksum під опублікований artifact.
4. Для локальної інтеграції використовуйте root Swift package цього репозиторію як path dependency або перевіряйте тег, що ship-ить відповідний XCFramework snapshot.

Клієнт (iOS/macOS) використовує цю обгортку для identity, handshake, encrypt/decrypt, групових операцій та sealed serialize/deserialize з коректним `external_counter`.
