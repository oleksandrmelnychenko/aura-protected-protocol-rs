# Swift FFI — виклики та параметри

Swift-обгортка над C FFI бібліотеки Ecliptix Protocol. Збирається з XCFramework (Rust `staticlib` + C заголовок). Підтримка iOS 16+, macOS 13+.

## Ініціалізація

Перед будь-якими викликами протоколу викликайте ініціалізацію; при завершенні роботи — shutdown.

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `EcliptixProtocol.initialize()` | — | `throws` — викликати один раз при старті додатку |
| `EcliptixProtocol.shutdown()` | — | — — викликати при виході |
| `EcliptixProtocol.version` | — | `String` — версія бібліотеки |

## 1:1 сесія — повний цикл

### Крок 1: Identity (обидві сторони)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `EppIdentity.create()` | — | `EppIdentity` |
| `EppIdentity.create(fromSeed: Data)` | `seed` — 32+ байт | `EppIdentity` |
| `EppIdentity.create(fromSeed: Data, membershipId: String)` | `seed`, `membershipId` | `EppIdentity` |
| `identity.createPrekeyBundle()` | — | `Data` — PreKey bundle для відправки peer |
| `identity.x25519PublicKey` | — | `Data` (32 байти) |
| `identity.ed25519PublicKey` | — | `Data` (32 байти) |
| `identity.kyberPublicKey` | — | `Data` (1184 байти) |

**Важливо:** Респондер (сервер/отримувач) має зберегти свій `EppIdentity` і один раз згенерувати PreKey bundle; ініціатор отримує цей bundle по каналу (HTTPS тощо).

### Крок 2: Handshake — ініціатор (клієнт)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `EppHandshakeInitiator.start(identity:peerPrekeyBundle:config:)` | `identity` — локальна, `peerPrekeyBundle` — `Data` (bundle респондера), `config` — опційно `EppSessionConfig(maxMessagesPerChain: 1000)` | `(initiator, handshakeInit: Data)` |
| `initiator.finish(handshakeAck: Data)` | `handshakeAck` — відповідь від респондера | `EppSession` |

**Що передати:** Ініціатор надсилає `handshakeInit` респондеру; респондер повертає `handshakeAck`; ініціатор викликає `finish(handshakeAck)` і отримує сесію.

### Крок 3: Handshake — респондер (сервер)

Swift-обгортка надає `EppHandshakeResponder` (аналогічно `EppHandshakeInitiator`):

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `EppHandshakeResponder.start(identity:localPrekeyBundle:handshakeInit:config:)` | `identity` — локальна, `localPrekeyBundle` — свій bundle, `handshakeInit` — байти від ініціатора, `config` — опційно | `(responder, handshakeAck: Data)` |
| `responder.finish()` | — | `EppSession` |

**Що передати:** Респондер отримує `handshakeInit` від ініціатора, надсилає `handshakeAck` назад, викликає `finish()` і отримує сесію.

C FFI еквівалент (для прямої інтеграції без Swift-обгортки): `epp_handshake_responder_start` (вхід: `identity`, `local_prekey_bundle`, `handshake_init`, `config`; вихід: `handshake_ack`) → `epp_handshake_responder_finish` → `EppSessionHandle`.

### Крок 4: Шифрування / дешифрування (1:1)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `session.encrypt(plaintext:envelopeType:envelopeId:correlationId:)` | `plaintext: Data`, `envelopeType` (за замовчуванням `EPP_ENVELOPE_REQUEST`), `envelopeId: 0`, `correlationId: ""` | `Data` — зашифрований envelope |
| `session.decrypt(encryptedEnvelope: Data)` | `encryptedEnvelope` — байти отриманого повідомлення | `Data` — plaintext |

**Що передавати в `encrypt`:** payload (наприклад, JSON), тип конверта (Request/Response/Notification/Heartbeat/ErrorResponse), опційно id і correlation_id для зв'язки запит–відповідь.

### Крок 5: Nonce exhaustion warning (моніторинг вичерпання nonce)

Кожна сесія має обмежену кількість nonce (за замовчуванням 65 535). Коли залишок падає нижче 10%, спрацьовує callback `on_nonce_exhaustion_warning`. Додатково можна опитувати залишок вручну.

| Що викликати (C FFI) | Що передавати | Повертає |
|----------------------|---------------|----------|
| `epp_session_nonce_remaining` | `handle`, `out_remaining` (`*mut u64`), `out_error` | код помилки; кількість залишкових nonce у `out_remaining` |

Для отримання callback реалізуйте трейт `IProtocolEventHandler` і передайте через `session.set_event_handler(handler)`. Метод `on_nonce_exhaustion_warning(remaining, max_capacity)` викликається на кожному `encrypt()`, поки залишок ≤ 10% від max. Клієнт має ініціювати re-handshake до повного вичерпання.

### Крок 6: Збереження / відновлення сесії (sealed, рекомендовано)

Щоб уникнути rollback, використовуйте **sealed** state з монотонним лічильником (зберігайте його у себе).

| Що викликати (C FFI) | Що передавати | Повертає |
|----------------------|---------------|----------|
| `epp_session_serialize_sealed` | `handle`, `key` (32 байти), `external_counter` (зростаюче число, напр. з БД), `out_state`, `out_error` | код помилки; state в `out_state` |
| `epp_session_deserialize_sealed` | `state_bytes`, `key`, `min_external_counter` (останній прийнятий counter), `out_external_counter`, `out_handle`, `out_error` | код помилки; сесія в `out_handle`; записати `out_external_counter` для наступного `min_external_counter` |

Swift-обгортка:

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `session.serialize(key: Data, externalCounter: UInt64)` | `key` — 32 байти, `externalCounter` — зростаюче число | `Data` — sealed state |
| `EppSession.deserialize(sealedState: Data, key: Data, minExternalCounter: UInt64)` | `sealedState`, `key`, `minExternalCounter` | `(session: EppSession, externalCounter: UInt64)` |

**Що передавати на Relay/сервер:** Клієнт може надсилати зашифрований envelope як є (binary). Сервер лише пересилає байти; дешифрування робить одержувач на своїй сесії.

## Групова сесія (C FFI)

Групові функції наразі доступні лише через C FFI. Типи: `EppGroupSessionHandle`, `EppKeyPackageSecretsHandle`.

### Key Package (підготовка до вступу в групу)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `epp_group_generate_key_package` | `identity_handle`, `credential`, `credential_length`, `out_key_package`, `out_secrets`, `out_error` | Key package для Add-пропозиції; секрети зберегти для `epp_group_join` |
| `epp_group_key_package_secrets_destroy` | `handle_ptr` | Знищити секрети key package |

### Створення / приєднання до групи

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `epp_group_create` | `identity_handle`, `credential`, `credential_length`, `out_handle`, `out_error` | Нова група (автор — єдиний член) |
| `epp_group_join` | `identity_handle`, `welcome_bytes`, `welcome_length`, `secrets_handle`, `out_group_handle`, `out_error` | Приєднатися через Welcome (після Add комміту) |
| `epp_group_join_external` | `identity_handle`, `public_state`, `public_state_length`, `credential`, `credential_length`, `out_group_handle`, `out_commit`, `out_error` | Зовнішній join через публічний стан; commit надіслати групі |

### Управління учасниками

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `epp_group_add_member` | `handle`, `key_package_bytes`, `key_package_length`, `out_commit`, `out_welcome`, `out_error` | Commit (надіслати групі) + Welcome (надіслати новому учаснику) |
| `epp_group_remove_member` | `handle`, `leaf_index`, `out_commit`, `out_error` | Commit (надіслати групі) |
| `epp_group_update` | `handle`, `out_commit`, `out_error` | Update-commit (оновити свої ключі) |
| `epp_group_process_commit` | `handle`, `commit_bytes`, `commit_length`, `out_error` | Застосувати чужий Commit |

### Шифрування / дешифрування (групове)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `epp_group_encrypt` | `handle`, `plaintext`, `plaintext_length`, `out_ciphertext`, `out_error` | Зашифрований GroupMessage |
| `epp_group_decrypt` | `handle`, `ciphertext`, `ciphertext_length`, `out_plaintext`, `out_sender_leaf`, `out_generation`, `out_error` | Plaintext + `sender_leaf` + `generation` |
| `epp_group_encrypt_sealed` | `handle`, `plaintext`, `plaintext_length`, `hint`, `hint_length`, `out_ciphertext`, `out_error` | Sealed-повідомлення (анонімний відправник) |
| `epp_group_encrypt_disappearing` | `handle`, `plaintext`, `plaintext_length`, `ttl_seconds`, `out_ciphertext`, `out_error` | Повідомлення, що зникає (TTL) |
| `epp_group_encrypt_frankable` | `handle`, `plaintext`, `plaintext_length`, `out_ciphertext`, `out_error` | Frankable-повідомлення (можна довести автентичність третій стороні) |
| `epp_group_reveal_sealed` | `hint`, `hint_length`, `encrypted_content`, `encrypted_content_length`, `nonce`, `nonce_length`, `seal_key`, `seal_key_length`, `out_plaintext`, `out_error` | Розшифрувати sealed-повідомлення за ключем |
| `epp_group_verify_franking` | `franking_tag`, `franking_tag_length`, `franking_key`, `franking_key_length`, `content`, `content_length`, `sealed_content`, `sealed_content_length`, `out_valid`, `out_error` | Перевірити franking-тег |

### Серіалізація групової сесії (sealed)

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `epp_group_serialize` | `handle`, `key` (32 байти), `key_length`, `external_counter`, `out_state`, `out_error` | Sealed-стан групи |
| `epp_group_deserialize` | `state_bytes`, `state_length`, `key`, `key_length`, `min_external_counter`, `out_external_counter`, `identity_handle`, `out_handle`, `out_error` | Відновити групову сесію; зберегти `out_external_counter` |
| `epp_group_export_public_state` | `handle`, `out_public_state`, `out_error` | Публічний стан (для `epp_group_join_external`) |

### PSK та стан групи

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `epp_group_set_psk` | `handle`, `psk_id`, `psk_id_length`, `psk`, `psk_length`, `out_error` | Встановити Pre-Shared Key для наступного коміту |
| `epp_group_get_pending_reinit` | `handle`, `out_new_group_id`, `out_new_version`, `out_error` | Отримати дані reinit (якщо є) |

### Геттери групи

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `epp_group_get_id` | `handle`, `out_group_id`, `out_error` | `group_id` групи |
| `epp_group_get_epoch` | `handle` | `u64` — поточна epoch |
| `epp_group_get_my_leaf_index` | `handle` | `u32` — мій leaf index |
| `epp_group_get_member_count` | `handle` | `u32` — кількість учасників |
| `epp_group_get_member_leaf_indices` | `handle`, `out_indices`, `out_error` | Буфер з leaf indices усіх членів (масив `u32` LE) |
| `epp_group_destroy` | `handle_ptr` | Знищити групову сесію |

## Shamir Secret Sharing (C FFI)

Розщеплення та відновлення секретів за схемою Shamir (threshold-of-n).

| Що викликати | Що передавати | Повертає |
|--------------|---------------|----------|
| `epp_shamir_split` | `secret`, `secret_length`, `threshold` (мін. шарів), `share_count` (загальна к-ть), `auth_key`, `auth_key_length`, `out_shares`, `out_share_length`, `out_error` | Масив шарів у `out_shares`; розмір одного шару в `out_share_length` |
| `epp_shamir_reconstruct` | `shares`, `shares_length`, `share_length`, `share_count`, `auth_key`, `auth_key_length`, `out_secret`, `out_error` | Відновлений секрет у `out_secret` |

## Допоміжні функції (C FFI)

| Що викликати | Що передавати | Призначення |
|--------------|---------------|-------------|
| `epp_derive_root_key` | `opaque_session_key`, `user_context`, буфер для `out_root_key` (64 байти) | Похідний ключ з непрозорого ключа сесії та контексту |
| `epp_secure_wipe` | `data` (pointer), `length` | Знищення секрету в пам'яті |
| `epp_envelope_validate` | `encrypted_envelope`, `length` | Перевірка формату envelope без дешифрування |
| `epp_buffer_release` | `EppBuffer*` | Звільнити DATA всередині буфера (не сам struct) |
| `epp_buffer_alloc` | `size` | Алокувати буфер заданого розміру |
| `epp_buffer_free` | `EppBuffer*` | Звільнити буфер цілком (struct + data) |
| `epp_error_free` | `EppError*` | Звільнити повідомлення про помилку |
| `epp_error_string` | `EppError*` | Отримати рядок помилки |

## Помилки

Усі функції, що повертають `EppErrorCode`, заповнюють `EppError` (code + message). У Swift це перетворено на `EppError` (enum/тип з кодами). Типові коди: `EPP_SUCCESS`, `EPP_ERROR_REPLAY_ATTACK`, `EPP_ERROR_DECRYPTION`, `EPP_ERROR_INVALID_STATE` тощо. Після обробки помилки викликайте `epp_error_free(&outError)`.

## Збірка Swift-пакету

1. Зібрати XCFramework з Rust через локальний release flow або CI workflow.
2. Release artifact має назву `ecliptix-protected-protocol.xcframework.zip`.
3. Локальний Swift package використовує checked-in binary target у `swift/XCFrameworks/EcliptixProtocolC.xcframework`.
4. У проекті додати залежність на Swift Package (шлях до папки `swift`).

Клієнт (iOS/macOS) використовує цю обгортку для identity, handshake, encrypt/decrypt, групових операцій та sealed serialize/deserialize з коректним `external_counter`.
