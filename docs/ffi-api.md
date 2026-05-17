# Aura Protocol — C FFI API Reference

C API для інтеграції Aura Protocol у будь-яку мову (Swift, Kotlin, C#, Python, C++, Go, etc.).

Headers: `include/aura_api.h` (umbrella), `include/aura_client_api.h`, `include/aura_common_api.h`
Бібліотека: `libaura_protocol.a` (staticlib) або `.dylib`/`.so`/`.dll` (cdylib)

---

## Ролі та профілі збірки

API розрахований на три ролі:

| Роль | Опис | Прапор збірки |
|------|------|---------------|
| **Client (Agent)** | Кінцевий пристрій користувача — ініціює handshake, шифрує/дешифрує, бере участь у групах | За замовчуванням (без прапорів) |
| **Server (Endpoint)** | Сервер, що приймає з'єднання від клієнтів — відповідає на handshake, шифрує/дешифрує | `AURA_SERVER_BUILD` (ховає initiator) |
| **Relay** | Проміжний сервер — лише пересилає зашифровані байти, не має ключів | `AURA_SERVER_BUILD` (використовує мінімум API) |

### Зведена таблиця функцій за ролями

`C` = Client/Agent, `S` = Server Endpoint, `R` = Relay

| Функція | C | S | R | Опис |
|---------|:-:|:-:|:-:|------|
| **Ініціалізація** | | | |
| `aura_version` | + | + | + | Версія бібліотеки |
| `aura_init` | + | + | + | Ініціалізація крипто |
| `aura_shutdown` | + | + | + | Завершення роботи |
| **Identity** | | | |
| `aura_identity_create` | + | + | - | Створити identity (випадкова) |
| `aura_identity_create_from_seed` | + | + | - | Створити identity (з seed) |
| `aura_identity_create_with_context` | + | + | - | Створити identity (seed + context) |
| `aura_identity_get_x25519_public` | + | + | - | Отримати X25519 public key |
| `aura_identity_get_ed25519_public` | + | + | - | Отримати Ed25519 public key |
| `aura_identity_get_kyber_public` | + | + | - | Отримати ML-KEM public key |
| `aura_identity_destroy` | + | + | - | Знищити identity |
| `aura_time_provider_manual_create` | + | + | - | Створити manual clock |
| `aura_time_provider_manual_set_now_unix` | + | + | - | Пересунути manual clock вперед |
| `aura_identity_set_time_provider` | + | + | - | Прив'язати identity до explicit clock |
| `aura_time_provider_destroy` | + | + | - | Знищити manual clock |
| **Pre-Key Bundle** | | | |
| `aura_prekey_bundle_create` | + | + | - | Створити PreKey bundle |
| **Handshake — Initiator** | | | |
| `aura_handshake_initiator_start` | + | - | - | Почати handshake (клієнт) |
| `aura_handshake_initiator_finish` | + | - | - | Завершити handshake (клієнт) |
| `aura_handshake_initiator_destroy` | + | - | - | Знищити initiator handle |
| **Handshake — Responder** | | | |
| `aura_handshake_responder_start` | + | + | - | Прийняти handshake (сервер) |
| `aura_handshake_responder_finish` | + | + | - | Завершити handshake (сервер) |
| `aura_handshake_responder_destroy` | + | + | - | Знищити responder handle |
| **Session (1:1)** | | | |
| `aura_session_encrypt` | + | + | - | Шифрування |
| `aura_session_decrypt` | + | + | - | Дешифрування |
| `aura_session_nonce_remaining` | + | + | - | Залишок nonce |
| `aura_session_destroy` | + | + | - | Знищити сесію |
| `aura_session_serialize_sealed` | + | + | - | Зберегти стан |
| `aura_session_deserialize_sealed` | + | + | - | Відновити стан |
| **Envelope** | | | |
| `aura_envelope_validate` | + | + | + | Валідація формату (без ключів) |
| **Key Derivation** | | | |
| `aura_derive_root_key` | + | + | - | HKDF з OPAQUE key |
| **Shamir SSS** | | | |
| `aura_shamir_split` | + | + | - | Розщепити секрет |
| `aura_shamir_reconstruct` | + | + | - | Відновити секрет |
| **Attachments / Media** | | | |
| `aura_attachment_generate_id` | + | + | + | Згенерувати attachment ID |
| `aura_attachment_generate_file_key` | + | + | - | Згенерувати file DEK |
| `aura_attachment_encrypt_chunk` | + | + | - | Шифрувати chunk |
| `aura_attachment_decrypt_chunk` | + | + | - | Дешифрувати chunk |
| `aura_attachment_manifest_create` | + | + | - | Створити AttachmentManifest |
| `aura_attachment_manifest_validate` | + | + | + | Валідувати AttachmentManifest |
| `aura_attachment_chunk_validate` | + | + | + | Валідувати encrypted chunk shape |
| **Group — Key Package** | | | |
| `aura_group_generate_key_package` | + | + | - | Створити KeyPackage |
| `aura_group_key_package_secrets_destroy` | + | + | - | Знищити секрети KP |
| **Group — Core** | | | |
| `aura_group_create` | + | + | - | Створити групу |
| `aura_group_create_shielded` | + | + | - | Створити shielded групу |
| `aura_group_create_with_policy` | + | + | - | Створити групу з custom policy |
| `aura_group_is_shielded` | + | + | - | Чи shield mode |
| `aura_group_get_security_policy` | + | + | - | Отримати policy деталі |
| `aura_group_join` | + | + | - | Приєднатися (Welcome) |
| `aura_group_join_external` | + | + | - | Приєднатися (зовнішній) |
| **Group — Management** | | | |
| `aura_group_add_member` | + | + | - | Додати учасника |
| `aura_group_remove_member` | + | + | - | Видалити учасника |
| `aura_group_update` | + | + | - | Оновити ключі |
| `aura_group_process_commit` | + | + | - | Обробити commit |
| **Group — Encrypt / Decrypt** | | | |
| `aura_group_encrypt` | + | + | - | Шифрування (група) |
| `aura_group_decrypt` | + | + | - | Дешифрування (група) |
| `aura_group_encrypt_sealed` | + | + | - | Sealed (анонімне) |
| `aura_group_encrypt_disappearing` | + | + | - | Disappearing (TTL) |
| `aura_group_encrypt_frankable` | + | + | - | Frankable (доказ) |
| `aura_group_reveal_sealed` | + | + | - | Розшифрувати sealed |
| `aura_group_verify_franking` | + | + | + | Перевірити franking tag |
| **Group — State** | | | |
| `aura_group_get_id` | + | + | - | Group ID |
| `aura_group_get_epoch` | + | + | - | Поточна epoch |
| `aura_group_get_my_leaf_index` | + | + | - | Мій leaf index |
| `aura_group_get_member_count` | + | + | - | К-ть учасників |
| `aura_group_get_member_leaf_indices` | + | + | - | Leaf indices всіх |
| `aura_group_destroy` | + | + | - | Знищити групу |
| **Group — Serialization** | | | |
| `aura_group_serialize` | + | + | - | Зберегти стан групи |
| `aura_group_deserialize` | + | + | - | Відновити стан групи |
| `aura_group_export_public_state` | + | + | - | Публічний стан |
| `aura_group_authorize_external_join` | + | + | - | Видати дозвіл на external join |
| **Group — PSK & ReInit** | | | |
| `aura_group_set_psk` | + | + | - | Встановити PSK |
| `aura_group_get_pending_reinit` | + | + | - | Перевірити ReInit |
| **Group — Edit / Delete** | | | |
| `aura_group_encrypt_edit` | + | + | - | Шифрувати edit-повідомлення |
| `aura_group_encrypt_delete` | + | + | - | Шифрувати delete-повідомлення |
| `aura_group_decrypt_ex` | + | + | - | Повне дешифрування (з sealed/franking) |
| `aura_group_decrypt_result_free` | + | + | - | Звільнити AuraGroupDecryptResult |
| `aura_group_compute_message_id` | + | + | + | Обчислити стабільний Message ID |
| **Session — Identity** | | | |
| `aura_session_get_id` | + | + | - | Отримати Session ID |
| `aura_session_get_identity_binding_hash` | + | + | - | Отримати Identity Binding Hash |
| `aura_session_get_peer_identity` | + | + | - | Отримати identity peer-а |
| `aura_session_get_local_identity` | + | + | - | Отримати локальну identity |
| **OTK Replenishment** | | | |
| `aura_prekey_bundle_replenish` | + | + | - | Поповнити OTK пул |
| **Envelope Metadata** | | | |
| `aura_envelope_metadata_parse` | + | + | - | Розпарсити EnvelopeMetadata |
| `aura_envelope_metadata_free` | + | + | - | Звільнити EnvelopeMetadata |
| **Event Callbacks** | | | |
| `aura_session_set_event_handler` | + | + | - | Реєстрація callback-ів сесії |
| `aura_group_set_event_handler` | + | + | - | Реєстрація callback-ів групи |
| `aura_identity_set_event_handler` | + | + | - | Реєстрація callback-ів identity |
| **Memory / Errors** | | | |
| `aura_buffer_release` | + | + | + | Звільнити data буфера |
| `aura_buffer_alloc` | + | + | + | Алокувати буфер |
| `aura_buffer_free` | + | + | + | Звільнити буфер цілком |
| `aura_error_free` | + | + | + | Звільнити помилку |
| `aura_error_string` | + | + | + | Текст помилки |
| `aura_secure_wipe` | + | + | + | Занулити пам'ять |

### Relay — мінімальний набір (9 функцій)

Relay-сервер НЕ має ключів і НЕ дешифрує повідомлення. Він лише:
- пересилає зашифровані envelope між клієнтами
- зберігає та роздає PreKey bundles (як opaque bytes)
- може валідувати формат envelope
- може перевіряти franking tags (модерація контенту)

```
aura_init / aura_shutdown / aura_version
aura_envelope_validate
aura_group_verify_franking
aura_buffer_release / aura_buffer_alloc / aura_buffer_free
aura_error_free / aura_error_string
aura_secure_wipe
```

### Server Endpoint — все крім initiator

При збірці з `AURA_SERVER_BUILD` handshake initiator функції та тип `AuraHandshakeInitiatorHandle` не компілюються. Сервер приймає з'єднання через responder.

Примітка: low-level VoIP, managed sealed-state helpers і attachment streaming surface теж задекларовані в `include/aura_client_api.h`; для цих підрозділів header лишається найповнішим списком прототипів.

## Current snapshot contract updates

Поточний HEAD містить такі інтеграторсько-видимі зміни поверх hardening cycle:

- більшість вхідних буферів мають жорсткі розмірні ліміти, а oversized input повертає `AURA_ERROR_INVALID_INPUT`;
- manual time provider тепер тільки forward-only: спроба відкотити clock назад також повертає `AURA_ERROR_INVALID_INPUT`;
- low-level VoIP destroy entry points працюють через `**handle`, зануляють слот і безпечні при повторному destroy;
- конкурентний доступ до одного й того самого native handle повертає `AURA_ERROR_BUSY` замість блокування.

Практичні дії для інтегратора:

1. На клієнті перевіряти розміри payload локально до FFI-виклику (`encrypt/decrypt/handshake`), щоб уникати зайвих алокацій.
2. На сервері ставити transport-level body limits (HTTP/WebSocket frame caps) не вище протокольних.
3. Якщо отримали `AURA_ERROR_INVALID_INPUT` через розмір або rewind manual clock, трактувати як policy/usage rejection (не як retryable transport failure).
4. Якщо отримали `AURA_ERROR_BUSY`, не reuse-ити той самий handle паралельно без зовнішньої синхронізації.

## Зміст

- [Типи та структури](#типи-та-структури)
- [Коди помилок](#коди-помилок)
- [Ініціалізація](#ініціалізація)
- [Identity (ідентичність)](#identity)
- [Manual Time Provider](#manual-time-provider)
- [Pre-Key Bundle](#pre-key-bundle)
- [Handshake — Initiator (Client only)](#handshake--initiator)
- [Handshake — Responder (Client + Server)](#handshake--responder)
- [Session (1:1 сесія)](#session-11)
- [Envelope Validation (Client + Server + Relay)](#envelope-validation)
- [Session Serialization (sealed)](#session-serialization)
- [Key Derivation](#key-derivation)
- [Shamir Secret Sharing](#shamir-secret-sharing)
- [Attachments / Media](#attachments--media)
- [Group — Key Package](#group--key-package)
- [Group — Create / Join](#group--create--join)
- [Group — Member Management](#group--member-management)
- [Group — Encrypt / Decrypt](#group--encrypt--decrypt)
- [Group — Sealed / Disappearing / Frankable](#group--sealed--disappearing--frankable)
- [Group — State & Getters](#group--state--getters)
- [Group — Serialization](#group--serialization)
- [Group — PSK & ReInit](#group--psk--reinit)
- [Buffer & Memory Management (Client + Server + Relay)](#buffer--memory-management)
- [Error Handling (Client + Server + Relay)](#error-handling)
- [Ownership & Lifecycle](#ownership--lifecycle)
- [Thread Safety](#thread-safety)

---

## Типи та структури

```c
// Opaque handles — не дивитися всередину, тільки передавати у функції
typedef struct AuraIdentityHandle AuraIdentityHandle;
typedef struct AuraSessionHandle AuraSessionHandle;
typedef struct AuraVoipSessionHandle AuraVoipSessionHandle;
typedef struct AuraGroupSessionHandle AuraGroupSessionHandle;
typedef struct AuraKeyPackageSecretsHandle AuraKeyPackageSecretsHandle;
typedef struct AuraHandshakeInitiatorHandle AuraHandshakeInitiatorHandle;  // #ifndef AURA_SERVER_BUILD
typedef struct AuraHandshakeResponderHandle AuraHandshakeResponderHandle;
typedef struct AuraVoipCallInitiatorHandle AuraVoipCallInitiatorHandle;
typedef struct AuraSealedStateCounterTrackerHandle AuraSealedStateCounterTrackerHandle;
typedef struct AuraSealedStateSlotHandle AuraSealedStateSlotHandle;
typedef struct AuraTimeProviderHandle AuraTimeProviderHandle;

// Буфер для передачі бінарних даних. Caller owns data і звільняє через
// aura_buffer_release або aura_buffer_free. Перед повторним використанням
// того самого out-слота старий data треба звільнити явно.
typedef struct AuraBuffer {
    uint8_t* data;
    size_t   length;
} AuraBuffer;

// Структура помилки. Звільняти message через aura_error_free.
typedef struct AuraError {
    AuraErrorCode code;
    char*        message;   // UTF-8 null-terminated, або NULL
} AuraError;

// Конфігурація сесії (опційна).
typedef struct AuraSessionConfig {
    uint32_t max_messages_per_chain;  // за замовчуванням 1000
} AuraSessionConfig;

// Security policy для групових сесій (Shield Mode).
typedef struct AuraGroupSecurityPolicy {
    uint32_t max_messages_per_epoch;        // 10..100000 (0 = default)
    uint32_t max_skipped_keys_per_sender;   // 1..32 (0 = default)
    uint8_t  block_external_join;           // 0/1
    uint8_t  enhanced_key_schedule;         // 0/1
    uint8_t  mandatory_franking;            // 0/1
} AuraGroupSecurityPolicy;

// Тип envelope для 1:1 повідомлень.
typedef enum {
    AURA_ENVELOPE_REQUEST        = 0,
    AURA_ENVELOPE_RESPONSE       = 1,
    AURA_ENVELOPE_NOTIFICATION   = 2,
    AURA_ENVELOPE_HEARTBEAT      = 3,
    AURA_ENVELOPE_ERROR_RESPONSE = 4
} AuraEnvelopeType;
```

### Розміри ключів (константи)

| Константа | Байти | Опис |
|-----------|-------|------|
| X25519 public key | 32 | Curve25519 DH public key |
| Ed25519 public key | 32 | Ed25519 signing public key |
| ML-KEM-768 public key | 1184 | Post-quantum KEM public key |
| AES-256 key | 32 | Для sealed state encryption |
| AES-GCM nonce | 12 | Для reveal_sealed |
| HMAC / franking tag | 32 | Для SSS auth / franking |
| PSK | 32 | Pre-Shared Key мінімум |

---

## Коди помилок

```c
typedef enum {
    AURA_SUCCESS              = 0,   // OK
    AURA_ERROR_GENERIC        = 1,   // Внутрішня помилка
    AURA_ERROR_INVALID_INPUT  = 2,   // Невірні параметри
    AURA_ERROR_KEY_GENERATION = 3,   // Помилка генерації ключів
    AURA_ERROR_DERIVE_KEY     = 4,   // Помилка HKDF/KDF
    AURA_ERROR_HANDSHAKE      = 5,   // Помилка handshake
    AURA_ERROR_ENCRYPTION     = 6,   // Помилка шифрування
    AURA_ERROR_DECRYPTION     = 7,   // Помилка дешифрування
    AURA_ERROR_DECODE         = 8,   // Помилка Protobuf decode
    AURA_ERROR_ENCODE         = 9,   // Помилка Protobuf encode
    AURA_ERROR_BUFFER_TOO_SMALL = 10,// Буфер замалий
    AURA_ERROR_OBJECT_DISPOSED  = 11,// Handle вже знищений
    AURA_ERROR_PREPARE_LOCAL    = 12,// Локальні ключі не готові
    AURA_ERROR_OUT_OF_MEMORY    = 13,// Не вдалося алокувати пам'ять
    AURA_ERROR_CRYPTO_FAILURE   = 14,// Низькорівнева крипто-помилка
    AURA_ERROR_NULL_POINTER     = 15,// Передано NULL
    AURA_ERROR_INVALID_STATE    = 16,// Стан сесії невалідний
    AURA_ERROR_REPLAY_ATTACK    = 17,// Виявлено повторне повідомлення
    AURA_ERROR_SESSION_EXPIRED  = 18,// Сесія вичерпана
    AURA_ERROR_PQ_MISSING       = 19,// Відсутній PQ матеріал
    AURA_ERROR_GROUP_PROTOCOL   = 20,// Помилка групового протоколу
    AURA_ERROR_GROUP_MEMBERSHIP = 21,// Помилка членства в групі
    AURA_ERROR_TREE_INTEGRITY   = 22,// TreeKEM цілісність порушена
    AURA_ERROR_WELCOME          = 23,// Помилка обробки Welcome
    AURA_ERROR_MESSAGE_EXPIRED  = 24,// Повідомлення прострочене (TTL)
    AURA_ERROR_FRANKING         = 25,// Franking-верифікація невдала
    AURA_ERROR_VOIP_CALL        = 26,// Помилка VoIP call lifecycle
    AURA_ERROR_VOIP_MEDIA       = 27,// Помилка VoIP media decrypt/encrypt
    AURA_ERROR_VOIP_REKEY       = 28,// Помилка VoIP rekey
    AURA_ERROR_BUSY             = 29 // Handle уже використовується іншим викликом
} AuraErrorCode;
```

---

## Ініціалізація
> Ролі: **Client** + **Server** + **Relay**

### `aura_version`

```c
const char* aura_version(void);
```

Повертає версію бібліотеки як C-рядок (наприклад `"1.2.0"`). Не потрібно звільняти — статичний рядок.

### `aura_init`

```c
AuraErrorCode aura_init(void);
```

Ініціалізує криптографічну підсистему. **Викликати один раз** при старті програми, перед усіма іншими функціями.

- Повертає: `AURA_SUCCESS` або `AURA_ERROR_CRYPTO_FAILURE`

### `aura_shutdown`

```c
void aura_shutdown(void);
```

Завершення роботи бібліотеки. Викликати при виході з програми. Наразі no-op, але зарезервовано для майбутнього cleanup.

---

## Identity
> Ролі: **Client** + **Server** (Relay не використовує — немає identity)

### `aura_identity_create`

```c
AuraErrorCode aura_identity_create(
    AuraIdentityHandle** out_handle,  // [out] новий handle
    AuraError*           out_error    // [out] помилка
);
```

Створює нову випадкову ідентичність (Ed25519 + X25519 + ML-KEM-768 + Signed Pre-Key + 100 OPK).

- `out_handle`: буде записано вказівник на новий `AuraIdentityHandle`
- Після використання знищити через `aura_identity_destroy`

### `aura_identity_create_from_seed`

```c
AuraErrorCode aura_identity_create_from_seed(
    const uint8_t* seed,          // [in] master seed, мін. 32 байти
    size_t         seed_length,   // [in] розмір seed
    AuraIdentityHandle** out_handle,
    AuraError*           out_error
);
```

Створює **детерміністичну** ідентичність з seed (master key). Один seed завжди дає однакові ключі. Membership ID = `"default"`.

- `seed`: мінімум 32 байти, максимум 10 МБ
- Використовується для відновлення ідентичності на іншому пристрої

### `aura_identity_create_with_context`

```c
AuraErrorCode aura_identity_create_with_context(
    const uint8_t* seed,
    size_t         seed_length,
    const char*    membership_id,         // [in] UTF-8 ідентифікатор контексту
    size_t         membership_id_length,  // [in] довжина без null-terminator
    AuraIdentityHandle** out_handle,
    AuraError*           out_error
);
```

Як `create_from_seed`, але з явним `membership_id`. Різні `membership_id` з одним seed дають різні ключі. Корисно для multi-device / multi-account.

### `aura_identity_get_x25519_public`

```c
AuraErrorCode aura_identity_get_x25519_public(
    const AuraIdentityHandle* handle,
    uint8_t* out_key,          // [out] буфер мін. 32 байти
    size_t   out_key_length,   // [in] розмір буфера (>= 32)
    AuraError* out_error
);
```

Копіює X25519 identity public key (32 байти) у `out_key`.

### `aura_identity_get_ed25519_public`

```c
AuraErrorCode aura_identity_get_ed25519_public(
    const AuraIdentityHandle* handle,
    uint8_t* out_key,          // [out] буфер мін. 32 байти
    size_t   out_key_length,   // [in] розмір буфера (>= 32)
    AuraError* out_error
);
```

Копіює Ed25519 signing public key (32 байти) у `out_key`.

### `aura_identity_get_kyber_public`

```c
AuraErrorCode aura_identity_get_kyber_public(
    const AuraIdentityHandle* handle,
    uint8_t* out_key,          // [out] буфер мін. 1184 байти
    size_t   out_key_length,   // [in] розмір буфера (>= 1184)
    AuraError* out_error
);
```

Копіює ML-KEM-768 public key (1184 байти) у `out_key`.

### `aura_identity_destroy`

```c
void aura_identity_destroy(AuraIdentityHandle** handle);
```

Знищує identity handle. Зануляє `*handle` в NULL. Безпечно при `handle == NULL` або `*handle == NULL`. Секретні ключі wiped з пам'яті.

---

## Manual Time Provider
> Ролі: **Client** + **Server**

Manual clock потрібен для deterministic tests, trusted-time restore flow та TTL/expiry перевірок без покладання на локальний wall clock.

### `aura_time_provider_manual_create`

```c
AuraErrorCode aura_time_provider_manual_create(
    uint64_t                 initial_now_unix,
    AuraTimeProviderHandle**  out_handle,
    AuraError*                out_error
);
```

Створює mutable clock handle з початковим Unix timestamp.

### `aura_time_provider_manual_set_now_unix`

```c
AuraErrorCode aura_time_provider_manual_set_now_unix(
    AuraTimeProviderHandle* handle,
    uint64_t               now_unix,
    AuraError*              out_error
);
```

Пересуває manual clock тільки вперед. Значення, менші за поточний clock, відхиляються з `AURA_ERROR_INVALID_INPUT`.

### `aura_identity_set_time_provider`

```c
AuraErrorCode aura_identity_set_time_provider(
    AuraIdentityHandle*           identity_handle,
    const AuraTimeProviderHandle* time_provider_handle,
    AuraError*                    out_error
);
```

Прив'язує identity до explicit clock. Передайте `NULL`, щоб повернутися до системного часу.

### `aura_time_provider_destroy`

```c
void aura_time_provider_destroy(AuraTimeProviderHandle** handle);
```

Знищує manual clock handle та зануляє `*handle`.

---

## Pre-Key Bundle
> Ролі: **Client** + **Server** (Relay зберігає bundles як opaque bytes — не викликає цю функцію)

### `aura_prekey_bundle_create`

```c
AuraErrorCode aura_prekey_bundle_create(
    const AuraIdentityHandle* identity_keys,  // [in] identity handle
    AuraBuffer*               out_bundle,     // [out] Protobuf-encoded PreKeyBundle
    AuraError*                out_error
);
```

Створює PreKey bundle для передачі іншій стороні (через сервер/HTTPS). Bundle містить: identity public keys, signed pre-key, one-time pre-keys, ML-KEM public key.

- `out_bundle.data`: звільнити через `aura_buffer_release`
- Bundle передається peer'у, який використає його в `aura_handshake_initiator_start`

### `aura_prekey_bundle_replenish`

```c
AuraErrorCode aura_prekey_bundle_replenish(
    AuraIdentityHandle* identity_handle,
    uint32_t           count,           // [in] кількість нових OTK (> 0)
    AuraBuffer*         out_keys,        // [out] Protobuf PreKeyBundle з новими OTK
    AuraError*          out_error
);
```

Генерує `count` нових One-Time Pre-Keys та додає їх до локального пулу. Повертає частковий `PreKeyBundle` proto (тільки поле `one_time_pre_keys`) для завантаження на сервер.

- Викликати після отримання `on_otk_exhaustion_warning` callback (залишок < 10%)
- `out_keys.data`: звільнити через `aura_buffer_release`
- Повернений bundle надіслати на сервер через ваш API; сервер додає нові OTK до сховища

**Типовий OTK replenishment flow:**
```c
// У callback on_otk_exhaustion_warning:
AuraBuffer new_keys = {0};
AuraError err = {0};
aura_prekey_bundle_replenish(identity, 50, &new_keys, &err);
// Надіслати new_keys.data на сервер
upload_otks_to_server(new_keys.data, new_keys.length);
aura_buffer_release(&new_keys);
```

---

## Handshake — Initiator
> Ролі: **Client only** — недоступні при `AURA_SERVER_BUILD`

### `aura_handshake_initiator_start`

```c
AuraErrorCode aura_handshake_initiator_start(
    AuraIdentityHandle*        identity_keys,           // [in] локальна identity
    const uint8_t*            peer_prekey_bundle,       // [in] Protobuf bundle від peer
    size_t                    peer_prekey_bundle_length, // [in] розмір bundle (макс. 16 КБ)
    const AuraSessionConfig*   config,                   // [in] NULL = defaults (1000 msgs/chain)
    AuraHandshakeInitiatorHandle** out_handle,           // [out] initiator handle
    AuraBuffer*                out_handshake_init,        // [out] повідомлення для відправки peer
    AuraError*                 out_error
);
```

Починає X3DH+ML-KEM handshake як ініціатор.

**Потік:**
1. Ініціатор викликає `start` → отримує `handshake_init` bytes
2. Надсилає `handshake_init` респондеру
3. Отримує `handshake_ack` від респондера
4. Викликає `finish` → отримує `Session`

### `aura_handshake_initiator_finish`

```c
AuraErrorCode aura_handshake_initiator_finish(
    AuraHandshakeInitiatorHandle* handle,           // [in] handle від start (consumed!)
    const uint8_t*               handshake_ack,     // [in] відповідь від респондера
    size_t                       handshake_ack_length,
    AuraSessionHandle**           out_session,       // [out] готова сесія
    AuraError*                    out_error
);
```

Завершує handshake і створює готову сесію. **Handle consumed** — після виклику він порожній.

### `aura_handshake_initiator_destroy`

```c
void aura_handshake_initiator_destroy(AuraHandshakeInitiatorHandle** handle);
```

Знищує initiator handle. Викликати якщо handshake не завершено (відміна).

---

## Handshake — Responder
> Ролі: **Client** + **Server** (Relay не бере участі в handshake)

### `aura_handshake_responder_start`

```c
AuraErrorCode aura_handshake_responder_start(
    AuraIdentityHandle*         identity_keys,
    const uint8_t*             local_prekey_bundle,       // [in] свій Protobuf bundle
    size_t                     local_prekey_bundle_length,
    const uint8_t*             handshake_init,             // [in] від ініціатора
    size_t                     handshake_init_length,
    const AuraSessionConfig*    config,                     // [in] NULL = defaults
    AuraHandshakeResponderHandle** out_handle,
    AuraBuffer*                 out_handshake_ack,           // [out] відповідь для ініціатора
    AuraError*                  out_error
);
```

Обробляє `handshake_init` від ініціатора, генерує `handshake_ack`.

### `aura_handshake_responder_finish`

```c
AuraErrorCode aura_handshake_responder_finish(
    AuraHandshakeResponderHandle* handle,     // [in] consumed!
    AuraSessionHandle**           out_session, // [out] готова сесія
    AuraError*                    out_error
);
```

Завершує handshake і створює сесію. Handle consumed.

### `aura_handshake_responder_destroy`

```c
void aura_handshake_responder_destroy(AuraHandshakeResponderHandle** handle);
```

---

## Session (1:1)
> Ролі: **Client** + **Server** (Relay не шифрує/дешифрує)

### `aura_session_encrypt`

```c
AuraErrorCode aura_session_encrypt(
    AuraSessionHandle* handle,
    const uint8_t*    plaintext,               // [in] payload
    size_t            plaintext_length,          // [in] макс. 1 МБ
    AuraEnvelopeType   envelope_type,            // [in] тип повідомлення
    uint32_t          envelope_id,              // [in] ідентифікатор (для кореляції)
    const char*       correlation_id,           // [in] UTF-8, може бути NULL
    size_t            correlation_id_length,     // [in] довжина, 0 якщо NULL
    AuraBuffer*        out_encrypted_envelope,   // [out] Protobuf SecureEnvelope
    AuraError*         out_error
);
```

Шифрує plaintext у SecureEnvelope (AES-256-GCM-SIV, Double Ratchet).

- `envelope_type`: визначає семантику (request/response/notification/heartbeat)
- `envelope_id` + `correlation_id`: для зв'язки запит-відповідь (0 / NULL якщо не потрібно)
- `out_encrypted_envelope.data`: звільнити через `aura_buffer_release`
- Кожен `encrypt` споживає один nonce; коли nonce вичерпано — помилка `AURA_ERROR_SESSION_EXPIRED`

### `aura_session_decrypt`

```c
AuraErrorCode aura_session_decrypt(
    AuraSessionHandle* handle,
    const uint8_t*    encrypted_envelope,        // [in] Protobuf SecureEnvelope
    size_t            encrypted_envelope_length,  // [in] макс. 1 МБ
    AuraBuffer*        out_plaintext,             // [out] розшифровані дані
    AuraBuffer*        out_metadata,              // [out] Protobuf EnvelopeMetadata
    AuraError*         out_error
);
```

Дешифрує SecureEnvelope.

- `out_plaintext`: оригінальний payload
- `out_metadata`: містить `envelope_type`, `envelope_id`, `correlation_id`, `message_index`, `epoch`
- Обидва буфери звільнити через `aura_buffer_release`
- Replay detection: повторне повідомлення → `AURA_ERROR_REPLAY_ATTACK`

### `aura_session_nonce_remaining`

```c
AuraErrorCode aura_session_nonce_remaining(
    AuraSessionHandle* handle,
    uint64_t*         out_remaining,   // [out] кількість залишкових nonce
    AuraError*         out_error
);
```

Повертає кількість nonce, що залишилось для шифрування. Максимум 65 535. Коли < 10% — рекомендовано ініціювати re-handshake.

### `aura_session_destroy`

```c
void aura_session_destroy(AuraSessionHandle** handle);
```

Знищує сесію. Всі ключі wiped з пам'яті.

---

## Envelope Validation
> Ролі: **Client** + **Server** + **Relay** — основна функція для relay

### `aura_envelope_validate`

```c
AuraErrorCode aura_envelope_validate(
    const uint8_t* encrypted_envelope,
    size_t         encrypted_envelope_length,
    AuraError*      out_error
);
```

Перевіряє структуру SecureEnvelope **без дешифрування**. Перевіряє: версію протоколу, розміри полів, nonce format. Корисно для relay-серверів, що не мають ключів.

---

## Session Serialization
> Ролі: **Client** + **Server**

### `aura_session_serialize_sealed`

```c
AuraErrorCode aura_session_serialize_sealed(
    AuraSessionHandle* handle,
    const uint8_t*    key,               // [in] 32 байти AES-256 ключ
    size_t            key_length,         // [in] == 32
    uint64_t          external_counter,   // [in] монотонно зростаючий, > 0
    AuraBuffer*        out_state,          // [out] зашифрований стан
    AuraError*         out_error
);
```

Серіалізує стан сесії у зашифрований blob з anti-rollback лічильником.

- `key`: ключ шифрування стану (зберігати окремо!)
- `external_counter`: кожен наступний виклик має мати більший counter
- `out_state.data`: звільнити через `aura_buffer_release`

### `aura_session_deserialize_sealed`

```c
AuraErrorCode aura_session_deserialize_sealed(
    const uint8_t* state_bytes,           // [in] blob від serialize
    size_t         state_length,
    const uint8_t* key,                   // [in] 32 байти (той самий ключ)
    size_t         key_length,
    uint64_t       min_external_counter,  // [in] мінімально дозволений counter
    uint64_t*      out_external_counter,  // [out] counter з blob
    AuraSessionHandle** out_handle,        // [out] відновлена сесія
    AuraError*      out_error
);
```

Відновлює сесію із sealed state.

- Якщо counter у blob `< min_external_counter` → `AURA_ERROR_REPLAY_ATTACK`; рівність дозволена як ідемпотентне re-restore того самого blob
- `*out_external_counter` валідний тільки при `AURA_SUCCESS` (на помилці не використовувати/не persist-ити)
- Після успішного імпорту зберегти `*out_external_counter` для наступного `min_external_counter`

---

## Session — Identity & Verification
> Ролі: **Client** + **Server**

Після завершення handshake (`aura_handshake_initiator_finish` / `aura_handshake_responder_finish`) сесія містить повну ідентифікаційну інформацію peer-а. Використовуйте ці функції для peer verification перед тим як вважати сесію trusted.

### `AuraSessionPeerIdentity`

```c
typedef struct AuraSessionPeerIdentity {
    uint8_t ed25519_public[32];   // Ed25519 signing key (для fingerprint)
    uint8_t x25519_public[32];    // X25519 DH key
} AuraSessionPeerIdentity;
```

Фіксована структура, stack-allocated. Не потребує звільнення.

### `aura_session_get_id`

```c
AuraErrorCode aura_session_get_id(
    AuraSessionHandle* handle,
    AuraBuffer*        out_session_id,   // [out] 16 байт Session ID
    AuraError*         out_error
);
```

Повертає 16-байтний Session ID — детермінований ідентифікатор сесії, однаковий у обох сторін.

### `aura_session_get_identity_binding_hash`

```c
AuraErrorCode aura_session_get_identity_binding_hash(
    AuraSessionHandle* handle,
    AuraBuffer*        out_binding_hash,   // [out] 32 байти Identity Binding Hash
    AuraError*         out_error
);
```

Повертає 32-байтний Identity Binding Hash — криптографічно прив'язує конкретну пару ключів peer-а до цієї сесії. Порівнювати з очікуваним значенням для peer verification. Однаковий у обох сторін.

### `aura_session_get_peer_identity`

```c
AuraErrorCode aura_session_get_peer_identity(
    AuraSessionHandle*      handle,
    AuraSessionPeerIdentity* out_identity,   // [out] stack-allocated struct
    AuraError*              out_error
);
```

Повертає Ed25519 та X25519 public keys peer-а. Використовується для:
- порівняння з раніше збереженими ключами (TOFU / key pinning)
- відображення fingerprint у UI
- детектування key change attack

### `aura_session_get_local_identity`

```c
AuraErrorCode aura_session_get_local_identity(
    AuraSessionHandle*      handle,
    AuraSessionPeerIdentity* out_identity,   // [out] stack-allocated struct
    AuraError*              out_error
);
```

Повертає Ed25519 та X25519 public keys локальної сторони (з поточної сесії).

**Типовий peer verification flow:**
```c
AuraSessionPeerIdentity peer_id = {0};
aura_session_get_peer_identity(session, &peer_id, &err);

// Порівняти з відомими ключами:
if (memcmp(peer_id.ed25519_public, known_key, 32) != 0) {
    // Key mismatch — попередити або заблокувати
}

// Або отримати binding hash для верифікації:
AuraBuffer binding = {0};
aura_session_get_identity_binding_hash(session, &binding, &err);
// Показати binding.data як fingerprint і верифікувати з peer OOB
aura_buffer_release(&binding);
```

---

## Key Derivation
> Ролі: **Client** + **Server**

### `aura_derive_root_key`

```c
AuraErrorCode aura_derive_root_key(
    const uint8_t* opaque_session_key,        // [in] 32 байти (від OPAQUE)
    size_t         opaque_session_key_length,  // [in] == 32
    const uint8_t* user_context,              // [in] контекст (user ID, etc.)
    size_t         user_context_length,        // [in] > 0
    uint8_t*       out_root_key,              // [out] буфер мін. 32 байти
    size_t         out_root_key_length,        // [in] >= 32
    AuraError*      out_error
);
```

Виводить root key з OPAQUE session key + user context через HKDF. Для інтеграції з password-authenticated key exchange.

---

## Shamir Secret Sharing
> Ролі: **Client** + **Server**

### `aura_shamir_split`

```c
AuraErrorCode aura_shamir_split(
    const uint8_t* secret,            // [in] секрет для розщеплення
    size_t         secret_length,      // [in] 1..65536 байт
    uint8_t        threshold,          // [in] мін. шарів для відновлення (>= 2)
    uint8_t        share_count,        // [in] загальна кількість шарів (>= threshold)
    const uint8_t* auth_key,           // [in] 32 байти HMAC ключ для автентикації
    size_t         auth_key_length,    // [in] == 32
    AuraBuffer*     out_shares,         // [out] конкатенація всіх шарів + auth tag
    size_t*        out_share_length,   // [out] розмір одного шару
    AuraError*      out_error
);
```

Розщеплює секрет на `share_count` шарів (threshold-of-n).

**Формат `out_shares.data`:**
```
[ share_0 ][ share_1 ]...[ share_{n-1} ][ auth_tag_32_bytes ]
  ^--- кожен по *out_share_length байт ---^
```

- Загальний розмір: `share_count * (*out_share_length) + 32`
- `auth_key`: використовується для HMAC верифікації при reconstruct

### `aura_shamir_reconstruct`

```c
AuraErrorCode aura_shamir_reconstruct(
    const uint8_t* shares,            // [in] конкатенація шарів + auth tag
    size_t         shares_length,      // [in] == share_count * share_length + 32
    size_t         share_length,       // [in] розмір одного шару (з split)
    size_t         share_count,        // [in] кількість шарів (>= threshold)
    const uint8_t* auth_key,           // [in] 32 байти (той самий ключ)
    size_t         auth_key_length,
    AuraBuffer*     out_secret,         // [out] відновлений секрет
    AuraError*      out_error
);
```

Відновлює секрет з >= threshold шарів. Перевіряє HMAC автентичність.

---

## Attachments / Media
> Ролі: **Client** + **Server** (+ частково **Relay** для stateless validation)

Attachment flow у FFI працює як crypto/validation ядро. Transport (gRPC/HTTP/S3) поза межами бібліотеки.

### `aura_attachment_generate_id`

```c
AuraErrorCode aura_attachment_generate_id(
    AuraBuffer* out_attachment_id,
    AuraError*  out_error
);
```

Повертає випадковий 32-байтний `attachment_id`.

### `aura_attachment_generate_file_key`

```c
AuraErrorCode aura_attachment_generate_file_key(
    AuraBuffer* out_file_key,
    AuraError*  out_error
);
```

Повертає випадковий 32-байтний `file_key` (DEK) для одного файлу.

### `aura_attachment_encrypt_chunk`

```c
AuraErrorCode aura_attachment_encrypt_chunk(
    const uint8_t* file_key,
    size_t         file_key_length,
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const char*    mime_type,
    size_t         mime_type_length,
    uint64_t       total_size,
    uint32_t       chunk_size,
    uint32_t       chunk_index,
    uint32_t       chunk_count,
    const uint8_t* plaintext,
    size_t         plaintext_length,
    AuraBuffer*     out_nonce,
    AuraBuffer*     out_ciphertext,
    AuraError*      out_error
);
```

Шифрує один chunk через AES-256-GCM-SIV. Nonce детерміновано виводиться з `(file_key, attachment_id, chunk_index)`.

### `aura_attachment_decrypt_chunk`

```c
AuraErrorCode aura_attachment_decrypt_chunk(
    const uint8_t* file_key,
    size_t         file_key_length,
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const char*    mime_type,
    size_t         mime_type_length,
    uint64_t       total_size,
    uint32_t       chunk_size,
    uint32_t       chunk_index,
    uint32_t       chunk_count,
    const uint8_t* nonce,
    size_t         nonce_length,
    const uint8_t* ciphertext,
    size_t         ciphertext_length,
    AuraBuffer*     out_plaintext,
    AuraError*      out_error
);
```

Дешифрує один chunk. Перевіряє nonce/AAD відповідність контексту manifest.

### `aura_attachment_manifest_create`

```c
AuraErrorCode aura_attachment_manifest_create(
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const char*    mime_type,
    size_t         mime_type_length,
    uint64_t       total_size,
    uint32_t       chunk_size,
    uint32_t       chunk_count,
    const uint8_t* file_sha256,
    size_t         file_sha256_length,
    const uint8_t* encrypted_file_key,
    size_t         encrypted_file_key_length,
    AuraBuffer*     out_manifest,
    AuraError*      out_error
);
```

Створює protobuf `AttachmentManifest` blob для відправки через ваш messaging/transport шар.

У `AttachmentManifest` доступне optional поле `collage_index` для порядку елементів у collage Threads.

### `aura_attachment_manifest_validate`

```c
AuraErrorCode aura_attachment_manifest_validate(
    const uint8_t* manifest_bytes,
    size_t         manifest_length,
    AuraError*      out_error
);
```

Decode + strict validate `AttachmentManifest`.

### `aura_attachment_chunk_validate`

```c
AuraErrorCode aura_attachment_chunk_validate(
    const uint8_t* manifest_bytes,
    size_t         manifest_length,
    uint32_t       chunk_index,
    const uint8_t* nonce,
    size_t         nonce_length,
    const uint8_t* ciphertext,
    size_t         ciphertext_length,
    AuraError*      out_error
);
```

Stateless валідація форми encrypted chunk (розмір/index/nonce) без дешифрування.

---

## Group — Key Package
> Ролі: **Client** + **Server**

### `aura_group_generate_key_package`

```c
AuraErrorCode aura_group_generate_key_package(
    AuraIdentityHandle*          identity_handle,  // [in] identity
    const uint8_t*              credential,        // [in] credential (або NULL)
    size_t                      credential_length, // [in] 0 якщо NULL
    AuraBuffer*                  out_key_package,   // [out] Protobuf GroupKeyPackage
    AuraKeyPackageSecretsHandle** out_secrets,       // [out] секрети (зберегти для join!)
    AuraError*                   out_error
);
```

Генерує KeyPackage для вступу в групу. Секрети (`out_secrets`) потрібні для `aura_group_join` — зберегти до отримання Welcome.

- `credential`: опаковані дані (ім'я, роль, etc.) — вбудовуються в KeyPackage
- `out_key_package.data`: надіслати тому, хто робить Add

### `aura_group_key_package_secrets_destroy`

```c
void aura_group_key_package_secrets_destroy(AuraKeyPackageSecretsHandle** handle);
```

Знищити секрети key package (після join або при відміні).

---

## Group — Create / Join
> Ролі: **Client** + **Server**

### `aura_group_create`

```c
AuraErrorCode aura_group_create(
    AuraIdentityHandle*      identity_handle,
    const uint8_t*          credential,        // [in] credential (або NULL)
    size_t                  credential_length,
    AuraGroupSessionHandle** out_handle,        // [out] нова група
    AuraError*               out_error
);
```

Створює нову групу. Автор — єдиний член (leaf index 0, epoch 0).

### `aura_group_create_shielded`

```c
AuraErrorCode aura_group_create_shielded(
    AuraIdentityHandle*      identity_handle,
    const uint8_t*          credential,
    size_t                  credential_length,
    AuraGroupSessionHandle** out_handle,
    AuraError*               out_error
);
```

Створює групу з preset Shield Mode policy: enhanced KDF, BLAKE2b chain, mandatory franking, blocked external join, max 1000 messages/epoch, max 4 skipped keys/sender.

### `aura_group_create_with_policy`

```c
typedef struct AuraGroupSecurityPolicy {
    uint32_t max_messages_per_epoch;        // 10..100000 (0 = default 100000)
    uint32_t max_skipped_keys_per_sender;   // 1..32 (0 = default 32)
    uint8_t  block_external_join;           // 0 = false, 1 = true
    uint8_t  enhanced_key_schedule;         // 0 = false, 1 = true
    uint8_t  mandatory_franking;            // 0 = false, 1 = true
} AuraGroupSecurityPolicy;

AuraErrorCode aura_group_create_with_policy(
    AuraIdentityHandle*            identity_handle,
    const uint8_t*                credential,
    size_t                        credential_length,
    const AuraGroupSecurityPolicy* policy,       // [in] custom policy
    AuraGroupSessionHandle**       out_handle,
    AuraError*                     out_error
);
```

Створює групу з custom security policy. Policy валідується при створенні — невалідні значення повертають `AURA_ERROR_INVALID_INPUT`. Policy прив'язується до group context hash і є **immutable** після створення.

### `aura_group_is_shielded`

```c
AuraErrorCode aura_group_is_shielded(
    AuraGroupSessionHandle* handle,
    uint8_t*               out_shielded,   // [out] 1 = shielded, 0 = default
    AuraError*              out_error
);
```

Перевіряє чи група в Shield Mode (enhanced_key_schedule AND mandatory_franking AND block_external_join).

### `aura_group_get_security_policy`

```c
AuraErrorCode aura_group_get_security_policy(
    AuraGroupSessionHandle*  handle,
    AuraGroupSecurityPolicy* out_policy,    // [out] заповнюється policy полями
    AuraError*               out_error
);
```

Повертає повну security policy групи. Корисно для UI (показати ліміти) або логіки (перевірити конкретний прапорець).

### `aura_group_join`

```c
AuraErrorCode aura_group_join(
    AuraIdentityHandle*          identity_handle,
    const uint8_t*              welcome_bytes,     // [in] Welcome від add_member
    size_t                      welcome_length,
    AuraKeyPackageSecretsHandle* secrets_handle,     // [in] секрети від generate_key_package
    AuraGroupSessionHandle**     out_group_handle,  // [out] групова сесія
    AuraError*                   out_error
);
```

Приєднується до групи через Welcome message (отриманий після Add-commit).

### `aura_group_authorize_external_join`

```c
AuraErrorCode aura_group_authorize_external_join(
    AuraGroupSessionHandle* handle,
    const uint8_t*         joiner_identity_ed25519_public,        // [in] 32 байти
    size_t                 joiner_identity_ed25519_public_length,  // [in] == 32
    const uint8_t*         joiner_identity_x25519_public,         // [in] 32 байти
    size_t                 joiner_identity_x25519_public_length,   // [in] == 32
    const uint8_t*         joiner_credential,      // [in] credential (або NULL)
    size_t                 joiner_credential_length,
    AuraBuffer*             out_authorization,       // [out] authorization artifact
    AuraError*              out_error
);
```

Видає authorization artifact для зовнішнього учасника. Чинний член групи підписує дані joiner-а. `out_authorization` треба передати joiner-у, який передасть його в `aura_group_join_external`.

- Викликається **до** того, як joiner викличе `aura_group_join_external`
- `out_authorization.data`: звільнити через `aura_buffer_release`

### `aura_group_join_external`

```c
AuraErrorCode aura_group_join_external(
    AuraIdentityHandle*      identity_handle,
    const uint8_t*          public_state,          // [in] від export_public_state
    size_t                  public_state_length,
    const uint8_t*          authorization,         // [in] artifact від authorize_external_join
    size_t                  authorization_length,
    const uint8_t*          credential,
    size_t                  credential_length,
    AuraGroupSessionHandle** out_group_handle,      // [out] групова сесія
    AuraBuffer*              out_commit,            // [out] commit для broadcast
    AuraError*               out_error
);
```

Зовнішній join з authorization artifact — через публічний стан групи. Commit треба надіслати всім членам.

**Повний flow external join:**
```
Існуючий член:
  aura_group_export_public_state() → public_state
  aura_group_authorize_external_join(joiner_ed, joiner_x, ...) → authorization

Joiner:
  aura_group_join_external(public_state, authorization, ...) → group_handle + commit

Всі члени:
  aura_group_process_commit(commit)
```

---

## Group — Member Management
> Ролі: **Client** + **Server**

### `aura_group_add_member`

```c
AuraErrorCode aura_group_add_member(
    AuraGroupSessionHandle* handle,
    const uint8_t*         key_package_bytes,   // [in] KeyPackage нового учасника
    size_t                 key_package_length,
    AuraBuffer*             out_commit,           // [out] commit → broadcast всім
    AuraBuffer*             out_welcome,          // [out] welcome → надіслати новому
    AuraError*              out_error
);
```

Додає учасника в групу.

- `out_commit`: надіслати **всім існуючим** учасникам (вони викличуть `process_commit`)
- `out_welcome`: надіслати **тільки новому** учаснику (він викличе `aura_group_join`)

### `aura_group_remove_member`

```c
AuraErrorCode aura_group_remove_member(
    AuraGroupSessionHandle* handle,
    uint32_t               leaf_index,   // [in] leaf index учасника для видалення
    AuraBuffer*             out_commit,   // [out] commit → broadcast
    AuraError*              out_error
);
```

Видаляє учасника за його leaf index. Commit надіслати всім.

### `aura_group_update`

```c
AuraErrorCode aura_group_update(
    AuraGroupSessionHandle* handle,
    AuraBuffer*             out_commit,   // [out] commit → broadcast
    AuraError*              out_error
);
```

Оновлює власні ключі (key rotation). Commit надіслати всім.

### `aura_group_process_commit`

```c
AuraErrorCode aura_group_process_commit(
    AuraGroupSessionHandle* handle,
    const uint8_t*         commit_bytes,   // [in] commit від іншого учасника
    size_t                 commit_length,
    AuraError*              out_error
);
```

Застосовує Commit від іншого учасника. Оновлює epoch, ключі, дерево.

---

## Group — Encrypt / Decrypt
> Ролі: **Client** + **Server**

### `aura_group_encrypt`

```c
AuraErrorCode aura_group_encrypt(
    AuraGroupSessionHandle* handle,
    const uint8_t*         plaintext,
    size_t                 plaintext_length,   // [in] макс. 1 МБ
    AuraBuffer*             out_ciphertext,     // [out] зашифроване повідомлення
    AuraError*              out_error
);
```

Шифрує повідомлення для групи (Sender Key).

### `aura_group_decrypt`

```c
AuraErrorCode aura_group_decrypt(
    AuraGroupSessionHandle* handle,
    const uint8_t*         ciphertext,
    size_t                 ciphertext_length,
    AuraBuffer*             out_plaintext,       // [out] розшифрований payload
    uint32_t*              out_sender_leaf,     // [out] leaf index відправника
    uint32_t*              out_generation,      // [out] generation counter
    AuraError*              out_error
);
```

Дешифрує групове повідомлення. Повертає leaf index відправника і generation (для ordering).

### `aura_group_decrypt_ex`

```c
typedef struct AuraGroupDecryptResult {
    AuraBuffer plaintext;             // розшифрований payload
    uint32_t  sender_leaf_index;     // leaf index відправника
    uint32_t  generation;           // generation counter
    uint32_t  content_type;         // 0=Normal 1=Sealed 2=Disappearing 3=SealedDisappearing 4=Edit 5=Delete
    uint32_t  ttl_seconds;          // TTL (для Disappearing; 0 якщо не встановлено)
    uint64_t  sent_timestamp;       // unix timestamp відправника (для Disappearing)
    AuraBuffer message_id;           // 32 байти стабільний Message ID
    AuraBuffer referenced_message_id;// 32 байти ID повідомлення-цілі (для Edit/Delete; порожній інакше)
    uint8_t   has_sealed_payload;   // 1 якщо є sealed payload
    uint8_t   has_franking_data;    // 1 якщо є franking data
    AuraBuffer sealed_hint;          // hint текст sealed-повідомлення (може бути порожнім)
    AuraBuffer sealed_encrypted_content; // зашифрований контент sealed-повідомлення
    AuraBuffer sealed_nonce;         // 12 байт nonce для reveal_sealed
    AuraBuffer sealed_key;           // 32 байти seal key для reveal_sealed
    AuraBuffer franking_tag;         // 32 байти HMAC commitment (для модерації)
    AuraBuffer franking_key;         // 32 байти franking key
    AuraBuffer franking_content;     // plaintext контент (для verify_franking)
    AuraBuffer franking_sealed_content; // sealed контент (для verify_franking; може бути порожнім)
} AuraGroupDecryptResult;

AuraErrorCode aura_group_decrypt_ex(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          ciphertext,
    size_t                  ciphertext_length,
    AuraGroupDecryptResult*  out_result,   // [out] caller-allocated struct (stack або heap)
    AuraError*               out_error
);
```

Розширена версія `aura_group_decrypt`. Повертає повну структуру з усіма полями: content_type, TTL, message ID, referenced ID (для Edit/Delete), sealed payload (для `reveal_sealed`), franking data (для `verify_franking`).

**Використання:**
```c
AuraGroupDecryptResult result = {0};  // нульова ініціалізація обов'язкова!
AuraError err = {0};

AuraErrorCode code = aura_group_decrypt_ex(group, ct, ct_len, &result, &err);
if (code == AURA_SUCCESS) {
    printf("From leaf %u, gen %u\n", result.sender_leaf_index, result.generation);
    if (result.content_type == 1 && result.has_sealed_payload) {
        // Є sealed payload — можна викликати reveal_sealed пізніше
        // result.sealed_key / sealed_nonce / sealed_encrypted_content
    }
    if (result.has_franking_data) {
        // Є franking data — можна verify_franking
    }
    aura_group_decrypt_result_free(&result);
}
```

### `aura_group_decrypt_result_free`

```c
void aura_group_decrypt_result_free(AuraGroupDecryptResult* result);
```

Звільняє всі heap-allocated буфери всередині `AuraGroupDecryptResult` через `aura_buffer_release`. **Не** звільняє сам struct (caller-allocated).

**Важливо:** Викликати лише після успішного `aura_group_decrypt_ex` (код `AURA_SUCCESS`). Якщо функція повернула помилку — struct не повністю заповнений; `aura_group_decrypt_result_free` все одно безпечний якщо struct був нульово-ініціалізований (`= {0}`), оскільки `aura_buffer_release` перевіряє `data != NULL`.

---

## Group — Sealed / Disappearing / Frankable
> Ролі: **Client** + **Server** (крім `aura_group_verify_franking` — також **Relay** для модерації)

### `aura_group_encrypt_sealed`

```c
AuraErrorCode aura_group_encrypt_sealed(
    AuraGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t         plaintext_length,
    const uint8_t* hint,              // [in] підказка (може бути NULL)
    size_t         hint_length,
    AuraBuffer*     out_ciphertext,
    AuraError*      out_error
);
```

Шифрує sealed-повідомлення (анонімний відправник). Одержувачі бачать повідомлення, але не знають від кого. `hint` — опціональна підказка для розкриття.

### `aura_group_encrypt_disappearing`

```c
AuraErrorCode aura_group_encrypt_disappearing(
    AuraGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t         plaintext_length,
    uint32_t       ttl_seconds,       // [in] час життя в секундах (макс. 7 днів)
    AuraBuffer*     out_ciphertext,
    AuraError*      out_error
);
```

Шифрує повідомлення з TTL. Після `ttl_seconds` дешифрування поверне `AURA_ERROR_MESSAGE_EXPIRED`.

### `aura_group_encrypt_frankable`

```c
AuraErrorCode aura_group_encrypt_frankable(
    AuraGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t         plaintext_length,
    AuraBuffer*     out_ciphertext,
    AuraError*      out_error
);
```

Шифрує frankable-повідомлення. Одержувач може довести третій стороні (модератору), що це повідомлення автентичне.

### `aura_group_reveal_sealed`

```c
AuraErrorCode aura_group_reveal_sealed(
    const uint8_t* hint,                     // [in] hint (або NULL)
    size_t         hint_length,
    const uint8_t* encrypted_content,        // [in] зашифрований контент
    size_t         encrypted_content_length,
    const uint8_t* nonce,                    // [in] 12 байт AES-GCM nonce
    size_t         nonce_length,             // [in] == 12
    const uint8_t* seal_key,                 // [in] 32 байти seal key
    size_t         seal_key_length,          // [in] == 32
    AuraBuffer*     out_plaintext,
    AuraError*      out_error
);
```

Розшифровує sealed-повідомлення за допомогою seal key (отриманого з decrypt result).

### `aura_group_verify_franking`

```c
AuraErrorCode aura_group_verify_franking(
    const uint8_t* franking_tag,             // [in] 32 байти
    size_t         franking_tag_length,
    const uint8_t* franking_key,             // [in] 32 байти
    size_t         franking_key_length,
    const uint8_t* content,                  // [in] оригінальний контент
    size_t         content_length,
    const uint8_t* sealed_content,           // [in] або NULL/0
    size_t         sealed_content_length,
    uint8_t*       out_valid,                // [out] 1 = valid, 0 = invalid
    AuraError*      out_error
);
```

Верифікує franking tag — доказ автентичності повідомлення для третьої сторони.

---

## Group — Edit / Delete
> Ролі: **Client** + **Server**

### `aura_group_encrypt_edit`

```c
AuraErrorCode aura_group_encrypt_edit(
    AuraGroupSessionHandle* handle,
    const uint8_t*         new_content,              // [in] новий текст повідомлення
    size_t                 new_content_length,        // [in] макс. 1 МБ
    const uint8_t*         target_message_id,        // [in] 32 байти — ID редагованого повідомлення
    size_t                 target_message_id_length,  // [in] == 32
    AuraBuffer*             out_ciphertext,
    AuraError*              out_error
);
```

Шифрує Edit-повідомлення — заміну вмісту раніше надісланого повідомлення. `target_message_id` — стабільний ID (з `aura_group_compute_message_id` або `aura_group_decrypt_ex.message_id`) редагованого повідомлення. При decrypt `content_type == 4` (Edit), `referenced_message_id` вказує на ціль.

### `aura_group_encrypt_delete`

```c
AuraErrorCode aura_group_encrypt_delete(
    AuraGroupSessionHandle* handle,
    const uint8_t*         target_message_id,        // [in] 32 байти — ID повідомлення для видалення
    size_t                 target_message_id_length,  // [in] == 32
    AuraBuffer*             out_ciphertext,
    AuraError*              out_error
);
```

Шифрує Delete-повідомлення — сигнал для видалення. `target_message_id` — ID повідомлення, яке треба видалити. При decrypt `content_type == 5` (Delete), `referenced_message_id` вказує на ціль.

**Content type константи:**

| Значення | Тип | Опис |
|----------|-----|------|
| 0 | Normal | Звичайне повідомлення |
| 1 | Sealed | Двошарове шифрування з hint |
| 2 | Disappearing | З TTL, протокольний enforcement |
| 3 | SealedDisappearing | Sealed + TTL |
| 4 | Edit | Редагування раніше надісланого |
| 5 | Delete | Видалення раніше надісланого |

---

## Group — State & Getters
> Ролі: **Client** + **Server**

### `aura_group_get_id`

```c
AuraErrorCode aura_group_get_id(
    AuraGroupSessionHandle* handle,
    AuraBuffer*             out_group_id,   // [out] 32 байти group ID
    AuraError*              out_error
);
```

### `aura_group_get_epoch`

```c
uint64_t aura_group_get_epoch(AuraGroupSessionHandle* handle);
```

Повертає поточну epoch групи. 0 при помилці або NULL handle.

### `aura_group_get_my_leaf_index`

```c
uint32_t aura_group_get_my_leaf_index(AuraGroupSessionHandle* handle);
```

Повертає мій leaf index у дереві. `UINT32_MAX` при помилці.

### `aura_group_get_member_count`

```c
uint32_t aura_group_get_member_count(AuraGroupSessionHandle* handle);
```

Повертає кількість учасників. 0 при помилці.

### `aura_group_get_member_leaf_indices`

```c
AuraErrorCode aura_group_get_member_leaf_indices(
    AuraGroupSessionHandle* handle,
    AuraBuffer*             out_indices,   // [out] масив u32 little-endian
    AuraError*              out_error
);
```

Повертає leaf indices всіх учасників як масив `uint32_t` у little-endian.

- Кількість елементів: `out_indices.length / 4`
- Зчитувати: `uint32_t idx = *(uint32_t*)(out_indices.data + i * 4)`

### `aura_group_compute_message_id`

```c
AuraErrorCode aura_group_compute_message_id(
    const uint8_t* group_id,            // [in] 32 байти group ID
    size_t         group_id_length,      // [in] == 32
    uint64_t       epoch,               // [in] epoch в якій надіслано повідомлення
    uint32_t       sender_leaf_index,   // [in] leaf index відправника
    uint32_t       generation,          // [in] generation counter з encrypt/decrypt
    AuraBuffer*     out_message_id,      // [out] 32 байти стабільний Message ID
    AuraError*      out_error
);
```

Обчислює детермінований 32-байтний Message ID з `(group_id, epoch, sender_leaf_index, generation)`. ID однаковий у відправника і всіх отримувачів — використовується для Edit/Delete targeting та дедублікації. Relay може викликати без identity (Relay-роль).

- Усі чотири вхідні параметри повинні точно збігатися між відправником і отримувачем
- `generation` береться з `aura_group_decrypt_ex.generation` або з `aura_group_encrypt` (якщо відправник зберігає його)
- `out_message_id.data`: звільнити через `aura_buffer_release`

### `aura_group_destroy`

```c
void aura_group_destroy(AuraGroupSessionHandle** handle);
```

---

## Group — Serialization
> Ролі: **Client** + **Server**

### `aura_group_serialize`

```c
AuraErrorCode aura_group_serialize(
    AuraGroupSessionHandle* handle,
    const uint8_t*         key,               // [in] 32 байти AES key
    size_t                 key_length,
    uint64_t               external_counter,  // [in] > 0, монотонно зростаючий
    AuraBuffer*             out_state,
    AuraError*              out_error
);
```

Серіалізує групову сесію у sealed blob. Аналогічно session serialization.

### `aura_group_deserialize`

```c
AuraErrorCode aura_group_deserialize(
    const uint8_t*          state_bytes,
    size_t                  state_length,
    const uint8_t*          key,                   // [in] 32 байти
    size_t                  key_length,
    uint64_t                min_external_counter,  // [in] anti-rollback
    uint64_t*               out_external_counter,  // [out] counter з blob
    AuraIdentityHandle*      identity_handle,       // [in] identity (для Ed25519 signing)
    AuraGroupSessionHandle** out_handle,
    AuraError*               out_error
);
```

Відновлює групову сесію. `identity_handle` потрібен для Ed25519 private key.

- Якщо counter у blob `< min_external_counter` → replay/rollback помилка; рівність дозволена як ідемпотентне re-restore.
- `*out_external_counter` валідний тільки при `AURA_SUCCESS` (на помилці не використовувати/не persist-ити)

### `aura_group_export_public_state`

```c
AuraErrorCode aura_group_export_public_state(
    AuraGroupSessionHandle* handle,
    AuraBuffer*             out_public_state,   // [out] публічний стан
    AuraError*              out_error
);
```

Експортує публічний стан групи (для `aura_group_join_external`). Не містить секретів.

---

## Group — PSK & ReInit
> Ролі: **Client** + **Server**

### `aura_group_set_psk`

```c
AuraErrorCode aura_group_set_psk(
    AuraGroupSessionHandle* handle,
    const uint8_t*         psk_id,         // [in] ідентифікатор PSK
    size_t                 psk_id_length,   // [in] > 0
    const uint8_t*         psk,            // [in] Pre-Shared Key (мін. 32 байти)
    size_t                 psk_length,      // [in] >= 32
    AuraError*              out_error
);
```

Встановлює PSK для наступного commit. PSK вмішується в epoch secret через HKDF.

### `aura_group_get_pending_reinit`

```c
AuraErrorCode aura_group_get_pending_reinit(
    AuraGroupSessionHandle* handle,
    AuraBuffer*             out_new_group_id,   // [out] новий group ID (або порожній)
    uint32_t*              out_new_version,    // [out] нова версія (0 якщо немає)
    AuraError*              out_error
);
```

Перевіряє чи є pending ReInit. Якщо `out_new_group_id.length > 0` — треба створити нову групу.

---

## Envelope Metadata
> Ролі: **Client** + **Server**

### `AuraEnvelopeMetadata`

```c
typedef struct AuraEnvelopeMetadata {
    AuraEnvelopeType envelope_type;       // тип конверта
    uint32_t        envelope_id;         // id повідомлення
    uint64_t        message_index;       // порядковий номер у chain
    char*           correlation_id;      // heap-allocated UTF-8 рядок (або NULL)
    size_t          correlation_id_length;
} AuraEnvelopeMetadata;
```

Caller-allocated struct (stack). Поле `correlation_id` — heap-allocated, звільняється через `aura_envelope_metadata_free`. Сам struct **не** звільняти.

### `aura_envelope_metadata_parse`

```c
AuraErrorCode aura_envelope_metadata_parse(
    const uint8_t*      metadata_bytes,   // [in] Protobuf EnvelopeMetadata bytes (з aura_session_decrypt)
    size_t              metadata_length,
    AuraEnvelopeMetadata* out_meta,        // [out] caller-allocated struct
    AuraError*           out_error
);
```

Парсить `out_metadata` blob, повернутий `aura_session_decrypt`, у зручну C-структуру.

```c
AuraBuffer plaintext = {0}, metadata_buf = {0};
AuraError err = {0};
aura_session_decrypt(session, ct, ct_len, &plaintext, &metadata_buf, &err);

AuraEnvelopeMetadata meta = {0};
aura_envelope_metadata_parse(metadata_buf.data, metadata_buf.length, &meta, &err);
printf("Type=%d id=%u corr=%s\n", meta.envelope_type, meta.envelope_id,
       meta.correlation_id ? meta.correlation_id : "(none)");

aura_envelope_metadata_free(&meta);
aura_buffer_release(&metadata_buf);
aura_buffer_release(&plaintext);
```

### `aura_envelope_metadata_free`

```c
void aura_envelope_metadata_free(AuraEnvelopeMetadata* meta);
```

Звільняє heap-allocated `correlation_id` та обнуляє відповідні поля. **Не** звільняє сам struct.

---

## Event Callbacks
> Ролі: **Client** + **Server**

Event callbacks дозволяють отримувати сповіщення про зміни стану сесії/групи/identity без polling. Кожен callback slot може бути `NULL` — відповідна подія ігнорується. `user_data` передається у кожен callback незміненим.

**Важливо про thread safety:** `user_data` та ресурси, на які він вказує, повинні бути доступні з тих потоків, в яких викликаються `encrypt`/`decrypt`/`process_commit`. Синхронізація — на стороні caller.

### Session event callbacks

```c
// Тип: виклик після завершення handshake. session_id — 16 байт.
typedef void (*AuraOnHandshakeCompleted)(const uint8_t* session_id, size_t session_id_len,
                                        void* user_data);

// Тип: виклик при кожній ротації DH ratchet.
typedef void (*AuraOnRatchetRotated)(uint64_t epoch, void* user_data);

// Тип: виклик при внутрішній помилці протоколу (non-fatal).
typedef void (*AuraOnSessionError)(AuraErrorCode code, const char* message, void* user_data);

// Тип: виклик коли залишок nonce падає нижче ~20%.
typedef void (*AuraOnNonceExhaustionWarning)(uint64_t remaining, uint64_t max_capacity,
                                             void* user_data);

// Тип: виклик коли багато повідомлень без DH ratchet кроку.
typedef void (*AuraOnRatchetStallingWarning)(uint64_t messages_since_ratchet, void* user_data);

typedef struct AuraSessionEventCallbacks {
    AuraOnHandshakeCompleted    on_handshake_completed;     // або NULL
    AuraOnRatchetRotated        on_ratchet_rotated;         // або NULL
    AuraOnSessionError          on_error;                   // або NULL
    AuraOnNonceExhaustionWarning on_nonce_exhaustion_warning; // або NULL
    AuraOnRatchetStallingWarning on_ratchet_stalling_warning; // або NULL
    void*                      user_data;                  // передається кожному callback
} AuraSessionEventCallbacks;

AuraErrorCode aura_session_set_event_handler(
    AuraSessionHandle*               handle,
    const AuraSessionEventCallbacks* callbacks,   // [in] копіюється за значенням
    AuraError*                       out_error
);
```

Реєструє C callback-и на сесії. Struct копіюється — caller може звільнити після виклику. Новий виклик `set_event_handler` замінює попередній handler.

### Group event callbacks

```c
// Тип: виклик при додаванні нового учасника через Commit.
// identity_ed25519 — 32 байти Ed25519 public key нового учасника.
typedef void (*AuraOnMemberAdded)(uint32_t leaf_index,
                                  const uint8_t* identity_ed25519, size_t identity_ed25519_len,
                                  void* user_data);

// Тип: виклик при видаленні учасника через Commit.
typedef void (*AuraOnMemberRemoved)(uint32_t leaf_index, void* user_data);

// Тип: виклик при кожному просуванні epoch.
typedef void (*AuraOnEpochAdvanced)(uint64_t new_epoch, uint32_t member_count, void* user_data);

// Тип: виклик коли sender key generation наближається до max_messages_per_epoch.
typedef void (*AuraOnSenderKeyExhaustionWarning)(uint32_t remaining, uint32_t max_capacity,
                                                 void* user_data);

// Тип: виклик коли Commit містить ReInit proposal. Група застаріла — мігрувати.
// new_group_id / new_group_id_len дійсні тільки під час callback.
typedef void (*AuraOnReInitProposed)(const uint8_t* new_group_id, size_t new_group_id_len,
                                     uint32_t new_version, void* user_data);

typedef struct AuraGroupEventCallbacks {
    AuraOnMemberAdded                on_member_added;                  // або NULL
    AuraOnMemberRemoved              on_member_removed;                // або NULL
    AuraOnEpochAdvanced              on_epoch_advanced;                // або NULL
    AuraOnSenderKeyExhaustionWarning on_sender_key_exhaustion_warning; // або NULL
    AuraOnReInitProposed             on_reinit_proposed;               // або NULL
    void*                           user_data;
} AuraGroupEventCallbacks;

AuraErrorCode aura_group_set_event_handler(
    AuraGroupSessionHandle*        handle,
    const AuraGroupEventCallbacks* callbacks,   // [in] копіюється за значенням
    AuraError*                     out_error
);
```

### Identity event callbacks

```c
// Тип: виклик коли OTK пул падає нижче ~10% від DEFAULT_ONE_TIME_KEY_COUNT (100).
// Потрібно викликати aura_prekey_bundle_replenish та завантажити нові OTK на сервер.
typedef void (*AuraOnOtkExhaustionWarning)(uint32_t remaining, uint32_t max_capacity,
                                           void* user_data);

typedef struct AuraIdentityEventCallbacks {
    AuraOnOtkExhaustionWarning on_otk_exhaustion_warning;   // або NULL
    void*                     user_data;
} AuraIdentityEventCallbacks;

AuraErrorCode aura_identity_set_event_handler(
    AuraIdentityHandle*              handle,
    const AuraIdentityEventCallbacks* callbacks,   // [in] копіюється за значенням
    AuraError*                       out_error
);
```

**Повний приклад реєстрації:**
```c
static void on_nonce_warn(uint64_t remaining, uint64_t max, void* ud) {
    printf("Nonce low: %llu / %llu — re-handshake soon\n", remaining, max);
}

static void on_otk_warn(uint32_t remaining, uint32_t max, void* ud) {
    // replenish OTKs
    aura_prekey_bundle_replenish((AuraIdentityHandle*)ud, 50, &keys, &err);
    upload_to_server(keys.data, keys.length);
    aura_buffer_release(&keys);
}

AuraSessionEventCallbacks session_cbs = {0};
session_cbs.on_nonce_exhaustion_warning = on_nonce_warn;
session_cbs.user_data = NULL;
aura_session_set_event_handler(session, &session_cbs, &err);

AuraIdentityEventCallbacks id_cbs = {0};
id_cbs.on_otk_exhaustion_warning = on_otk_warn;
id_cbs.user_data = identity;
aura_identity_set_event_handler(identity, &id_cbs, &err);
```

---

## Buffer & Memory Management
> Ролі: **Client** + **Server** + **Relay**

### `aura_buffer_release`

```c
void aura_buffer_release(AuraBuffer* buffer);
```

Зануляє та звільняє `buffer->data`. **Не** звільняє сам struct `AuraBuffer`. Використовувати для stack-allocated `AuraBuffer`:

```c
AuraBuffer buf = {0};
aura_session_encrypt(handle, ..., &buf, &err);
// використати buf.data / buf.length
aura_buffer_release(&buf);  // звільнити data, struct на стеку
```

FFI output writers не читають і не звільняють попередній вміст простих
`AuraBuffer*` / `out_handle` слотів. Якщо слот використовується повторно,
спочатку викличте `aura_buffer_release(&buf)` або відповідний `_destroy(&handle)`,
потім передавайте його в наступну FFI-функцію. Compound structs на кшталт
`AuraEncryptedFrame`, `AuraDecryptedFrame`, `AuraEnvelopeMetadata` і
`AuraGroupDecryptResult` все ще мають бути zero-initialized перед першим
використанням, бо їхні cleanup paths можуть дивитися на вкладені поля.

### `aura_buffer_alloc`

```c
AuraBuffer* aura_buffer_alloc(size_t capacity);
```

Алокує `AuraBuffer` на heap із заданим розміром. Повертає NULL якщо `capacity == 0`.

### `aura_buffer_free`

```c
void aura_buffer_free(AuraBuffer* buffer);
```

Зануляє та звільняє і data, і сам struct. Для heap-allocated буферів (від `aura_buffer_alloc`).

### `aura_secure_wipe`

```c
AuraErrorCode aura_secure_wipe(uint8_t* data, size_t length);
```

Гарантовано зануляє пам'ять (з compiler fence). Для видалення секретів з пам'яті.

---

## Error Handling
> Ролі: **Client** + **Server** + **Relay**

### `aura_error_free`

```c
void aura_error_free(AuraError* error);
```

Звільняє `error->message`. Викликати після обробки помилки. Безпечно при NULL.

### `aura_error_string`

```c
const char* aura_error_string(AuraErrorCode code);
```

Повертає людиночитабельний опис коду помилки (статичний рядок, не звільняти).

Практично важливо:

- `AURA_ERROR_INVALID_INPUT` покриває oversize input, malformed payload і rewind manual clock;
- `AURA_ERROR_BUSY` означає, що той самий native handle уже використовується іншим викликом;
- VoIP-specific помилки мапляться в `AURA_ERROR_VOIP_CALL`, `AURA_ERROR_VOIP_MEDIA`, `AURA_ERROR_VOIP_REKEY`.

### Патерн обробки помилок

```c
AuraError err = {0};
AuraBuffer buf = {0};

AuraErrorCode code = aura_session_encrypt(handle, data, len,
    AURA_ENVELOPE_REQUEST, 0, NULL, 0, &buf, &err);

if (code != AURA_SUCCESS) {
    printf("Error %d: %s\n", err.code, err.message);
    aura_error_free(&err);
    return;
}

// використати buf.data, buf.length
send_to_peer(buf.data, buf.length);
aura_buffer_release(&buf);
```

---

## Ownership & Lifecycle

### Правила ownership

1. **Handle** — caller owns. Завжди знищувати через відповідний `_destroy(Aura*Handle** handle)`; destroy зануляє `*handle`. Перед reuse того самого `out_handle` слота старий handle треба знищити явно.
2. **AuraBuffer.data** — caller owns. Звільняти через `aura_buffer_release` (stack) або `aura_buffer_free` (heap). Перед reuse того самого `AuraBuffer` out-слота старий `data` треба звільнити явно.
3. **AuraError.message** — caller owns. Звільняти через `aura_error_free`
4. **Consumed handles** — `_finish` забирає ownership, handle стає порожнім

### Типовий lifecycle 1:1 сесії (Client)

```
aura_init()
  ↓
aura_identity_create() → identity_handle
  ↓
aura_prekey_bundle_create() → bundle bytes
  ↓                    (передати peer)
aura_handshake_initiator_start() → initiator_handle + init_msg
  ↓                    (надіслати init_msg)
  ↓                    (отримати ack_msg)
aura_handshake_initiator_finish() → session_handle
  ↓
aura_session_encrypt() / aura_session_decrypt()  (повторювати)
  ↓
aura_session_serialize_sealed() → зберегти на диск
  ↓
aura_session_destroy()
aura_identity_destroy()
aura_shutdown()
```

### Типовий lifecycle групи (Client / Server)

```
aura_group_create() → group_handle              (або aura_group_join)
  ↓
aura_group_add_member() → commit + welcome      (надіслати учасникам)
  ↓
aura_group_encrypt() / aura_group_decrypt()       (повторювати)
  ↓
aura_group_process_commit()                      (при отриманні commit)
  ↓
aura_group_serialize() → зберегти на диск
  ↓
aura_group_destroy()
```

### Типовий lifecycle Relay

```
aura_init()
  ↓
// Отримати encrypted_envelope від клієнта
aura_envelope_validate(envelope, len, &err)    // перевірити формат
  ↓
// Переслати envelope одержувачу(ям) as-is
forward_to_recipients(envelope, len)
  ↓
// Модерація (опційно): перевірити franking tag
aura_group_verify_franking(tag, tag_len, key, key_len,
    content, content_len, sealed, sealed_len, &valid, &err)
  ↓
aura_shutdown()
```

Relay **ніколи не бачить plaintext** — працює виключно з зашифрованими байтами.

---

## Thread Safety

- **Різні** handle можна використовувати з різних потоків одночасно
- **Один і той самий** handle — НЕ thread-safe; конкурентний доступ може повернути `AURA_ERROR_BUSY`
- `aura_init` / `aura_shutdown` — викликати з одного потоку
- `aura_version`, `aura_error_string` — thread-safe (статичні дані)
