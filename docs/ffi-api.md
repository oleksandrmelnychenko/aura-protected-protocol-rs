# Ecliptix Protocol — C FFI API Reference

C API для інтеграції Ecliptix Protocol у будь-яку мову (Swift, Kotlin, C#, Python, C++, Go, etc.).

Header: `include/epp_api.h`
Бібліотека: `libecliptix_protocol.a` (staticlib) або `.dylib`/`.so`/`.dll` (cdylib)

---

## Ролі та профілі збірки

API розрахований на три ролі:

| Роль | Опис | Прапор збірки |
|------|------|---------------|
| **Client (Agent)** | Кінцевий пристрій користувача — ініціює handshake, шифрує/дешифрує, бере участь у групах | За замовчуванням (без прапорів) |
| **Server (Endpoint)** | Сервер, що приймає з'єднання від клієнтів — відповідає на handshake, шифрує/дешифрує | `EPP_SERVER_BUILD` (ховає initiator) |
| **Relay** | Проміжний сервер — лише пересилає зашифровані байти, не має ключів | `EPP_SERVER_BUILD` (використовує мінімум API) |

### Зведена таблиця функцій за ролями

`C` = Client/Agent, `S` = Server Endpoint, `R` = Relay

| Функція | C | S | R | Опис |
|---------|:-:|:-:|:-:|------|
| **Ініціалізація** | | | |
| `epp_version` | + | + | + | Версія бібліотеки |
| `epp_init` | + | + | + | Ініціалізація крипто |
| `epp_shutdown` | + | + | + | Завершення роботи |
| **Identity** | | | |
| `epp_identity_create` | + | + | - | Створити identity (випадкова) |
| `epp_identity_create_from_seed` | + | + | - | Створити identity (з seed) |
| `epp_identity_create_with_context` | + | + | - | Створити identity (seed + context) |
| `epp_identity_get_x25519_public` | + | + | - | Отримати X25519 public key |
| `epp_identity_get_ed25519_public` | + | + | - | Отримати Ed25519 public key |
| `epp_identity_get_kyber_public` | + | + | - | Отримати Kyber public key |
| `epp_identity_destroy` | + | + | - | Знищити identity |
| **Pre-Key Bundle** | | | |
| `epp_prekey_bundle_create` | + | + | - | Створити PreKey bundle |
| **Handshake — Initiator** | | | |
| `epp_handshake_initiator_start` | + | - | - | Почати handshake (клієнт) |
| `epp_handshake_initiator_finish` | + | - | - | Завершити handshake (клієнт) |
| `epp_handshake_initiator_destroy` | + | - | - | Знищити initiator handle |
| **Handshake — Responder** | | | |
| `epp_handshake_responder_start` | + | + | - | Прийняти handshake (сервер) |
| `epp_handshake_responder_finish` | + | + | - | Завершити handshake (сервер) |
| `epp_handshake_responder_destroy` | + | + | - | Знищити responder handle |
| **Session (1:1)** | | | |
| `epp_session_encrypt` | + | + | - | Шифрування |
| `epp_session_decrypt` | + | + | - | Дешифрування |
| `epp_session_nonce_remaining` | + | + | - | Залишок nonce |
| `epp_session_destroy` | + | + | - | Знищити сесію |
| `epp_session_serialize_sealed` | + | + | - | Зберегти стан |
| `epp_session_deserialize_sealed` | + | + | - | Відновити стан |
| **Envelope** | | | |
| `epp_envelope_validate` | + | + | + | Валідація формату (без ключів) |
| **Key Derivation** | | | |
| `epp_derive_root_key` | + | + | - | HKDF з OPAQUE key |
| **Shamir SSS** | | | |
| `epp_shamir_split` | + | + | - | Розщепити секрет |
| `epp_shamir_reconstruct` | + | + | - | Відновити секрет |
| **Group — Key Package** | | | |
| `epp_group_generate_key_package` | + | + | - | Створити KeyPackage |
| `epp_group_key_package_secrets_destroy` | + | + | - | Знищити секрети KP |
| **Group — Core** | | | |
| `epp_group_create` | + | + | - | Створити групу |
| `epp_group_create_shielded` | + | + | - | Створити shielded групу |
| `epp_group_create_with_policy` | + | + | - | Створити групу з custom policy |
| `epp_group_is_shielded` | + | + | - | Чи shield mode |
| `epp_group_get_security_policy` | + | + | - | Отримати policy деталі |
| `epp_group_join` | + | + | - | Приєднатися (Welcome) |
| `epp_group_join_external` | + | + | - | Приєднатися (зовнішній) |
| **Group — Management** | | | |
| `epp_group_add_member` | + | + | - | Додати учасника |
| `epp_group_remove_member` | + | + | - | Видалити учасника |
| `epp_group_update` | + | + | - | Оновити ключі |
| `epp_group_process_commit` | + | + | - | Обробити commit |
| **Group — Encrypt / Decrypt** | | | |
| `epp_group_encrypt` | + | + | - | Шифрування (група) |
| `epp_group_decrypt` | + | + | - | Дешифрування (група) |
| `epp_group_encrypt_sealed` | + | + | - | Sealed (анонімне) |
| `epp_group_encrypt_disappearing` | + | + | - | Disappearing (TTL) |
| `epp_group_encrypt_frankable` | + | + | - | Frankable (доказ) |
| `epp_group_reveal_sealed` | + | + | - | Розшифрувати sealed |
| `epp_group_verify_franking` | + | + | + | Перевірити franking tag |
| **Group — State** | | | |
| `epp_group_get_id` | + | + | - | Group ID |
| `epp_group_get_epoch` | + | + | - | Поточна epoch |
| `epp_group_get_my_leaf_index` | + | + | - | Мій leaf index |
| `epp_group_get_member_count` | + | + | - | К-ть учасників |
| `epp_group_get_member_leaf_indices` | + | + | - | Leaf indices всіх |
| `epp_group_destroy` | + | + | - | Знищити групу |
| **Group — Serialization** | | | |
| `epp_group_serialize` | + | + | - | Зберегти стан групи |
| `epp_group_deserialize` | + | + | - | Відновити стан групи |
| `epp_group_export_public_state` | + | + | - | Публічний стан |
| `epp_group_authorize_external_join` | + | + | - | Видати дозвіл на external join |
| **Group — PSK & ReInit** | | | |
| `epp_group_set_psk` | + | + | - | Встановити PSK |
| `epp_group_get_pending_reinit` | + | + | - | Перевірити ReInit |
| **Group — Edit / Delete** | | | |
| `epp_group_encrypt_edit` | + | + | - | Шифрувати edit-повідомлення |
| `epp_group_encrypt_delete` | + | + | - | Шифрувати delete-повідомлення |
| `epp_group_decrypt_ex` | + | + | - | Повне дешифрування (з sealed/franking) |
| `epp_group_decrypt_result_free` | + | + | - | Звільнити EppGroupDecryptResult |
| `epp_group_compute_message_id` | + | + | + | Обчислити стабільний Message ID |
| **Session — Identity** | | | |
| `epp_session_get_id` | + | + | - | Отримати Session ID |
| `epp_session_get_identity_binding_hash` | + | + | - | Отримати Identity Binding Hash |
| `epp_session_get_peer_identity` | + | + | - | Отримати identity peer-а |
| `epp_session_get_local_identity` | + | + | - | Отримати локальну identity |
| **OTK Replenishment** | | | |
| `epp_prekey_bundle_replenish` | + | + | - | Поповнити OTK пул |
| **Envelope Metadata** | | | |
| `epp_envelope_metadata_parse` | + | + | - | Розпарсити EnvelopeMetadata |
| `epp_envelope_metadata_free` | + | + | - | Звільнити EnvelopeMetadata |
| **Event Callbacks** | | | |
| `epp_session_set_event_handler` | + | + | - | Реєстрація callback-ів сесії |
| `epp_group_set_event_handler` | + | + | - | Реєстрація callback-ів групи |
| `epp_identity_set_event_handler` | + | + | - | Реєстрація callback-ів identity |
| **Memory / Errors** | | | |
| `epp_buffer_release` | + | + | + | Звільнити data буфера |
| `epp_buffer_alloc` | + | + | + | Алокувати буфер |
| `epp_buffer_free` | + | + | + | Звільнити буфер цілком |
| `epp_error_free` | + | + | + | Звільнити помилку |
| `epp_error_string` | + | + | + | Текст помилки |
| `epp_secure_wipe` | + | + | + | Занулити пам'ять |

### Relay — мінімальний набір (9 функцій)

Relay-сервер НЕ має ключів і НЕ дешифрує повідомлення. Він лише:
- пересилає зашифровані envelope між клієнтами
- зберігає та роздає PreKey bundles (як opaque bytes)
- може валідувати формат envelope
- може перевіряти franking tags (модерація контенту)

```
epp_init / epp_shutdown / epp_version
epp_envelope_validate
epp_group_verify_franking
epp_buffer_release / epp_buffer_alloc / epp_buffer_free
epp_error_free / epp_error_string
epp_secure_wipe
```

### Server Endpoint — все крім initiator

При збірці з `EPP_SERVER_BUILD` handshake initiator функції та тип `EppHandshakeInitiatorHandle` не компілюються. Сервер приймає з'єднання через responder.

## Зміст

- [Типи та структури](#типи-та-структури)
- [Коди помилок](#коди-помилок)
- [Ініціалізація](#ініціалізація)
- [Identity (ідентичність)](#identity)
- [Pre-Key Bundle](#pre-key-bundle)
- [Handshake — Initiator (Client only)](#handshake--initiator)
- [Handshake — Responder (Client + Server)](#handshake--responder)
- [Session (1:1 сесія)](#session-11)
- [Envelope Validation (Client + Server + Relay)](#envelope-validation)
- [Session Serialization (sealed)](#session-serialization)
- [Key Derivation](#key-derivation)
- [Shamir Secret Sharing](#shamir-secret-sharing)
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
typedef struct EppIdentityHandle EppIdentityHandle;
typedef struct EppSessionHandle EppSessionHandle;
typedef struct EppGroupSessionHandle EppGroupSessionHandle;
typedef struct EppKeyPackageSecretsHandle EppKeyPackageSecretsHandle;
typedef struct EppHandshakeInitiatorHandle EppHandshakeInitiatorHandle;  // #ifndef EPP_SERVER_BUILD
typedef struct EppHandshakeResponderHandle EppHandshakeResponderHandle;

// Буфер для передачі бінарних даних. Звільняти через epp_buffer_release або epp_buffer_free.
typedef struct EppBuffer {
    uint8_t* data;
    size_t   length;
} EppBuffer;

// Структура помилки. Звільняти message через epp_error_free.
typedef struct EppError {
    EppErrorCode code;
    char*        message;   // UTF-8 null-terminated, або NULL
} EppError;

// Конфігурація сесії (опційна).
typedef struct EppSessionConfig {
    uint32_t max_messages_per_chain;  // за замовчуванням 1000
} EppSessionConfig;

// Security policy для групових сесій (Shield Mode).
typedef struct EppGroupSecurityPolicy {
    uint32_t max_messages_per_epoch;        // 10..100000 (0 = default)
    uint32_t max_skipped_keys_per_sender;   // 1..32 (0 = default)
    uint8_t  block_external_join;           // 0/1
    uint8_t  enhanced_key_schedule;         // 0/1
    uint8_t  mandatory_franking;            // 0/1
} EppGroupSecurityPolicy;

// Тип envelope для 1:1 повідомлень.
typedef enum {
    EPP_ENVELOPE_REQUEST        = 0,
    EPP_ENVELOPE_RESPONSE       = 1,
    EPP_ENVELOPE_NOTIFICATION   = 2,
    EPP_ENVELOPE_HEARTBEAT      = 3,
    EPP_ENVELOPE_ERROR_RESPONSE = 4
} EppEnvelopeType;
```

### Розміри ключів (константи)

| Константа | Байти | Опис |
|-----------|-------|------|
| X25519 public key | 32 | Curve25519 DH public key |
| Ed25519 public key | 32 | Ed25519 signing public key |
| Kyber-768 public key | 1184 | Post-quantum KEM public key |
| AES-256 key | 32 | Для sealed state encryption |
| AES-GCM nonce | 12 | Для reveal_sealed |
| HMAC / franking tag | 32 | Для SSS auth / franking |
| PSK | 32 | Pre-Shared Key мінімум |

---

## Коди помилок

```c
typedef enum {
    EPP_SUCCESS              = 0,   // OK
    EPP_ERROR_GENERIC        = 1,   // Внутрішня помилка
    EPP_ERROR_INVALID_INPUT  = 2,   // Невірні параметри
    EPP_ERROR_KEY_GENERATION = 3,   // Помилка генерації ключів
    EPP_ERROR_DERIVE_KEY     = 4,   // Помилка HKDF/KDF
    EPP_ERROR_HANDSHAKE      = 5,   // Помилка handshake
    EPP_ERROR_ENCRYPTION     = 6,   // Помилка шифрування
    EPP_ERROR_DECRYPTION     = 7,   // Помилка дешифрування
    EPP_ERROR_DECODE         = 8,   // Помилка Protobuf decode
    EPP_ERROR_ENCODE         = 9,   // Помилка Protobuf encode
    EPP_ERROR_BUFFER_TOO_SMALL = 10,// Буфер замалий
    EPP_ERROR_OBJECT_DISPOSED  = 11,// Handle вже знищений
    EPP_ERROR_PREPARE_LOCAL    = 12,// Локальні ключі не готові
    EPP_ERROR_OUT_OF_MEMORY    = 13,// Не вдалося алокувати пам'ять
    EPP_ERROR_CRYPTO_FAILURE   = 14,// Низькорівнева крипто-помилка
    EPP_ERROR_NULL_POINTER     = 15,// Передано NULL
    EPP_ERROR_INVALID_STATE    = 16,// Стан сесії невалідний
    EPP_ERROR_REPLAY_ATTACK    = 17,// Виявлено повторне повідомлення
    EPP_ERROR_SESSION_EXPIRED  = 18,// Сесія вичерпана
    EPP_ERROR_PQ_MISSING       = 19,// Відсутній PQ матеріал
    EPP_ERROR_GROUP_PROTOCOL   = 20,// Помилка групового протоколу
    EPP_ERROR_GROUP_MEMBERSHIP = 21,// Помилка членства в групі
    EPP_ERROR_TREE_INTEGRITY   = 22,// TreeKEM цілісність порушена
    EPP_ERROR_WELCOME          = 23,// Помилка обробки Welcome
    EPP_ERROR_MESSAGE_EXPIRED  = 24,// Повідомлення прострочене (TTL)
    EPP_ERROR_FRANKING         = 25 // Franking-верифікація невдала
} EppErrorCode;
```

---

## Ініціалізація
> Ролі: **Client** + **Server** + **Relay**

### `epp_version`

```c
const char* epp_version(void);
```

Повертає версію бібліотеки як C-рядок (наприклад `"1.0.0"`). Не потрібно звільняти — статичний рядок.

### `epp_init`

```c
EppErrorCode epp_init(void);
```

Ініціалізує криптографічну підсистему. **Викликати один раз** при старті програми, перед усіма іншими функціями.

- Повертає: `EPP_SUCCESS` або `EPP_ERROR_CRYPTO_FAILURE`

### `epp_shutdown`

```c
void epp_shutdown(void);
```

Завершення роботи бібліотеки. Викликати при виході з програми. Наразі no-op, але зарезервовано для майбутнього cleanup.

---

## Identity
> Ролі: **Client** + **Server** (Relay не використовує — немає identity)

### `epp_identity_create`

```c
EppErrorCode epp_identity_create(
    EppIdentityHandle** out_handle,  // [out] новий handle
    EppError*           out_error    // [out] помилка
);
```

Створює нову випадкову ідентичність (Ed25519 + X25519 + Kyber-768 + Signed Pre-Key + 100 OPK).

- `out_handle`: буде записано вказівник на новий `EppIdentityHandle`
- Після використання знищити через `epp_identity_destroy`

### `epp_identity_create_from_seed`

```c
EppErrorCode epp_identity_create_from_seed(
    const uint8_t* seed,          // [in] master seed, мін. 32 байти
    size_t         seed_length,   // [in] розмір seed
    EppIdentityHandle** out_handle,
    EppError*           out_error
);
```

Створює **детерміністичну** ідентичність з seed (master key). Один seed завжди дає однакові ключі. Membership ID = `"default"`.

- `seed`: мінімум 32 байти, максимум 10 МБ
- Використовується для відновлення ідентичності на іншому пристрої

### `epp_identity_create_with_context`

```c
EppErrorCode epp_identity_create_with_context(
    const uint8_t* seed,
    size_t         seed_length,
    const char*    membership_id,         // [in] UTF-8 ідентифікатор контексту
    size_t         membership_id_length,  // [in] довжина без null-terminator
    EppIdentityHandle** out_handle,
    EppError*           out_error
);
```

Як `create_from_seed`, але з явним `membership_id`. Різні `membership_id` з одним seed дають різні ключі. Корисно для multi-device / multi-account.

### `epp_identity_get_x25519_public`

```c
EppErrorCode epp_identity_get_x25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,          // [out] буфер мін. 32 байти
    size_t   out_key_length,   // [in] розмір буфера (>= 32)
    EppError* out_error
);
```

Копіює X25519 identity public key (32 байти) у `out_key`.

### `epp_identity_get_ed25519_public`

```c
EppErrorCode epp_identity_get_ed25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,          // [out] буфер мін. 32 байти
    size_t   out_key_length,   // [in] розмір буфера (>= 32)
    EppError* out_error
);
```

Копіює Ed25519 signing public key (32 байти) у `out_key`.

### `epp_identity_get_kyber_public`

```c
EppErrorCode epp_identity_get_kyber_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,          // [out] буфер мін. 1184 байти
    size_t   out_key_length,   // [in] розмір буфера (>= 1184)
    EppError* out_error
);
```

Копіює Kyber-768 public key (1184 байти) у `out_key`.

### `epp_identity_destroy`

```c
void epp_identity_destroy(EppIdentityHandle** handle);
```

Знищує identity handle. Зануляє `*handle` в NULL. Безпечно при `handle == NULL` або `*handle == NULL`. Секретні ключі wiped з пам'яті.

---

## Pre-Key Bundle
> Ролі: **Client** + **Server** (Relay зберігає bundles як opaque bytes — не викликає цю функцію)

### `epp_prekey_bundle_create`

```c
EppErrorCode epp_prekey_bundle_create(
    const EppIdentityHandle* identity_keys,  // [in] identity handle
    EppBuffer*               out_bundle,     // [out] Protobuf-encoded PreKeyBundle
    EppError*                out_error
);
```

Створює PreKey bundle для передачі іншій стороні (через сервер/HTTPS). Bundle містить: identity public keys, signed pre-key, one-time pre-keys, Kyber public key.

- `out_bundle.data`: звільнити через `epp_buffer_release`
- Bundle передається peer'у, який використає його в `epp_handshake_initiator_start`

### `epp_prekey_bundle_replenish`

```c
EppErrorCode epp_prekey_bundle_replenish(
    EppIdentityHandle* identity_handle,
    uint32_t           count,           // [in] кількість нових OTK (> 0)
    EppBuffer*         out_keys,        // [out] Protobuf PreKeyBundle з новими OTK
    EppError*          out_error
);
```

Генерує `count` нових One-Time Pre-Keys та додає їх до локального пулу. Повертає частковий `PreKeyBundle` proto (тільки поле `one_time_pre_keys`) для завантаження на сервер.

- Викликати після отримання `on_otk_exhaustion_warning` callback (залишок < 10%)
- `out_keys.data`: звільнити через `epp_buffer_release`
- Повернений bundle надіслати на сервер через ваш API; сервер додає нові OTK до сховища

**Типовий OTK replenishment flow:**
```c
// У callback on_otk_exhaustion_warning:
EppBuffer new_keys = {0};
EppError err = {0};
epp_prekey_bundle_replenish(identity, 50, &new_keys, &err);
// Надіслати new_keys.data на сервер
upload_otks_to_server(new_keys.data, new_keys.length);
epp_buffer_release(&new_keys);
```

---

## Handshake — Initiator
> Ролі: **Client only** — недоступні при `EPP_SERVER_BUILD`

### `epp_handshake_initiator_start`

```c
EppErrorCode epp_handshake_initiator_start(
    EppIdentityHandle*        identity_keys,           // [in] локальна identity
    const uint8_t*            peer_prekey_bundle,       // [in] Protobuf bundle від peer
    size_t                    peer_prekey_bundle_length, // [in] розмір bundle (макс. 16 КБ)
    const EppSessionConfig*   config,                   // [in] NULL = defaults (1000 msgs/chain)
    EppHandshakeInitiatorHandle** out_handle,           // [out] initiator handle
    EppBuffer*                out_handshake_init,        // [out] повідомлення для відправки peer
    EppError*                 out_error
);
```

Починає X3DH+Kyber handshake як ініціатор.

**Потік:**
1. Ініціатор викликає `start` → отримує `handshake_init` bytes
2. Надсилає `handshake_init` респондеру
3. Отримує `handshake_ack` від респондера
4. Викликає `finish` → отримує `Session`

### `epp_handshake_initiator_finish`

```c
EppErrorCode epp_handshake_initiator_finish(
    EppHandshakeInitiatorHandle* handle,           // [in] handle від start (consumed!)
    const uint8_t*               handshake_ack,     // [in] відповідь від респондера
    size_t                       handshake_ack_length,
    EppSessionHandle**           out_session,       // [out] готова сесія
    EppError*                    out_error
);
```

Завершує handshake і створює готову сесію. **Handle consumed** — після виклику він порожній.

### `epp_handshake_initiator_destroy`

```c
void epp_handshake_initiator_destroy(EppHandshakeInitiatorHandle** handle);
```

Знищує initiator handle. Викликати якщо handshake не завершено (відміна).

---

## Handshake — Responder
> Ролі: **Client** + **Server** (Relay не бере участі в handshake)

### `epp_handshake_responder_start`

```c
EppErrorCode epp_handshake_responder_start(
    EppIdentityHandle*         identity_keys,
    const uint8_t*             local_prekey_bundle,       // [in] свій Protobuf bundle
    size_t                     local_prekey_bundle_length,
    const uint8_t*             handshake_init,             // [in] від ініціатора
    size_t                     handshake_init_length,
    const EppSessionConfig*    config,                     // [in] NULL = defaults
    EppHandshakeResponderHandle** out_handle,
    EppBuffer*                 out_handshake_ack,           // [out] відповідь для ініціатора
    EppError*                  out_error
);
```

Обробляє `handshake_init` від ініціатора, генерує `handshake_ack`.

### `epp_handshake_responder_finish`

```c
EppErrorCode epp_handshake_responder_finish(
    EppHandshakeResponderHandle* handle,     // [in] consumed!
    EppSessionHandle**           out_session, // [out] готова сесія
    EppError*                    out_error
);
```

Завершує handshake і створює сесію. Handle consumed.

### `epp_handshake_responder_destroy`

```c
void epp_handshake_responder_destroy(EppHandshakeResponderHandle** handle);
```

---

## Session (1:1)
> Ролі: **Client** + **Server** (Relay не шифрує/дешифрує)

### `epp_session_encrypt`

```c
EppErrorCode epp_session_encrypt(
    EppSessionHandle* handle,
    const uint8_t*    plaintext,               // [in] payload
    size_t            plaintext_length,          // [in] макс. 1 МБ
    EppEnvelopeType   envelope_type,            // [in] тип повідомлення
    uint32_t          envelope_id,              // [in] ідентифікатор (для кореляції)
    const char*       correlation_id,           // [in] UTF-8, може бути NULL
    size_t            correlation_id_length,     // [in] довжина, 0 якщо NULL
    EppBuffer*        out_encrypted_envelope,   // [out] Protobuf SecureEnvelope
    EppError*         out_error
);
```

Шифрує plaintext у SecureEnvelope (AES-256-GCM-SIV, Double Ratchet).

- `envelope_type`: визначає семантику (request/response/notification/heartbeat)
- `envelope_id` + `correlation_id`: для зв'язки запит-відповідь (0 / NULL якщо не потрібно)
- `out_encrypted_envelope.data`: звільнити через `epp_buffer_release`
- Кожен `encrypt` споживає один nonce; коли nonce вичерпано — помилка `EPP_ERROR_SESSION_EXPIRED`

### `epp_session_decrypt`

```c
EppErrorCode epp_session_decrypt(
    EppSessionHandle* handle,
    const uint8_t*    encrypted_envelope,        // [in] Protobuf SecureEnvelope
    size_t            encrypted_envelope_length,  // [in] макс. 1 МБ
    EppBuffer*        out_plaintext,             // [out] розшифровані дані
    EppBuffer*        out_metadata,              // [out] Protobuf EnvelopeMetadata
    EppError*         out_error
);
```

Дешифрує SecureEnvelope.

- `out_plaintext`: оригінальний payload
- `out_metadata`: містить `envelope_type`, `envelope_id`, `correlation_id`, `message_index`, `epoch`
- Обидва буфери звільнити через `epp_buffer_release`
- Replay detection: повторне повідомлення → `EPP_ERROR_REPLAY_ATTACK`

### `epp_session_nonce_remaining`

```c
EppErrorCode epp_session_nonce_remaining(
    EppSessionHandle* handle,
    uint64_t*         out_remaining,   // [out] кількість залишкових nonce
    EppError*         out_error
);
```

Повертає кількість nonce, що залишилось для шифрування. Максимум 65 535. Коли < 10% — рекомендовано ініціювати re-handshake.

### `epp_session_destroy`

```c
void epp_session_destroy(EppSessionHandle** handle);
```

Знищує сесію. Всі ключі wiped з пам'яті.

---

## Envelope Validation
> Ролі: **Client** + **Server** + **Relay** — основна функція для relay

### `epp_envelope_validate`

```c
EppErrorCode epp_envelope_validate(
    const uint8_t* encrypted_envelope,
    size_t         encrypted_envelope_length,
    EppError*      out_error
);
```

Перевіряє структуру SecureEnvelope **без дешифрування**. Перевіряє: версію протоколу, розміри полів, nonce format. Корисно для relay-серверів, що не мають ключів.

---

## Session Serialization
> Ролі: **Client** + **Server**

### `epp_session_serialize_sealed`

```c
EppErrorCode epp_session_serialize_sealed(
    EppSessionHandle* handle,
    const uint8_t*    key,               // [in] 32 байти AES-256 ключ
    size_t            key_length,         // [in] == 32
    uint64_t          external_counter,   // [in] монотонно зростаючий, > 0
    EppBuffer*        out_state,          // [out] зашифрований стан
    EppError*         out_error
);
```

Серіалізує стан сесії у зашифрований blob з anti-rollback лічильником.

- `key`: ключ шифрування стану (зберігати окремо!)
- `external_counter`: кожен наступний виклик має мати більший counter
- `out_state.data`: звільнити через `epp_buffer_release`

### `epp_session_deserialize_sealed`

```c
EppErrorCode epp_session_deserialize_sealed(
    const uint8_t* state_bytes,           // [in] blob від serialize
    size_t         state_length,
    const uint8_t* key,                   // [in] 32 байти (той самий ключ)
    size_t         key_length,
    uint64_t       min_external_counter,  // [in] останній прийнятий counter
    uint64_t*      out_external_counter,  // [out] counter з blob
    EppSessionHandle** out_handle,        // [out] відновлена сесія
    EppError*      out_error
);
```

Відновлює сесію із sealed state.

- Якщо counter у blob < `min_external_counter` → `EPP_ERROR_REPLAY_ATTACK`
- Зберегти `*out_external_counter` для наступного `min_external_counter`

---

## Session — Identity & Verification
> Ролі: **Client** + **Server**

Після завершення handshake (`epp_handshake_initiator_finish` / `epp_handshake_responder_finish`) сесія містить повну ідентифікаційну інформацію peer-а. Використовуйте ці функції для peer verification перед тим як вважати сесію trusted.

### `EppSessionPeerIdentity`

```c
typedef struct EppSessionPeerIdentity {
    uint8_t ed25519_public[32];   // Ed25519 signing key (для fingerprint)
    uint8_t x25519_public[32];    // X25519 DH key
} EppSessionPeerIdentity;
```

Фіксована структура, stack-allocated. Не потребує звільнення.

### `epp_session_get_id`

```c
EppErrorCode epp_session_get_id(
    EppSessionHandle* handle,
    EppBuffer*        out_session_id,   // [out] 16 байт Session ID
    EppError*         out_error
);
```

Повертає 16-байтний Session ID — детермінований ідентифікатор сесії, однаковий у обох сторін.

### `epp_session_get_identity_binding_hash`

```c
EppErrorCode epp_session_get_identity_binding_hash(
    EppSessionHandle* handle,
    EppBuffer*        out_binding_hash,   // [out] 32 байти Identity Binding Hash
    EppError*         out_error
);
```

Повертає 32-байтний Identity Binding Hash — криптографічно прив'язує конкретну пару ключів peer-а до цієї сесії. Порівнювати з очікуваним значенням для peer verification. Однаковий у обох сторін.

### `epp_session_get_peer_identity`

```c
EppErrorCode epp_session_get_peer_identity(
    EppSessionHandle*      handle,
    EppSessionPeerIdentity* out_identity,   // [out] stack-allocated struct
    EppError*              out_error
);
```

Повертає Ed25519 та X25519 public keys peer-а. Використовується для:
- порівняння з раніше збереженими ключами (TOFU / key pinning)
- відображення fingerprint у UI
- детектування key change attack

### `epp_session_get_local_identity`

```c
EppErrorCode epp_session_get_local_identity(
    EppSessionHandle*      handle,
    EppSessionPeerIdentity* out_identity,   // [out] stack-allocated struct
    EppError*              out_error
);
```

Повертає Ed25519 та X25519 public keys локальної сторони (з поточної сесії).

**Типовий peer verification flow:**
```c
EppSessionPeerIdentity peer_id = {0};
epp_session_get_peer_identity(session, &peer_id, &err);

// Порівняти з відомими ключами:
if (memcmp(peer_id.ed25519_public, known_key, 32) != 0) {
    // Key mismatch — попередити або заблокувати
}

// Або отримати binding hash для верифікації:
EppBuffer binding = {0};
epp_session_get_identity_binding_hash(session, &binding, &err);
// Показати binding.data як fingerprint і верифікувати з peer OOB
epp_buffer_release(&binding);
```

---

## Key Derivation
> Ролі: **Client** + **Server**

### `epp_derive_root_key`

```c
EppErrorCode epp_derive_root_key(
    const uint8_t* opaque_session_key,        // [in] 32 байти (від OPAQUE)
    size_t         opaque_session_key_length,  // [in] == 32
    const uint8_t* user_context,              // [in] контекст (user ID, etc.)
    size_t         user_context_length,        // [in] > 0
    uint8_t*       out_root_key,              // [out] буфер мін. 32 байти
    size_t         out_root_key_length,        // [in] >= 32
    EppError*      out_error
);
```

Виводить root key з OPAQUE session key + user context через HKDF. Для інтеграції з password-authenticated key exchange.

---

## Shamir Secret Sharing
> Ролі: **Client** + **Server**

### `epp_shamir_split`

```c
EppErrorCode epp_shamir_split(
    const uint8_t* secret,            // [in] секрет для розщеплення
    size_t         secret_length,      // [in] 1..65536 байт
    uint8_t        threshold,          // [in] мін. шарів для відновлення (>= 2)
    uint8_t        share_count,        // [in] загальна кількість шарів (>= threshold)
    const uint8_t* auth_key,           // [in] 32 байти HMAC ключ для автентикації
    size_t         auth_key_length,    // [in] == 32
    EppBuffer*     out_shares,         // [out] конкатенація всіх шарів + auth tag
    size_t*        out_share_length,   // [out] розмір одного шару
    EppError*      out_error
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

### `epp_shamir_reconstruct`

```c
EppErrorCode epp_shamir_reconstruct(
    const uint8_t* shares,            // [in] конкатенація шарів + auth tag
    size_t         shares_length,      // [in] == share_count * share_length + 32
    size_t         share_length,       // [in] розмір одного шару (з split)
    size_t         share_count,        // [in] кількість шарів (>= threshold)
    const uint8_t* auth_key,           // [in] 32 байти (той самий ключ)
    size_t         auth_key_length,
    EppBuffer*     out_secret,         // [out] відновлений секрет
    EppError*      out_error
);
```

Відновлює секрет з >= threshold шарів. Перевіряє HMAC автентичність.

---

## Group — Key Package
> Ролі: **Client** + **Server**

### `epp_group_generate_key_package`

```c
EppErrorCode epp_group_generate_key_package(
    EppIdentityHandle*          identity_handle,  // [in] identity
    const uint8_t*              credential,        // [in] credential (або NULL)
    size_t                      credential_length, // [in] 0 якщо NULL
    EppBuffer*                  out_key_package,   // [out] Protobuf GroupKeyPackage
    EppKeyPackageSecretsHandle** out_secrets,       // [out] секрети (зберегти для join!)
    EppError*                   out_error
);
```

Генерує KeyPackage для вступу в групу. Секрети (`out_secrets`) потрібні для `epp_group_join` — зберегти до отримання Welcome.

- `credential`: опаковані дані (ім'я, роль, etc.) — вбудовуються в KeyPackage
- `out_key_package.data`: надіслати тому, хто робить Add

### `epp_group_key_package_secrets_destroy`

```c
void epp_group_key_package_secrets_destroy(EppKeyPackageSecretsHandle** handle);
```

Знищити секрети key package (після join або при відміні).

---

## Group — Create / Join
> Ролі: **Client** + **Server**

### `epp_group_create`

```c
EppErrorCode epp_group_create(
    EppIdentityHandle*      identity_handle,
    const uint8_t*          credential,        // [in] credential (або NULL)
    size_t                  credential_length,
    EppGroupSessionHandle** out_handle,        // [out] нова група
    EppError*               out_error
);
```

Створює нову групу. Автор — єдиний член (leaf index 0, epoch 0).

### `epp_group_create_shielded`

```c
EppErrorCode epp_group_create_shielded(
    EppIdentityHandle*      identity_handle,
    const uint8_t*          credential,
    size_t                  credential_length,
    EppGroupSessionHandle** out_handle,
    EppError*               out_error
);
```

Створює групу з preset Shield Mode policy: enhanced KDF, BLAKE2b chain, mandatory franking, blocked external join, max 1000 messages/epoch, max 4 skipped keys/sender.

### `epp_group_create_with_policy`

```c
typedef struct EppGroupSecurityPolicy {
    uint32_t max_messages_per_epoch;        // 10..100000 (0 = default 100000)
    uint32_t max_skipped_keys_per_sender;   // 1..32 (0 = default 32)
    uint8_t  block_external_join;           // 0 = false, 1 = true
    uint8_t  enhanced_key_schedule;         // 0 = false, 1 = true
    uint8_t  mandatory_franking;            // 0 = false, 1 = true
} EppGroupSecurityPolicy;

EppErrorCode epp_group_create_with_policy(
    EppIdentityHandle*            identity_handle,
    const uint8_t*                credential,
    size_t                        credential_length,
    const EppGroupSecurityPolicy* policy,       // [in] custom policy
    EppGroupSessionHandle**       out_handle,
    EppError*                     out_error
);
```

Створює групу з custom security policy. Policy валідується при створенні — невалідні значення повертають `EPP_ERROR_INVALID_INPUT`. Policy прив'язується до group context hash і є **immutable** після створення.

### `epp_group_is_shielded`

```c
EppErrorCode epp_group_is_shielded(
    EppGroupSessionHandle* handle,
    uint8_t*               out_shielded,   // [out] 1 = shielded, 0 = default
    EppError*              out_error
);
```

Перевіряє чи група в Shield Mode (enhanced_key_schedule AND mandatory_franking AND block_external_join).

### `epp_group_get_security_policy`

```c
EppErrorCode epp_group_get_security_policy(
    EppGroupSessionHandle*  handle,
    EppGroupSecurityPolicy* out_policy,    // [out] заповнюється policy полями
    EppError*               out_error
);
```

Повертає повну security policy групи. Корисно для UI (показати ліміти) або логіки (перевірити конкретний прапорець).

### `epp_group_join`

```c
EppErrorCode epp_group_join(
    EppIdentityHandle*          identity_handle,
    const uint8_t*              welcome_bytes,     // [in] Welcome від add_member
    size_t                      welcome_length,
    EppKeyPackageSecretsHandle* secrets_handle,     // [in] секрети від generate_key_package
    EppGroupSessionHandle**     out_group_handle,  // [out] групова сесія
    EppError*                   out_error
);
```

Приєднується до групи через Welcome message (отриманий після Add-commit).

### `epp_group_authorize_external_join`

```c
EppErrorCode epp_group_authorize_external_join(
    EppGroupSessionHandle* handle,
    const uint8_t*         joiner_identity_ed25519_public,        // [in] 32 байти
    size_t                 joiner_identity_ed25519_public_length,  // [in] == 32
    const uint8_t*         joiner_identity_x25519_public,         // [in] 32 байти
    size_t                 joiner_identity_x25519_public_length,   // [in] == 32
    const uint8_t*         joiner_credential,      // [in] credential (або NULL)
    size_t                 joiner_credential_length,
    EppBuffer*             out_authorization,       // [out] authorization artifact
    EppError*              out_error
);
```

Видає authorization artifact для зовнішнього учасника. Чинний член групи підписує дані joiner-а. `out_authorization` треба передати joiner-у, який передасть його в `epp_group_join_external`.

- Викликається **до** того, як joiner викличе `epp_group_join_external`
- `out_authorization.data`: звільнити через `epp_buffer_release`

### `epp_group_join_external`

```c
EppErrorCode epp_group_join_external(
    EppIdentityHandle*      identity_handle,
    const uint8_t*          public_state,          // [in] від export_public_state
    size_t                  public_state_length,
    const uint8_t*          authorization,         // [in] artifact від authorize_external_join
    size_t                  authorization_length,
    const uint8_t*          credential,
    size_t                  credential_length,
    EppGroupSessionHandle** out_group_handle,      // [out] групова сесія
    EppBuffer*              out_commit,            // [out] commit для broadcast
    EppError*               out_error
);
```

Зовнішній join з authorization artifact — через публічний стан групи. Commit треба надіслати всім членам.

**Повний flow external join:**
```
Існуючий член:
  epp_group_export_public_state() → public_state
  epp_group_authorize_external_join(joiner_ed, joiner_x, ...) → authorization

Joiner:
  epp_group_join_external(public_state, authorization, ...) → group_handle + commit

Всі члени:
  epp_group_process_commit(commit)
```

---

## Group — Member Management
> Ролі: **Client** + **Server**

### `epp_group_add_member`

```c
EppErrorCode epp_group_add_member(
    EppGroupSessionHandle* handle,
    const uint8_t*         key_package_bytes,   // [in] KeyPackage нового учасника
    size_t                 key_package_length,
    EppBuffer*             out_commit,           // [out] commit → broadcast всім
    EppBuffer*             out_welcome,          // [out] welcome → надіслати новому
    EppError*              out_error
);
```

Додає учасника в групу.

- `out_commit`: надіслати **всім існуючим** учасникам (вони викличуть `process_commit`)
- `out_welcome`: надіслати **тільки новому** учаснику (він викличе `epp_group_join`)

### `epp_group_remove_member`

```c
EppErrorCode epp_group_remove_member(
    EppGroupSessionHandle* handle,
    uint32_t               leaf_index,   // [in] leaf index учасника для видалення
    EppBuffer*             out_commit,   // [out] commit → broadcast
    EppError*              out_error
);
```

Видаляє учасника за його leaf index. Commit надіслати всім.

### `epp_group_update`

```c
EppErrorCode epp_group_update(
    EppGroupSessionHandle* handle,
    EppBuffer*             out_commit,   // [out] commit → broadcast
    EppError*              out_error
);
```

Оновлює власні ключі (key rotation). Commit надіслати всім.

### `epp_group_process_commit`

```c
EppErrorCode epp_group_process_commit(
    EppGroupSessionHandle* handle,
    const uint8_t*         commit_bytes,   // [in] commit від іншого учасника
    size_t                 commit_length,
    EppError*              out_error
);
```

Застосовує Commit від іншого учасника. Оновлює epoch, ключі, дерево.

---

## Group — Encrypt / Decrypt
> Ролі: **Client** + **Server**

### `epp_group_encrypt`

```c
EppErrorCode epp_group_encrypt(
    EppGroupSessionHandle* handle,
    const uint8_t*         plaintext,
    size_t                 plaintext_length,   // [in] макс. 1 МБ
    EppBuffer*             out_ciphertext,     // [out] зашифроване повідомлення
    EppError*              out_error
);
```

Шифрує повідомлення для групи (Sender Key).

### `epp_group_decrypt`

```c
EppErrorCode epp_group_decrypt(
    EppGroupSessionHandle* handle,
    const uint8_t*         ciphertext,
    size_t                 ciphertext_length,
    EppBuffer*             out_plaintext,       // [out] розшифрований payload
    uint32_t*              out_sender_leaf,     // [out] leaf index відправника
    uint32_t*              out_generation,      // [out] generation counter
    EppError*              out_error
);
```

Дешифрує групове повідомлення. Повертає leaf index відправника і generation (для ordering).

### `epp_group_decrypt_ex`

```c
typedef struct EppGroupDecryptResult {
    EppBuffer plaintext;             // розшифрований payload
    uint32_t  sender_leaf_index;     // leaf index відправника
    uint32_t  generation;           // generation counter
    uint32_t  content_type;         // 0=Normal 1=Sealed 2=Disappearing 3=SealedDisappearing 4=Edit 5=Delete
    uint32_t  ttl_seconds;          // TTL (для Disappearing; 0 якщо не встановлено)
    uint64_t  sent_timestamp;       // unix timestamp відправника (для Disappearing)
    EppBuffer message_id;           // 32 байти стабільний Message ID
    EppBuffer referenced_message_id;// 32 байти ID повідомлення-цілі (для Edit/Delete; порожній інакше)
    uint8_t   has_sealed_payload;   // 1 якщо є sealed payload
    uint8_t   has_franking_data;    // 1 якщо є franking data
    EppBuffer sealed_hint;          // hint текст sealed-повідомлення (може бути порожнім)
    EppBuffer sealed_encrypted_content; // зашифрований контент sealed-повідомлення
    EppBuffer sealed_nonce;         // 12 байт nonce для reveal_sealed
    EppBuffer sealed_key;           // 32 байти seal key для reveal_sealed
    EppBuffer franking_tag;         // 32 байти HMAC commitment (для модерації)
    EppBuffer franking_key;         // 32 байти franking key
    EppBuffer franking_content;     // plaintext контент (для verify_franking)
    EppBuffer franking_sealed_content; // sealed контент (для verify_franking; може бути порожнім)
} EppGroupDecryptResult;

EppErrorCode epp_group_decrypt_ex(
    EppGroupSessionHandle*  handle,
    const uint8_t*          ciphertext,
    size_t                  ciphertext_length,
    EppGroupDecryptResult*  out_result,   // [out] caller-allocated struct (stack або heap)
    EppError*               out_error
);
```

Розширена версія `epp_group_decrypt`. Повертає повну структуру з усіма полями: content_type, TTL, message ID, referenced ID (для Edit/Delete), sealed payload (для `reveal_sealed`), franking data (для `verify_franking`).

**Використання:**
```c
EppGroupDecryptResult result = {0};  // нульова ініціалізація обов'язкова!
EppError err = {0};

EppErrorCode code = epp_group_decrypt_ex(group, ct, ct_len, &result, &err);
if (code == EPP_SUCCESS) {
    printf("From leaf %u, gen %u\n", result.sender_leaf_index, result.generation);
    if (result.content_type == 1 && result.has_sealed_payload) {
        // Є sealed payload — можна викликати reveal_sealed пізніше
        // result.sealed_key / sealed_nonce / sealed_encrypted_content
    }
    if (result.has_franking_data) {
        // Є franking data — можна verify_franking
    }
    epp_group_decrypt_result_free(&result);
}
```

### `epp_group_decrypt_result_free`

```c
void epp_group_decrypt_result_free(EppGroupDecryptResult* result);
```

Звільняє всі heap-allocated буфери всередині `EppGroupDecryptResult` через `epp_buffer_release`. **Не** звільняє сам struct (caller-allocated).

**Важливо:** Викликати лише після успішного `epp_group_decrypt_ex` (код `EPP_SUCCESS`). Якщо функція повернула помилку — struct не повністю заповнений; `epp_group_decrypt_result_free` все одно безпечний якщо struct був нульово-ініціалізований (`= {0}`), оскільки `epp_buffer_release` перевіряє `data != NULL`.

---

## Group — Sealed / Disappearing / Frankable
> Ролі: **Client** + **Server** (крім `epp_group_verify_franking` — також **Relay** для модерації)

### `epp_group_encrypt_sealed`

```c
EppErrorCode epp_group_encrypt_sealed(
    EppGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t         plaintext_length,
    const uint8_t* hint,              // [in] підказка (може бути NULL)
    size_t         hint_length,
    EppBuffer*     out_ciphertext,
    EppError*      out_error
);
```

Шифрує sealed-повідомлення (анонімний відправник). Одержувачі бачать повідомлення, але не знають від кого. `hint` — опціональна підказка для розкриття.

### `epp_group_encrypt_disappearing`

```c
EppErrorCode epp_group_encrypt_disappearing(
    EppGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t         plaintext_length,
    uint32_t       ttl_seconds,       // [in] час життя в секундах (макс. 7 днів)
    EppBuffer*     out_ciphertext,
    EppError*      out_error
);
```

Шифрує повідомлення з TTL. Після `ttl_seconds` дешифрування поверне `EPP_ERROR_MESSAGE_EXPIRED`.

### `epp_group_encrypt_frankable`

```c
EppErrorCode epp_group_encrypt_frankable(
    EppGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t         plaintext_length,
    EppBuffer*     out_ciphertext,
    EppError*      out_error
);
```

Шифрує frankable-повідомлення. Одержувач може довести третій стороні (модератору), що це повідомлення автентичне.

### `epp_group_reveal_sealed`

```c
EppErrorCode epp_group_reveal_sealed(
    const uint8_t* hint,                     // [in] hint (або NULL)
    size_t         hint_length,
    const uint8_t* encrypted_content,        // [in] зашифрований контент
    size_t         encrypted_content_length,
    const uint8_t* nonce,                    // [in] 12 байт AES-GCM nonce
    size_t         nonce_length,             // [in] == 12
    const uint8_t* seal_key,                 // [in] 32 байти seal key
    size_t         seal_key_length,          // [in] == 32
    EppBuffer*     out_plaintext,
    EppError*      out_error
);
```

Розшифровує sealed-повідомлення за допомогою seal key (отриманого з decrypt result).

### `epp_group_verify_franking`

```c
EppErrorCode epp_group_verify_franking(
    const uint8_t* franking_tag,             // [in] 32 байти
    size_t         franking_tag_length,
    const uint8_t* franking_key,             // [in] 32 байти
    size_t         franking_key_length,
    const uint8_t* content,                  // [in] оригінальний контент
    size_t         content_length,
    const uint8_t* sealed_content,           // [in] або NULL/0
    size_t         sealed_content_length,
    uint8_t*       out_valid,                // [out] 1 = valid, 0 = invalid
    EppError*      out_error
);
```

Верифікує franking tag — доказ автентичності повідомлення для третьої сторони.

---

## Group — Edit / Delete
> Ролі: **Client** + **Server**

### `epp_group_encrypt_edit`

```c
EppErrorCode epp_group_encrypt_edit(
    EppGroupSessionHandle* handle,
    const uint8_t*         new_content,              // [in] новий текст повідомлення
    size_t                 new_content_length,        // [in] макс. 1 МБ
    const uint8_t*         target_message_id,        // [in] 32 байти — ID редагованого повідомлення
    size_t                 target_message_id_length,  // [in] == 32
    EppBuffer*             out_ciphertext,
    EppError*              out_error
);
```

Шифрує Edit-повідомлення — заміну вмісту раніше надісланого повідомлення. `target_message_id` — стабільний ID (з `epp_group_compute_message_id` або `epp_group_decrypt_ex.message_id`) редагованого повідомлення. При decrypt `content_type == 4` (Edit), `referenced_message_id` вказує на ціль.

### `epp_group_encrypt_delete`

```c
EppErrorCode epp_group_encrypt_delete(
    EppGroupSessionHandle* handle,
    const uint8_t*         target_message_id,        // [in] 32 байти — ID повідомлення для видалення
    size_t                 target_message_id_length,  // [in] == 32
    EppBuffer*             out_ciphertext,
    EppError*              out_error
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

### `epp_group_get_id`

```c
EppErrorCode epp_group_get_id(
    EppGroupSessionHandle* handle,
    EppBuffer*             out_group_id,   // [out] 32 байти group ID
    EppError*              out_error
);
```

### `epp_group_get_epoch`

```c
uint64_t epp_group_get_epoch(EppGroupSessionHandle* handle);
```

Повертає поточну epoch групи. 0 при помилці або NULL handle.

### `epp_group_get_my_leaf_index`

```c
uint32_t epp_group_get_my_leaf_index(EppGroupSessionHandle* handle);
```

Повертає мій leaf index у дереві. `UINT32_MAX` при помилці.

### `epp_group_get_member_count`

```c
uint32_t epp_group_get_member_count(EppGroupSessionHandle* handle);
```

Повертає кількість учасників. 0 при помилці.

### `epp_group_get_member_leaf_indices`

```c
EppErrorCode epp_group_get_member_leaf_indices(
    EppGroupSessionHandle* handle,
    EppBuffer*             out_indices,   // [out] масив u32 little-endian
    EppError*              out_error
);
```

Повертає leaf indices всіх учасників як масив `uint32_t` у little-endian.

- Кількість елементів: `out_indices.length / 4`
- Зчитувати: `uint32_t idx = *(uint32_t*)(out_indices.data + i * 4)`

### `epp_group_compute_message_id`

```c
EppErrorCode epp_group_compute_message_id(
    const uint8_t* group_id,            // [in] 32 байти group ID
    size_t         group_id_length,      // [in] == 32
    uint64_t       epoch,               // [in] epoch в якій надіслано повідомлення
    uint32_t       sender_leaf_index,   // [in] leaf index відправника
    uint32_t       generation,          // [in] generation counter з encrypt/decrypt
    EppBuffer*     out_message_id,      // [out] 32 байти стабільний Message ID
    EppError*      out_error
);
```

Обчислює детермінований 32-байтний Message ID з `(group_id, epoch, sender_leaf_index, generation)`. ID однаковий у відправника і всіх отримувачів — використовується для Edit/Delete targeting та дедублікації. Relay може викликати без identity (Relay-роль).

- Усі чотири вхідні параметри повинні точно збігатися між відправником і отримувачем
- `generation` береться з `epp_group_decrypt_ex.generation` або з `epp_group_encrypt` (якщо відправник зберігає його)
- `out_message_id.data`: звільнити через `epp_buffer_release`

### `epp_group_destroy`

```c
void epp_group_destroy(EppGroupSessionHandle** handle);
```

---

## Group — Serialization
> Ролі: **Client** + **Server**

### `epp_group_serialize`

```c
EppErrorCode epp_group_serialize(
    EppGroupSessionHandle* handle,
    const uint8_t*         key,               // [in] 32 байти AES key
    size_t                 key_length,
    uint64_t               external_counter,  // [in] > 0, монотонно зростаючий
    EppBuffer*             out_state,
    EppError*              out_error
);
```

Серіалізує групову сесію у sealed blob. Аналогічно session serialization.

### `epp_group_deserialize`

```c
EppErrorCode epp_group_deserialize(
    const uint8_t*          state_bytes,
    size_t                  state_length,
    const uint8_t*          key,                   // [in] 32 байти
    size_t                  key_length,
    uint64_t                min_external_counter,  // [in] anti-rollback
    uint64_t*               out_external_counter,  // [out] counter з blob
    EppIdentityHandle*      identity_handle,       // [in] identity (для Ed25519 signing)
    EppGroupSessionHandle** out_handle,
    EppError*               out_error
);
```

Відновлює групову сесію. `identity_handle` потрібен для Ed25519 private key.

### `epp_group_export_public_state`

```c
EppErrorCode epp_group_export_public_state(
    EppGroupSessionHandle* handle,
    EppBuffer*             out_public_state,   // [out] публічний стан
    EppError*              out_error
);
```

Експортує публічний стан групи (для `epp_group_join_external`). Не містить секретів.

---

## Group — PSK & ReInit
> Ролі: **Client** + **Server**

### `epp_group_set_psk`

```c
EppErrorCode epp_group_set_psk(
    EppGroupSessionHandle* handle,
    const uint8_t*         psk_id,         // [in] ідентифікатор PSK
    size_t                 psk_id_length,   // [in] > 0
    const uint8_t*         psk,            // [in] Pre-Shared Key (мін. 32 байти)
    size_t                 psk_length,      // [in] >= 32
    EppError*              out_error
);
```

Встановлює PSK для наступного commit. PSK вмішується в epoch secret через HKDF.

### `epp_group_get_pending_reinit`

```c
EppErrorCode epp_group_get_pending_reinit(
    EppGroupSessionHandle* handle,
    EppBuffer*             out_new_group_id,   // [out] новий group ID (або порожній)
    uint32_t*              out_new_version,    // [out] нова версія (0 якщо немає)
    EppError*              out_error
);
```

Перевіряє чи є pending ReInit. Якщо `out_new_group_id.length > 0` — треба створити нову групу.

---

## Envelope Metadata
> Ролі: **Client** + **Server**

### `EppEnvelopeMetadata`

```c
typedef struct EppEnvelopeMetadata {
    EppEnvelopeType envelope_type;       // тип конверта
    uint32_t        envelope_id;         // id повідомлення
    uint64_t        message_index;       // порядковий номер у chain
    char*           correlation_id;      // heap-allocated UTF-8 рядок (або NULL)
    size_t          correlation_id_length;
} EppEnvelopeMetadata;
```

Caller-allocated struct (stack). Поле `correlation_id` — heap-allocated, звільняється через `epp_envelope_metadata_free`. Сам struct **не** звільняти.

### `epp_envelope_metadata_parse`

```c
EppErrorCode epp_envelope_metadata_parse(
    const uint8_t*      metadata_bytes,   // [in] Protobuf EnvelopeMetadata bytes (з epp_session_decrypt)
    size_t              metadata_length,
    EppEnvelopeMetadata* out_meta,        // [out] caller-allocated struct
    EppError*           out_error
);
```

Парсить `out_metadata` blob, повернутий `epp_session_decrypt`, у зручну C-структуру.

```c
EppBuffer plaintext = {0}, metadata_buf = {0};
EppError err = {0};
epp_session_decrypt(session, ct, ct_len, &plaintext, &metadata_buf, &err);

EppEnvelopeMetadata meta = {0};
epp_envelope_metadata_parse(metadata_buf.data, metadata_buf.length, &meta, &err);
printf("Type=%d id=%u corr=%s\n", meta.envelope_type, meta.envelope_id,
       meta.correlation_id ? meta.correlation_id : "(none)");

epp_envelope_metadata_free(&meta);
epp_buffer_release(&metadata_buf);
epp_buffer_release(&plaintext);
```

### `epp_envelope_metadata_free`

```c
void epp_envelope_metadata_free(EppEnvelopeMetadata* meta);
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
typedef void (*EppOnHandshakeCompleted)(const uint8_t* session_id, size_t session_id_len,
                                        void* user_data);

// Тип: виклик при кожній ротації DH ratchet.
typedef void (*EppOnRatchetRotated)(uint64_t epoch, void* user_data);

// Тип: виклик при внутрішній помилці протоколу (non-fatal).
typedef void (*EppOnSessionError)(EppErrorCode code, const char* message, void* user_data);

// Тип: виклик коли залишок nonce падає нижче ~20%.
typedef void (*EppOnNonceExhaustionWarning)(uint64_t remaining, uint64_t max_capacity,
                                             void* user_data);

// Тип: виклик коли багато повідомлень без DH ratchet кроку.
typedef void (*EppOnRatchetStallingWarning)(uint64_t messages_since_ratchet, void* user_data);

typedef struct EppSessionEventCallbacks {
    EppOnHandshakeCompleted    on_handshake_completed;     // або NULL
    EppOnRatchetRotated        on_ratchet_rotated;         // або NULL
    EppOnSessionError          on_error;                   // або NULL
    EppOnNonceExhaustionWarning on_nonce_exhaustion_warning; // або NULL
    EppOnRatchetStallingWarning on_ratchet_stalling_warning; // або NULL
    void*                      user_data;                  // передається кожному callback
} EppSessionEventCallbacks;

EppErrorCode epp_session_set_event_handler(
    EppSessionHandle*               handle,
    const EppSessionEventCallbacks* callbacks,   // [in] копіюється за значенням
    EppError*                       out_error
);
```

Реєструє C callback-и на сесії. Struct копіюється — caller може звільнити після виклику. Новий виклик `set_event_handler` замінює попередній handler.

### Group event callbacks

```c
// Тип: виклик при додаванні нового учасника через Commit.
// identity_ed25519 — 32 байти Ed25519 public key нового учасника.
typedef void (*EppOnMemberAdded)(uint32_t leaf_index,
                                  const uint8_t* identity_ed25519, size_t identity_ed25519_len,
                                  void* user_data);

// Тип: виклик при видаленні учасника через Commit.
typedef void (*EppOnMemberRemoved)(uint32_t leaf_index, void* user_data);

// Тип: виклик при кожному просуванні epoch.
typedef void (*EppOnEpochAdvanced)(uint64_t new_epoch, uint32_t member_count, void* user_data);

// Тип: виклик коли sender key generation наближається до max_messages_per_epoch.
typedef void (*EppOnSenderKeyExhaustionWarning)(uint32_t remaining, uint32_t max_capacity,
                                                 void* user_data);

// Тип: виклик коли Commit містить ReInit proposal. Група застаріла — мігрувати.
// new_group_id / new_group_id_len дійсні тільки під час callback.
typedef void (*EppOnReInitProposed)(const uint8_t* new_group_id, size_t new_group_id_len,
                                     uint32_t new_version, void* user_data);

typedef struct EppGroupEventCallbacks {
    EppOnMemberAdded                on_member_added;                  // або NULL
    EppOnMemberRemoved              on_member_removed;                // або NULL
    EppOnEpochAdvanced              on_epoch_advanced;                // або NULL
    EppOnSenderKeyExhaustionWarning on_sender_key_exhaustion_warning; // або NULL
    EppOnReInitProposed             on_reinit_proposed;               // або NULL
    void*                           user_data;
} EppGroupEventCallbacks;

EppErrorCode epp_group_set_event_handler(
    EppGroupSessionHandle*        handle,
    const EppGroupEventCallbacks* callbacks,   // [in] копіюється за значенням
    EppError*                     out_error
);
```

### Identity event callbacks

```c
// Тип: виклик коли OTK пул падає нижче ~10% від DEFAULT_ONE_TIME_KEY_COUNT (100).
// Потрібно викликати epp_prekey_bundle_replenish та завантажити нові OTK на сервер.
typedef void (*EppOnOtkExhaustionWarning)(uint32_t remaining, uint32_t max_capacity,
                                           void* user_data);

typedef struct EppIdentityEventCallbacks {
    EppOnOtkExhaustionWarning on_otk_exhaustion_warning;   // або NULL
    void*                     user_data;
} EppIdentityEventCallbacks;

EppErrorCode epp_identity_set_event_handler(
    EppIdentityHandle*              handle,
    const EppIdentityEventCallbacks* callbacks,   // [in] копіюється за значенням
    EppError*                       out_error
);
```

**Повний приклад реєстрації:**
```c
static void on_nonce_warn(uint64_t remaining, uint64_t max, void* ud) {
    printf("Nonce low: %llu / %llu — re-handshake soon\n", remaining, max);
}

static void on_otk_warn(uint32_t remaining, uint32_t max, void* ud) {
    // replenish OTKs
    epp_prekey_bundle_replenish((EppIdentityHandle*)ud, 50, &keys, &err);
    upload_to_server(keys.data, keys.length);
    epp_buffer_release(&keys);
}

EppSessionEventCallbacks session_cbs = {0};
session_cbs.on_nonce_exhaustion_warning = on_nonce_warn;
session_cbs.user_data = NULL;
epp_session_set_event_handler(session, &session_cbs, &err);

EppIdentityEventCallbacks id_cbs = {0};
id_cbs.on_otk_exhaustion_warning = on_otk_warn;
id_cbs.user_data = identity;
epp_identity_set_event_handler(identity, &id_cbs, &err);
```

---

## Buffer & Memory Management
> Ролі: **Client** + **Server** + **Relay**

### `epp_buffer_release`

```c
void epp_buffer_release(EppBuffer* buffer);
```

Зануляє та звільняє `buffer->data`. **Не** звільняє сам struct `EppBuffer`. Використовувати для stack-allocated `EppBuffer`:

```c
EppBuffer buf = {0};
epp_session_encrypt(handle, ..., &buf, &err);
// використати buf.data / buf.length
epp_buffer_release(&buf);  // звільнити data, struct на стеку
```

### `epp_buffer_alloc`

```c
EppBuffer* epp_buffer_alloc(size_t capacity);
```

Алокує `EppBuffer` на heap із заданим розміром. Повертає NULL якщо `capacity == 0`.

### `epp_buffer_free`

```c
void epp_buffer_free(EppBuffer* buffer);
```

Зануляє та звільняє і data, і сам struct. Для heap-allocated буферів (від `epp_buffer_alloc`).

### `epp_secure_wipe`

```c
EppErrorCode epp_secure_wipe(uint8_t* data, size_t length);
```

Гарантовано зануляє пам'ять (з compiler fence). Для видалення секретів з пам'яті.

---

## Error Handling
> Ролі: **Client** + **Server** + **Relay**

### `epp_error_free`

```c
void epp_error_free(EppError* error);
```

Звільняє `error->message`. Викликати після обробки помилки. Безпечно при NULL.

### `epp_error_string`

```c
const char* epp_error_string(EppErrorCode code);
```

Повертає людиночитабельний опис коду помилки (статичний рядок, не звільняти).

### Патерн обробки помилок

```c
EppError err = {0};
EppBuffer buf = {0};

EppErrorCode code = epp_session_encrypt(handle, data, len,
    EPP_ENVELOPE_REQUEST, 0, NULL, 0, &buf, &err);

if (code != EPP_SUCCESS) {
    printf("Error %d: %s\n", err.code, err.message);
    epp_error_free(&err);
    return;
}

// використати buf.data, buf.length
send_to_peer(buf.data, buf.length);
epp_buffer_release(&buf);
```

---

## Ownership & Lifecycle

### Правила ownership

1. **Handle** — caller owns. Завжди знищувати через відповідний `_destroy`
2. **EppBuffer.data** — caller owns. Звільняти через `epp_buffer_release` (stack) або `epp_buffer_free` (heap)
3. **EppError.message** — caller owns. Звільняти через `epp_error_free`
4. **Consumed handles** — `_finish` забирає ownership, handle стає порожнім

### Типовий lifecycle 1:1 сесії (Client)

```
epp_init()
  ↓
epp_identity_create() → identity_handle
  ↓
epp_prekey_bundle_create() → bundle bytes
  ↓                    (передати peer)
epp_handshake_initiator_start() → initiator_handle + init_msg
  ↓                    (надіслати init_msg)
  ↓                    (отримати ack_msg)
epp_handshake_initiator_finish() → session_handle
  ↓
epp_session_encrypt() / epp_session_decrypt()  (повторювати)
  ↓
epp_session_serialize_sealed() → зберегти на диск
  ↓
epp_session_destroy()
epp_identity_destroy()
epp_shutdown()
```

### Типовий lifecycle групи (Client / Server)

```
epp_group_create() → group_handle              (або epp_group_join)
  ↓
epp_group_add_member() → commit + welcome      (надіслати учасникам)
  ↓
epp_group_encrypt() / epp_group_decrypt()       (повторювати)
  ↓
epp_group_process_commit()                      (при отриманні commit)
  ↓
epp_group_serialize() → зберегти на диск
  ↓
epp_group_destroy()
```

### Типовий lifecycle Relay

```
epp_init()
  ↓
// Отримати encrypted_envelope від клієнта
epp_envelope_validate(envelope, len, &err)    // перевірити формат
  ↓
// Переслати envelope одержувачу(ям) as-is
forward_to_recipients(envelope, len)
  ↓
// Модерація (опційно): перевірити franking tag
epp_group_verify_franking(tag, tag_len, key, key_len,
    content, content_len, sealed, sealed_len, &valid, &err)
  ↓
epp_shutdown()
```

Relay **ніколи не бачить plaintext** — працює виключно з зашифрованими байтами.

---

## Thread Safety

- **Різні** handle можна використовувати з різних потоків одночасно
- **Один і той самий** handle — НЕ thread-safe, синхронізація на стороні caller
- `epp_init` / `epp_shutdown` — викликати з одного потоку
- `epp_version`, `epp_error_string` — thread-safe (статичні дані)
