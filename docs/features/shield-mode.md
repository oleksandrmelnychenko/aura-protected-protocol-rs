# Shield Mode (Захищений режим групи)

## Концепція

Shield Mode — посилений режим безпеки для групових сесій, де **policy криптографічно прив'язана до group context hash**. Зміна хоча б одного біта policy ламає всі HKDF-деривації — ключі, MAC, confirmation — все стає невалідним. Це не конфігурація "на честь", а enforcement на рівні криптографії.

**Маркетинг**: "Cryptographic policy enforcement — не перевірки на рівні коду, а прив'язка до key schedule"

## Криптографічний дизайн

```
Creator                              Member
    │                                    │
    │  create_with_policy(policy)        │
    │  ────────────────────────────►    │
    │                                    │
    │  group_context_hash = SHA-256(     │
    │    group_id ‖ epoch ‖              │
    │    tree_hash ‖ policy_bytes        │  ← policy прив'язана
    │  )                                 │
    │                                    │
    │  epoch_keys = double_KDF(          │
    │    init_secret,                    │
    │    commit_secret,                  │
    │    group_context_hash              │  ← KDF залежить від policy
    │  )                                 │
    │                                    │
    │  chain_key = BLAKE2b(              │
    │    HKDF(chain_key, info)           │  ← додатковий хеш-шар
    │  )                                 │
    │                                    │
    │  Welcome { policy_bytes, MAC }  ──►│  process_welcome():
    │                                    │  verify MAC → policy consensus
    │                                    │  validate(policy) → bounds check
```

### П'ять прапорців policy

| Прапорець | Що робить | Де enforcement |
|-----------|-----------|----------------|
| `enhanced_key_schedule` | Double-KDF (два HKDF-Expand проходи з різними info) | `derive_sub_key()` в key_schedule.rs |
| `enhanced` (chain) | BLAKE2b поверх HKDF-derived chain key | `next_message_key()` в sender_key.rs |
| `mandatory_franking` | Force `frankable = true` для всіх повідомлень | `encrypt_with_policy()` override в mod.rs |
| `block_external_join` | Відмова на вході в `from_external_join()` | Перевірка перед TreeKEM processing |
| `max_messages_per_epoch` | Ліміт повідомлень до обов'язкової epoch rotation | Подвійна перевірка: GroupSession + SenderKeyChain |

### Double-KDF (enhanced key schedule)

```
Звичайний:  epoch_secret →─ HKDF-Expand(info) ─→ sub_key

Enhanced:   epoch_secret →─ HKDF-Expand(info ‖ "Aura-Enhanced-Pass1") ─→ intermediate
            intermediate →─ HKDF-Expand(info ‖ "Aura-Enhanced-Pass2") ─→ sub_key
```

Компрометація одного HKDF-виклику не дає ключ — потрібно зламати обидва проходи з різними info strings.

### BLAKE2b chain ratchet

```
Звичайний:  chain_key →─ HKDF-Expand("chain") ─→ next_chain_key

Enhanced:   chain_key →─ HKDF-Expand("chain") ─→ tmp
            tmp →─ BLAKE2b("Aura-B2Chain", tmp) ─→ next_chain_key
            secure_wipe(tmp)
```

Два різних криптографічних примітиви в ланцюжку — компрометація HKDF не дає ключі без BLAKE2b.

### Mandatory franking

При `mandatory_franking = true`:
- `encrypt()` автоматично додає franking tag (навіть якщо caller не запитував)
- `decrypt()` перевіряє наявність franking tag для повідомлень з franking_key
- Модератор/relay може верифікувати автентичність повідомлення через `verify_franking()`

### Reduced skip window

Shield Mode зменшує вікно пропущених ключів з 32 до 4 per sender. Це обмежує можливість flood-атаки через skipped key cache.

| Параметр | Default | Shield |
|----------|---------|--------|
| `max_messages_per_epoch` | 100,000 | 1,000 |
| `max_skipped_keys_per_sender` | 32 | 4 |
| `max_skipped_total` (store) | 256 | 256 |

## Policy immutability

Policy встановлюється при створенні групи і **ніколи не змінюється**:
- Передається як `&GroupSecurityPolicy` reference (не `&mut`)
- Зберігається в `GroupSessionInner.security_policy`
- Commit processing бере policy з локального стану, не з commit message
- Policy consensus забезпечується через confirmation MAC:
  - `group_context_hash` включає `policy_bytes`
  - `confirmation_mac = HMAC(confirmation_key, group_context_hash)`
  - Якщо хтось має іншу policy → MAC не сходиться → commit відкидається

## Валідація

Policy валідується при:
- Створенні групи (`create_with_policy`)
- Десеріалізації з Welcome (`from_welcome`)
- Десеріалізації зі стану (`from_sealed_state`)
- Зовнішньому join (`from_external_join`)

Обмеження:
- `max_messages_per_epoch`: 10 — 100,000
- `max_skipped_keys_per_sender`: 1 — 32

## Властивості безпеки

| Властивість | Гарантія |
|-------------|----------|
| **Policy binding** | SHA-256(policy_bytes) в group_context_hash → впливає на всі ключі |
| **Consensus** | Confirmation MAC верифікує що всі члени мають однакову policy |
| **Immutability** | Policy не мутується після створення; commit не несе policy на wire |
| **Double-KDF** | Два HKDF-проходи з різними info — компрометація одного не дає ключ |
| **BLAKE2b chain** | Другий криптографічний примітив у chain ratchet |
| **Forced rotation** | `max_messages_per_epoch` обмежує час життя sender keys |
| **Anti-flood** | Зменшене skip window запобігає cache flood через skipped keys |
| **Mandatory franking** | Всі повідомлення автентифіковані для модерації |
| **External join block** | Запобігає незапрошеному вступу до групи |

## API

### Rust

```rust
// Створити shielded групу (preset з усіма захистами)
let session = proto.create_shielded_group(b"credential".to_vec())?;

// Або custom policy
let policy = GroupSecurityPolicy {
    max_messages_per_epoch: 500,
    max_skipped_keys_per_sender: 2,
    block_external_join: true,
    enhanced_key_schedule: true,
    mandatory_franking: true,
};
let session = proto.create_group_with_policy(b"credential".to_vec(), policy)?;

// Перевірити стан
assert!(session.is_shielded()?);

// Отримати деталі policy
let p = session.security_policy()?;
assert_eq!(p.max_messages_per_epoch, 500);
assert!(p.mandatory_franking);

// Шифрування працює як звичайно — enforcement прозорий
let ct = session.encrypt(b"message")?;

// Epoch rotation обов'язкова після ліміту
for _ in 0..500 {
    session.encrypt(b"msg")?;
}
// Наступний encrypt → Err("Epoch rotation required")
let _ = session.update()?; // epoch rotation
session.encrypt(b"continues")?; // OK
```

### C FFI

```c
// Shielded (preset)
AuraGroupSessionHandle* group = NULL;
aura_group_create_shielded(identity, cred, cred_len, &group, &err);

// Custom policy
AuraGroupSecurityPolicy policy = {
    .max_messages_per_epoch = 500,
    .max_skipped_keys_per_sender = 2,
    .block_external_join = 1,
    .enhanced_key_schedule = 1,
    .mandatory_franking = 1,
};
aura_group_create_with_policy(identity, cred, cred_len, &policy, &group, &err);

// Query
uint8_t shielded = 0;
aura_group_is_shielded(group, &shielded, &err);

AuraGroupSecurityPolicy out_policy = {0};
aura_group_get_security_policy(group, &out_policy, &err);
printf("max messages: %u\n", out_policy.max_messages_per_epoch);
```

## Комбінація з іншими фічами

Shield Mode сумісний з усіма типами повідомлень:

```rust
// Disappearing + Shield → franking автоматично додається
session.encrypt_disappearing(b"secret", 3600)?;

// Sealed + Shield → анонімність + enhanced crypto
session.encrypt_sealed(b"anonymous", b"hint")?;

// Frankable + Shield → mandatory franking вже увімкнений, explicit frankable = no-op
session.encrypt_frankable(b"reportable")?;

// Edit/Delete + Shield → працює, referenced_message_id зберігається
session.encrypt_edit(b"edited", &message_id)?;
```

## Default vs Shield

| | Default (`GroupSecurityPolicy::default()`) | Shield (`GroupSecurityPolicy::shield()`) |
|---|---|---|
| `enhanced_key_schedule` | `false` | `true` |
| `mandatory_franking` | `false` | `true` |
| `block_external_join` | `false` | `true` |
| `max_messages_per_epoch` | 0 → effective 100,000 | 1,000 |
| `max_skipped_keys_per_sender` | 0 → effective 32 | 4 |
| Backward compatible | Так — пуста policy = існуюча поведінка | Ні — вимагає всіх учасників на новій версії |
