# Shield Mode (версійований захищений профіль групи)

## Що реально гарантує Shield V1

Shield V1 — це стабільний профіль `GroupSecurityPolicy`, прив'язаний до
криптографічного group context. Клієнт може чесно показувати назву Shield V1
лише тоді, коли policy точно відповідає цьому versioned preset:

| Контроль | Shield V1 |
|---|---:|
| `max_messages_per_epoch` | 1 000 |
| `max_skipped_keys_per_sender` | 4 |
| `block_external_join` | `true` |
| `enhanced_key_schedule` | `true` |
| `mandatory_franking` | `true` |

`GroupSecurityTier` має три стабільні значення:

- `Standard` — стандартний приватний E2E-профіль із delivery-tolerant вікном у
  1 000 пропущених ключів;
- `ShieldV1` — строгий профіль вище;
- `Custom` — валідна policy, яка не відповідає іменованому профілю.

Майбутній Shield V2 має отримати окремий enum/preset. Значення Shield V1 не
можна тихо перевизначити в новій версії бібліотеки.

## Криптографічне зв'язування policy

Серіалізовані `policy_bytes` входять до group context hash:

```text
SHA-256(
  len(group_id) || group_id ||
  epoch ||
  len(tree_hash) || tree_hash ||
  len(policy_bytes) || policy_bytes
)
```

Цей hash використовується key schedule і confirmation MAC. Тому учасник з
іншою policy не може непомітно застосувати той самий Commit або Welcome.
Policy також зберігається у sealed state і переноситься у Welcome.

## Standard проти Shield V1

| Властивість | Standard | Shield V1 |
|---|---:|---:|
| Enhanced key schedule | так | так |
| Mandatory franking | так | так |
| External join blocked | так | так |
| Max messages / epoch | 1 000 | 1 000 |
| Max skipped keys / sender | 1 000 | 4 |
| `is_shielded()` | `false` | `true` |

Обидва профілі залишаються сильним E2E. Різниця V1 навмисно полягає у строгій
межі пропущених sender keys і окремій версованій класифікації, яку host може
використати для Shield-specific message format та UX.

## Sealed messages

`encrypt_sealed()` створює вкладений encrypted payload, ключ якого виводиться
з per-message key. Одержувач, який уже має право розшифрувати групове
повідомлення, також може відкрити sealed payload. Отже це:

- корисний окремий wire/content type;
- не додатковий ACL між членами групи;
- не приховування автора;
- не traffic-analysis resistance.

Низькорівневий Rust API залишає вибір `encrypt()` / `encrypt_sealed()` host-у;
для disappearing Shield-повідомлень доступний окремий
`encrypt_sealed_disappearing()` primitive.
Клієнт, що заявляє Shield-specific sealed delivery, повинен використовувати
sealed API і мати round-trip тест на реальному receive path.

## Що Shield V1 не приховує

Shield V1 не шифрує від сервісу:

- roster та ролі учасників;
- назву, опис і avatar групи;
- sender/device identifiers у транспортному контурі;
- timestamps, message sizes та traffic shape;
- факт вступу, виходу чи видалення учасника.

Такі гарантії потребують окремого encrypted-metadata протоколу та padding/
batching/mix-network дизайну. Їх не можна приписувати Shield V1.

## Delivery gap і recovery

Вікно `4` захищає від неконтрольованого skipped-key cache, але робить Shield V1
чутливим до offline burst або втрати понад чотирьох послідовних повідомлень.
Протокол повертає помилку замість необмеженого просування ratchet. Host повинен
fail closed і виконати контрольований epoch update/rejoin/recovery flow; не
можна мовчки скидати криптографічний стан або трактувати ciphertext як втрачений
plaintext.

## Rust API

```rust
use aura_protected_protocol::protocol::{GroupSecurityTier, GroupSecurityPolicy};

let standard = proto.create_group(b"credential".to_vec())?;
assert_eq!(standard.security_tier()?, GroupSecurityTier::Standard);
assert!(!standard.is_shielded()?);

let shield = proto.create_shielded_group(b"credential".to_vec())?;
assert_eq!(shield.security_tier()?, GroupSecurityTier::ShieldV1);
assert!(shield.is_shielded()?);

let mut stricter = GroupSecurityPolicy::shield();
stricter.max_messages_per_epoch = 500;
stricter.max_skipped_keys_per_sender = 2;
assert_eq!(stricter.security_tier(), GroupSecurityTier::Custom);
assert!(!stricter.is_shielded());
```

## C FFI

```c
AuraGroupSessionHandle* group = NULL;
aura_group_create_shielded(identity, cred, cred_len, &group, &err);

AuraGroupSecurityTier tier = AURA_GROUP_SECURITY_TIER_CUSTOM;
aura_group_get_security_tier(group, &tier, &err);
assert(tier == AURA_GROUP_SECURITY_TIER_SHIELD_V1);
```

`aura_group_is_shielded()` збережено як сумісний helper, але для нової логіки
краще використовувати `aura_group_get_security_tier()`.
