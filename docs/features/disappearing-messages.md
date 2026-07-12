# Disappearing Messages (Зникаючі повідомлення)

## Концепція

Disappearing Messages — повідомлення з TTL (Time-To-Live), де **протокол криптографічно відмовляє в розшифруванні** після закінчення терміну. Це не UI-трюк (як у більшості месенджерів), а enforcement на рівні key schedule.

**Маркетинг**: "Cryptographic disappearing — не UI-фокус, а знищення ключів на рівні протоколу"

## Криптографічний дизайн

```
Відправник                          Отримувач
    │                                    │
    │  encrypt_disappearing(pt, ttl)     │
    │  ─────────────────────────────►    │
    │  GroupPlaintext {                   │
    │    content: plaintext              │
    │    policy: {                       │
    │      content_type: DISAPPEARING    │
    │      ttl_seconds: 3600             │
    │      sent_timestamp: now()         │
    │    }                               │
    │  }                                 │
    │                                    │  decrypt():
    │                                    │  if now > sent_timestamp + ttl:
    │                                    │    → Err(MessageExpired)
    │                                    │  else:
    │                                    │    → Ok(plaintext)
```

### Механізм enforcement

1. `sent_timestamp` та `ttl_seconds` зберігаються **всередині зашифрованого пейлоаду** (в `GroupPlaintext.policy`)
2. При `decrypt()` протокол перевіряє: `current_time > sent_timestamp + ttl_seconds`
3. Якщо TTL вичерпано → `Err(ProtocolError::MessageExpired(...))` — плейнтекст **не повертається**
4. `message_key` вже спожитий hash ratchet — повторне розшифрування неможливе
5. Sender key chain забезпечує forward secrecy: після advance старі ключі знищені

### Обмеження

- `sent_timestamp` встановлюється відправником — зловмисний відправник може виставити timestamp у майбутньому
- Практичне пом'якшення: отримувач може відхиляти повідомлення з `sent_timestamp` далеко в майбутньому
- Максимальний TTL: 7 днів (`MAX_TTL_SECONDS = 604800`)
- Мінімальний TTL: 1 секунда

## Властивості безпеки

| Властивість | Гарантія |
|-------------|----------|
| **Protocol enforcement** | `decrypt()` відмовляє повертати plaintext після TTL |
| **Forward secrecy** | Hash ratchet знищує message_key; перерозшифрування неможливе |
| **Anti-tampering** | TTL та timestamp всередині AES-GCM-SIV authenticated encryption |
| **Epoch rotation** | При новій епосі всі sender chain keys знищуються |

## API

```rust
// TTL = 1 година
let ct = session.encrypt_disappearing(b"Secret meeting at 5pm", 3600)?;

// Розшифрування (поки TTL валідний)
let result = session.decrypt(&ct)?;
assert_eq!(result.content_type, ContentType::Disappearing);
assert_eq!(result.ttl_seconds, 3600);

// Після TTL → помилка
std::thread::sleep(Duration::from_secs(3601));
let result = session.decrypt(&ct); // Err(MessageExpired)
```

## Комбінація з іншими фічами

Disappearing + Sealed:
```rust
let ct = session.encrypt_sealed_disappearing(
    plaintext,
    b"Disappearing Shield message",
    300, // 5 хвилин
)?;
```
