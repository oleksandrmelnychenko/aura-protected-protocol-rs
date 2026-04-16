# Sealed Messages (Замилені повідомлення)

## Концепція

Sealed Messages — повідомлення з подвійним шаром шифрування. Отримувач бачить метадані (хто, коли) та **hint** (підказку), але фактичний контент залишається зашифрованим ("замиленим") до явного розкриття.

**Маркетинг**: "Privacy on tap — бачиш хто написав, але контент прихований поки ти не готовий"

## Криптографічний дизайн

```
                         message_key (з sender key chain)
                              │
                    ┌─────────┴──────────┐
                    │                    │
               HKDF-Expand          AES-256-GCM-SIV
          (GROUP_SEAL_KEY_INFO)    (зовнішній шар — hint)
                    │
               seal_key
                    │
             AES-256-GCM-SIV
         (внутрішній шар — контент)
```

### Шифрування (encrypt_sealed)

1. Отримати `message_key` з sender key chain (як звичайне повідомлення)
2. Створити `seal_key = HKDF-Expand(message_key, "Aura-Group-SealKey", 32)`
3. Згенерувати випадковий `sealed_nonce` (12 байт)
4. Зашифрувати фактичний контент: `sealed_content = AES-GCM-SIV(seal_key, sealed_nonce, plaintext, "sealed")`
5. Записати `hint` як `content` у `GroupPlaintext`
6. Зашифрувати весь `GroupPlaintext` під `message_key` (зовнішній шар — як звичайне повідомлення)

### Розшифрування (decrypt + reveal_sealed)

1. Стандартне розшифрування зовнішнього шару → отримуємо `GroupPlaintext`
2. **Перед витиранням `message_key`**: `seal_key = HKDF-Expand(message_key, SEAL_KEY_INFO, 32)`
3. Витерти `message_key`
4. Повернути `GroupDecryptResult` з `plaintext = hint` та `sealed_payload = SealedPayload { hint, encrypted_content, nonce, seal_key }`
5. Коли користувач явно хоче бачити контент: `reveal_sealed(sealed_payload)` → `AES-GCM-SIV-Decrypt(seal_key, nonce, encrypted_content, "sealed")`

## Властивості безпеки

| Властивість | Гарантія |
|-------------|----------|
| **Конфіденційність контенту** | Внутрішній шар AES-256-GCM-SIV з окремим seal_key |
| **Forward secrecy** | seal_key виведений з message_key, який витирається після використання |
| **Domain separation** | seal_key та message_key — різні HKDF-Expand виклики з різними info labels |
| **Аутентичність** | Зовнішній AAD зв'язує group_id, epoch, sender, generation |

## API

```rust
// Шифрування
let ct = session.encrypt_sealed(actual_content, hint)?;

// Розшифрування
let result = session.decrypt(&ct)?;
assert_eq!(result.content_type, ContentType::Sealed);
assert_eq!(result.plaintext, hint); // Бачимо тільки підказку

// Явне розкриття
let content = GroupSession::reveal_sealed(result.sealed_payload.as_ref().unwrap())?;
```

## Приклади використання

- Фото/відео: hint = "Фото від Аліси", контент = зашифровані медіа-дані
- Спойлери: hint = "Спойлер до фільму", контент = текст спойлера
- Чутливі дані: hint = "Фінансовий звіт", контент = звіт
- NSFW контент: hint = "18+ контент", контент = зображення
