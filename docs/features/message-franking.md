# Message Franking (Франкування повідомлень)

## Концепція

Message Franking — механізм E2E-сумісної модерації. Відправник криптографічно зобов'язується до вмісту повідомлення (HMAC commitment), що дозволяє отримувачу довести модератору **що саме було надіслано**, без порушення E2E шифрування для всіх інших повідомлень.

**Маркетинг**: "E2E encryption WITH content moderation — безпека без безкарності"

## Криптографічний дизайн (Facebook-модель)

```
Відправник                       Сервер/Мережа                    Отримувач
    │                                │                                │
    │  franking_key = random(32)     │                                │
    │  franking_tag =                │                                │
    │    HMAC(fk, FrankInput(...))   │                                │
    │                                │                                │
    │  GroupApplicationMessage {     │                                │
    │    encrypted_payload =         │                                │
    │      E(message_key,            │                                │
    │        GroupPlaintext {         │                                │
    │          content: plaintext    │                                │
    │          franking_key: fk      │  ← franking_tag видимий       │
    │        })                      │    без розшифрування!          │
    │    franking_tag: tag           │                                │
    │  }                             │                                │
    │  ──────────────────────────────┼───────────────────────────────►│
    │                                │                                │
    │                                │  Отримувач розшифровує:       │
    │                                │  plaintext + franking_key     │
    │                                │                                │
    │                                │  Для скарги модератору:       │
    │                                │  → (plaintext, franking_key)  │
    │                                │                                │
    │                                │  Модератор перевіряє:         │
    │                                │  HMAC(fk, FrankInput(...))    │
    │                                │      == franking_tag          │
```

### FrankInput — що саме комітиться

```
FrankInput(content_type, content, sealed_content, sealed_nonce, seal_key) =
      "Aura-Group-FrankingTag-v2"
   || le32(GROUP_PROTOCOL_VERSION)
   || le32(content_type)
   || len32(content)        || content
   || len32(sealed_content) || sealed_content
   || len32(sealed_nonce)   || sealed_nonce
   || len32(seal_key)       || seal_key
```

Кожне змінне поле має length-префікс, є доменна мітка і версія. Це не
косметика: тег раніше рахувався над `content || sealed_content` без
роздільників, тож скаржник міг зсунути межу між полями і «довести», що
відправник надіслав будь-який **префікс** тексту — для звичайного повідомлення
`sealed_content` порожній, тому це означало будь-який префікс.

Для sealed-повідомлень тег додатково комітить `seal_key` і `sealed_nonce`.
Розшифрування AEAD детерміноване, тож ключ+nonce+шифротекст однозначно
задають один plaintext — саме це дає модератору змогу **відкрити** payload зі
скарги. Раніше для sealed-повідомлення `content` був порожньою підказкою, а
`sealed_content` — непрозорим шифротекстом, тож тег не розкривав нічого,
попри те що Shield примусово вмикає франкування на кожному повідомленні.
Прив'язка ключа заодно закриває відсутність key-commitment в AES-GCM-SIV:
скаржник не може підставити другий ключ, який відкриває той самий шифротекст
в інші байти.

### Ключові принципи

1. **`franking_tag`** — HMAC-SHA256(franking_key, FrankInput(...)) — розміщений **поза** encrypted_payload в `GroupApplicationMessage`
2. **`franking_key`** — випадковий 32 байти — розміщений **всередині** encrypted_payload (в `GroupPlaintext.franking_key`)
3. Сервер/мережа бачить `franking_tag`, але **не може** верифікувати без `franking_key`
4. Отримувач розшифровує → отримує `plaintext` + `franking_key`
5. Для скарги: отримувач передає модератору `FrankingData` — `franking_key`,
   `content`, `sealed_content`, `content_type`, `sealed_nonce`, `seal_key`
6. Модератор: `HMAC(franking_key, FrankInput(...)) == franking_tag` → доводить,
   що саме цей контент був надісланий; для sealed-повідомлення `seal_key` +
   `sealed_nonce` ще й відкривають payload

### Чому це працює

- **Відправник не може заперечити**: `franking_tag` прив'язаний через HMAC до конкретного `plaintext`, типу контенту і — для sealed — до ключа, що його відкриває
- **Отримувач не може підробити**: `franking_key` був згенерований відправником і зашифрований E2E
- **Сервер не може читати**: `franking_tag` без `franking_key` — це просто 32 непрозорих байти
- **Інші повідомлення захищені**: кожне повідомлення має свій випадковий `franking_key`

## Властивості безпеки

| Властивість | Гарантія |
|-------------|----------|
| **Commitment binding** | HMAC-SHA256 над length-префіксованим, доменно-сепарованим входом — межі полів однозначні |
| **Selective disclosure** | Тільки скаргу-повідомлення розкривається модератору |
| **Non-fabrication** | Отримувач не може підробити контент (key був усередині E2E) |
| **Forward secrecy** | franking_key витирається через Drop trait при знищенні FrankingData |
| **No E2E breakage** | Модератор верифікує тільки одне повідомлення, не має доступу до решти |

## API

```rust
// Шифрування
let ct = session.encrypt_frankable(b"Offensive content")?;

// Розшифрування (отримувач)
let result = session.decrypt(&ct)?;
let fd = result.franking_data.as_ref().unwrap();

// Верифікація (модератор)
let valid = GroupSession::verify_franking(fd)?;
assert!(valid);

// Підробка контенту — верифікація провалюється
let tampered = FrankingData {
    franking_tag: fd.franking_tag.clone(),
    franking_key: fd.franking_key.clone(),
    content: b"Different content".to_vec(),
};
let valid = GroupSession::verify_franking(&tampered)?;
assert!(!valid);
```

## Модель загроз

| Загроза | Захист |
|---------|--------|
| Відправник заперечує контент | franking_tag — незаперечний HMAC commitment |
| Отримувач підробляє скаргу | franking_key генерується відправником, зашифрований E2E |
| Сервер читає повідомлення | franking_tag без key — непрозорий blob |
| Масова стеження модератором | Модератор бачить тільки повідомлення, на які поскаржились |

## Порівняння з іншими протоколами

| Протокол | Модерація | E2E збережено |
|----------|-----------|---------------|
| Signal | Немає (скріншот) | Так |
| WhatsApp | Report → forward plaintext | Частково (сервер бачить скаргу) |
| **Aura** | Cryptographic franking | **Так** (HMAC verification) |
| Facebook Messenger | Message franking (наша модель) | Так |
