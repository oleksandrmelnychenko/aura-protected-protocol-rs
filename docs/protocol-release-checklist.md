# Protocol Release Checklist

Цей файл описує, що ще треба зробити перед release саме бібліотеки / протоколу як артефакта в git і build pipeline.

## 1. Release Artifacts

Перед тегом або релізом перевірити, що перевипущені всі ship-артефакти:

- Rust library release build
- C headers
- XCFramework / staticlib / dynamic artifacts, якщо вони ship-яться
- Swift wrapper package artifacts

Не покладатися на старі checked-in generated outputs.

## 2. Git Hygiene

- Переконатися, що в робочому дереві немає випадкових generated drift файлів.
- Не включати тимчасові audit notes або локальні build артефакти.
- Окремо перевірити, що видалення legacy/stale файлів дійсно intentional.

## 3. Versioning

- Підняти версію бібліотеки узгоджено в:
  - Rust crate metadata
  - C-facing version constants
  - Swift-facing reported version, якщо вона віддзеркалює native
- Якщо є breaking changes:
  - чітко позначити major/minor bump за вашою policy

## 4. Changelog / Migration Notes

Потрібно описати breaking changes:

- hardened default group posture
- external join тепер вимагає authorization
- Swift verification flow змінився / розширився
- FFI contracts змінені
- частина legacy/stale audit artifacts видалена

Окремо варто дати migration notes для:

- Rust інтеграторів
- C інтеграторів
- Swift / Apple platform клієнтів

## 5. Quality Gates

Перед релізом обов'язково прогнати:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`

Якщо Swift/Xcode артефакти ship-яться окремо, додатково:

- Swift build smoke test
- import/use smoke test для XCFramework

## 6. API Surface Review

Перед release ще раз вручну перевірити:

- headers відповідають реальному FFI
- Swift wrappers відповідають headers і native behavior
- docs не обіцяють те, чого вже немає або що тепер no-op

Особливо:

- `deriveRootKey`
- sealed/franking decrypt artifacts
- session identity/binding getters
- external join authorization flow

## 7. Security Review Before Tag

Перед тегом зробити короткий release review:

- чи всі критичні hardening changes реально покриті tests
- чи не залишився legacy permissive path
- чи немає checked-in stale PoC/docs, які суперечать поточному коду
- чи backend/client docs не ведуть інтеграторів у небезпечний flow

## 8. CI / Reproducibility

- Переконатися, що release build відтворюється в CI, а не тільки локально.
- Зафіксувати pipeline, який збирає:
  - Rust
  - FFI
  - Swift/XCFramework, якщо потрібно
- Артефакти release повинні походити саме з CI або чітко задокументованого reproducible build process.

## 9. Tag / Release Protocol

Практичний порядок:

1. `fmt` / `clippy` / `test`
2. rebuild release artifacts
3. перевірити docs + headers + Swift wrapper sync
4. підготувати changelog
5. створити git tag
6. attach / publish release artifacts
7. зберегти release notes з breaking changes

## Minimum Release Gate

- Усі quality gates зелені.
- Артефакти перевипущені.
- Docs синхронні з кодом.
- Breaking changes описані.
- CI build reproducible.
- Git tree чисте й без випадкових generated drift файлів.
