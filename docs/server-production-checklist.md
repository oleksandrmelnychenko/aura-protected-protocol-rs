# Server Production Checklist

Цей файл описує, що ще треба зробити на стороні сервера / relay / backend перед production rollout.

## Trust Boundaries

- Сервер не має вважати себе trusted crypto endpoint.
- Сервер повинен працювати як relay / policy / routing layer, а не як місце дешифрування client E2E state.
- Не зберігати plaintext там, де очікується лише encrypted payload transport.

## External Join Policy

- Визначити, чи `external join` дозволений у продукті.
- Якщо дозволений:
  - сервер повинен явно моделювати workflow видачі authorization artifact
  - визначити, хто має право його ініціювати
  - логувати факт видачі authorization
  - обмежити час життя / контекст використання, якщо це потрібно бізнес-логікою
- Якщо не дозволений:
  - не expose-ити endpoint/flow для `GroupPublicState` + authorization
  - тримати тільки `Welcome`-based membership flow

## Relay Validation

- На ingress перевіряти, що payload type відповідає очікуваному endpoint flow.
- Для key packages використовувати повноцінну криптографічну валідацію, а не лише shape check.
- Не приймати “майже схожі” blobs тільки тому, що вони добре декодуються.

## Storage

- Не зберігати зайві копії:
  - `GroupPublicState`
  - Welcome blobs
  - authorization artifacts
  - pending encrypted events
- Для всього, що зберігається:
  - TTL / retention policy
  - audit logging
  - clear ownership model

## Audit And Abuse Flows

- Якщо використовується franking:
  - визначити, хто і коли має право подавати abuse proof
  - визначити retention policy для franking-related blobs
  - не змішувати operational logs і privacy-sensitive audit material без потреби

## Event Queue / Delivery

- Якщо сервер реалізує pending event store:
  - гарантувати idempotent ack path
  - обмежити replay на рівні transport/event IDs
  - мати backpressure / size limits
- Не дозволяти безконтрольний ріст pending queue.

## API And Auth

- Для всіх endpoints, які торкаються E2E routing:
  - authn
  - authz
  - rate limiting
  - abuse monitoring
- Особливо важливо для:
  - prekey upload/replenish
  - welcome delivery
  - public-state export
  - external-join authorization workflows

## Observability

- Логувати:
  - routing success/failure
  - invalid payload rejections
  - unauthorized join attempts
  - replay-like transport anomalies
- Не логувати секретний або plaintext material.

## Operational Testing

- Додати backend integration tests для:
  - prekey lifecycle
  - welcome delivery
  - group commit fanout
  - external join authorization path
  - duplicate event ack path
- Додати tests для malformed input і policy rejection.

## Minimum Server Gate

- Чітко визначено, чи є external join.
- Є ingress validation для crypto artifacts.
- Немає plaintext dependency у critical path.
- Є retention/rate-limit/audit policy.
- Є integration tests для routing and membership flows.
