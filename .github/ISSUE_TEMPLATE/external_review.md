---
name: External Review
about: Record an independent review of the Aura paper artifact
title: '[REVIEW] '
labels: external-review, security
assignees: ''
---

## Reviewer

- Name:
- Affiliation / independent status:
- Review area: <!-- crypto proof, formal models, implementation, benchmarks, references -->

## Reviewed commit

```
git rev-parse HEAD
```

## Scope

- [ ] `docs/aura-paper.tex` / paper claims
- [ ] `docs/security-proof.tex`
- [ ] Tamarin models
- [ ] ProVerif model
- [ ] Rust handshake/session implementation
- [ ] Paper vectors and attack-PoC tests
- [ ] Benchmark methodology
- [ ] Reference audit

## Artifact evidence

- CI artifact links:
- Local artifact directories:
- `SHA256SUMS` verification result:

## Findings

### Blocking

<!-- Issues that must be resolved before publication or release. -->

### Non-blocking

<!-- Clarifications, wording issues, hardening ideas, future work. -->

### Accepted limitations

<!-- Explicitly accepted limits such as no PQ signatures or ProVerif Q5/Q6. -->

## Author response

<!-- Link follow-up commits or explain why a finding is accepted/rejected. -->
