# RCQ protocol specification

The wire protocol of the [RCQ](https://rcq.app) messenger, as actually
implemented by the shipped clients and the reference server. One document:
**[SPEC.md](SPEC.md)**.

It covers identity allocation and key publication, end-to-end encrypted 1:1 and
group delivery, the WebSocket channel, push (APNs and UnifiedPush), encrypted
media, account migration and burn, and the embedded censorship-circumvention
transport.

## Why this exists

A messenger that asks to be trusted should be checkable without reading every
line of three clients. This document is what the implementations are held to,
and it is written to be specific enough to build against: field names, error
codes, ordering rules, and the places where we knowingly traded something away.

Where the spec and the code disagree, the code is the bug or the spec is stale.
Either way it is worth an issue.

## Related

- Clients: [iOS](https://github.com/rcq-messenger/rcq-ios),
  [Android](https://github.com/rcq-messenger/rcq-android),
  [desktop](https://github.com/rcq-messenger/rcq-desktop)
- Reference server anyone can self-host:
  [rcq-server-ref](https://github.com/rcq-messenger/rcq-server-ref)
- Public island catalogue: [rcq-servers](https://github.com/rcq-messenger/rcq-servers)

## Versioning

The header carries the document version and section 15 records every change
with its date and reasoning. A wire-breaking change bumps the major version;
additive endpoints and optional fields do not.
