# RCQ Protocol Specification (v1.3)

## 0. Status & Scope

This document specifies the wire protocol of the RCQ messenger as
implemented in the open-source iOS client and the FastAPI backend.
It covers the messaging core: identity allocation, key publication,
end-to-end encrypted 1:1 and group delivery, the WebSocket signalling
channel, push notifications, encrypted media blobs, account migration,
and the embedded censorship-circumvention transport.

In scope:

- Identity (UIN), authentication (JWT bearer), profile + visibility.
- Contact graph (requests, accept/reject, block, mutual removal).
- libsignal v2 key bundle publication and prekey fetch.
- Sealed-sender 1:1 envelope routing and offline queue.
- Per-recipient group fanout, group membership, group settings.
- WebSocket channel (presence, typing, reactions, call signalling).
- APNs push (alert + VoIP), including the Notification Service
  Extension flow.
- Encrypted media blob upload/download with per-blob key exchange
  inside the encrypted envelope.
- Account migration (move identity to a fresh UIN) and burn (wipe).
- Censorship-circumvention transport selection (relay rotation,
  signed remote config). Wire details of VLESS+Reality and
  Hysteria2 themselves are defined by their upstream specs; this
  document only covers how RCQ selects and rotates between them.

Out of scope:

- Non-messaging APIs (audio rooms, random chat, stories, nearby,
  hood banners, UIN shop, reports, news, polls, referrals,
  admin). These ride on the same authentication layer described
  here, but their endpoints are not part of the messaging
  protocol. See Section 14 for a one-line index, and Section 14.1
  for the 2026-05-27 pivot record of what was removed.
- Operational concerns (deployment, monitoring, backups).
- The libsignal protocol itself. RCQ uses the upstream
  `libsignal` implementation (v0.93+, PQXDH) verbatim for v=2
  envelopes; readers should consult the Signal protocol docs for
  X3DH, Double Ratchet, and Sender Key internals.

Version: **v1.1**. Last updated: **2026-05-27**. Spec maintainer:
the RCQ team (issues / RFCs against `github.com/rcq-messenger/rcq-spec`).

## 1. Overview

RCQ is an anonymous messenger built around 9-digit ICQ-style
account numbers (UINs) rather than phone numbers or email
addresses. It provides end-to-end encrypted 1:1 and group messaging
on top of libsignal (X3DH + Double Ratchet + Kyber/PQXDH), wraps
every send in a sealed-sender envelope so the server cannot identify
the sender of a 1:1 message, and ships an in-app censorship
circumvention transport so the application works without an
external VPN in regions that block its TLS fingerprint.

The system has three pieces:

1. **iOS client** (open source, AGPL-3.0, at
   `github.com/rcq-messenger/rcq-ios`). Holds all private key
   material. Runs the libsignal session state. Performs all
   encryption and decryption. Also vendors `sing-box` as a
   library for the embedded VLESS/Hysteria2 transport.
2. **Backend** (FastAPI + Postgres + Redis). Stateless from the
   E2EE perspective: it stores public keys, ciphertext queued for
   offline recipients, and group metadata. It never sees a
   plaintext message body. Multi-worker uvicorn; cross-worker WS
   fanout via Redis pub/sub.
3. **Relays** (a small pool of VPS instances in different
   ASNs/clouds, each running `sing-box` server with two protocols
   active). Plain TCP+TLS to `api.rcq.app` is preferred when it
   works; the relay path is engaged automatically only when the
   direct path fails. Relay endpoints, SNI values, and credentials
   are published as a signed JSON config the client fetches via
   Cloudflare and a GitHub Raw mirror.

Key design choices:

- **Anonymous identity**: a UIN is a numeric handle the server
  allocates randomly. No phone number, no email, no captcha. By
  default the client owns the only copy of the private keys, so an
  account is "nothing to seize". New accounts may **opt in** to a
  seed-phrase backup (Section 2.7): the keypairs derive from a
  32-byte seed the user can write down as a BIP39 phrase, trading a
  slice of that property for recoverability on a new device.
- **libsignal for content secrecy**: every message body rides
  through Signal's Double Ratchet. PQXDH (X3DH + Kyber) is used
  to bootstrap each session so an attacker with a future quantum
  computer cannot decrypt historical traffic recorded today.
- **Sealed sender for metadata privacy**: the server addresses
  envelopes by recipient UIN only. The sender's identity is
  inside the encrypted payload. The server cannot answer "who
  messages whom". (See Section 13 for the exact threat-model
  caveats.)
- **In-app censorship transport**: the client carries a
  pluggable transport that auto-selects between direct TLS and a
  pool of relay protocols (VLESS+Reality, Hysteria2 with
  Salamander obfuscation). The transport is purely a network
  substitution; it never sees plaintext or affects the E2EE layer.

## 2. Identity & Authentication

### 2.1 UIN allocation

A UIN is a positive integer in the range `[100_000,
999_999_999]` (inclusive). Default allocation picks a random
value in that range, rejecting any that collide with an existing
account or with a UIN reserved by the UIN shop (`OwnedUin`).

Short "vanity" UINs are not part of the default allocator; they
are obtained through the UIN shop (see Section 14) and assigned
via the migration endpoint (Section 10).
This document treats UINs as opaque integers — the wire format
does not depend on digit count.

### 2.2 `POST /auth/register`

Creates a new account.

Request:

```json
{
  "nickname": "<string, 1..64 chars>",
  "identity_key": "<base64 of 32-byte raw X25519 public key>",
  "signing_key":  "<base64 of 32-byte raw Ed25519 public key>",
  "inviter_uin":  <int|null>   // optional referral code
}
```

Response (`201 Created`):

```json
{
  "uin":   <int>,           // freshly allocated
  "token": "<JWT>"          // bearer token for subsequent requests
}
```

Side effects:

- A `users` row is created with `nickname`, `identity_key`,
  `signing_key` set and all libsignal v=2 fields NULL (the
  client is expected to call `POST /keys/bundle` immediately
  after `/auth/register` to upload its libsignal bundle).
- If `RCQ_FOUNDER_UIN` is configured and exists as a non-fake
  user, two `Contact` rows are inserted (mutual link to the
  founder).
- If `RCQ_FOUNDER_BETA_GROUP_ID` is configured and the group
  exists, the new account is added as a `member` and a
  `group_membership_changed` WS event is fanned out to existing
  members.
- A starter pack (currency + 3 random items) is granted via
  internal service; this is a business detail, not a protocol
  invariant. A failure here does not roll back the account.
- If `inviter_uin` is set, a referral row is recorded if and
  only if the inviter is a real user other than self and the
  account has not already been referred. Invalid inviters are
  silently ignored.

Note: `register` does NOT take a password. The JWT returned in
the response is the only credential the client gets back; if the
client loses it before persisting, the account is effectively
unreachable. The client is expected to write the JWT and the
private keys to its local keychain in the same transaction.

### 2.3 `POST /auth/session`

Mints a fresh JWT for an existing authenticated session. Useful
when the client wants to extend its TTL without re-running any
identity logic.

Request: empty body, `Authorization: Bearer <existing JWT>`.

Response:

```json
{
  "token":  "<JWT>",
  "ws_url": "/ws/<uin>"
}
```

The `ws_url` is informational only — clients construct it
themselves in practice and the path layout is fixed.

### 2.4 `DELETE /auth/account` (burn)

Wipes the caller's account. Authorization required.

Behaviour:

1. Fans out a `{"type": "account_burned"}` WS message to every
   socket currently open for the UIN (so other devices learn
   immediately and can wipe local keys).
2. Deletes the `User` row. Cascading FKs drop all dependent
   rows (`device_tokens`, `contacts` rows the user owned,
   `one_time_prekeys`, etc.). Rows that hold a bare BigInteger
   reference to the UIN without an FK (e.g. group membership)
   are deliberately left dangling and
   garbage-collected by future writes.
3. Returns `204 No Content`.

There is no soft-delete, undo, or grace period. A burned UIN
returns to the allocator pool and may be reissued.

### 2.5 JWT format

- Algorithm: `HS256` (HMAC-SHA256 with a server-side secret;
  configurable via `JWT_ALG`).
- Header: standard `{"alg": "HS256", "typ": "JWT"}`.
- Claims:
  - `sub`: the UIN as a string.
  - `iat`: issued-at, UTC seconds since epoch.
  - `exp`: expiry, UTC seconds since epoch. Default TTL is
    `JWT_TTL_SECONDS = 60 * 60 * 24 * 30` (30 days).
- Signed with `JWT_SECRET` (deployment-specific). Tokens are
  rejected on bad signature, missing `sub`, expired `exp`,
  or unparseable `sub`.

Convention: the token is presented as
`Authorization: Bearer <jwt>` for every authenticated REST
request, and as the `token` query parameter for the WebSocket
upgrade (see Section 7).

### 2.6 Key material owned by the client

After bootstrap, the client holds:

| Key                          | Purpose                                                    | Stored where           |
|------------------------------|------------------------------------------------------------|------------------------|
| X25519 identity keypair      | Recipient half of every per-message ECDH (v=1 envelopes)   | Device keychain only   |
| Ed25519 signing keypair      | Signs every ciphertext (v=1 sealed-sender authentication)  | Device keychain only   |
| libsignal `IdentityKeyPair`  | Long-term identity for the libsignal stack                 | Device keychain only   |
| `SignedPreKeyRecord` (active)| Curve25519 prekey, signed by IdentityKey                   | Device keychain + server publishes public half |
| `KyberPreKeyRecord` (active) | PQ KEM prekey, signed by IdentityKey                       | Device keychain + server publishes public half |
| `OneTimePreKeyRecord` pool   | Target ~100 unused; one consumed per X3DH session start    | Device keychain + server publishes public halves |
| Per-session Double Ratchet   | Ratchet state per peer                                     | Device keychain only   |

The server stores only the **public** halves above, plus the
nickname and optional profile data. The server has no copy of
any private key. There is no key escrow, no recovery question,
and no server-side "forgot password" flow. The only recovery
path is the user-held seed phrase (Section 2.7), which never
leaves the device unless the user writes it down.

### 2.7 Account recovery (seed phrase)

Recovery is **opt-in** and **off by default**. A recoverable
account means one durable secret grants full access forever,
which weakens the ephemeral / "nothing to seize" posture; users
who want durability opt in by recording the phrase.

**Seed → keys.** A new account derives both base keypairs from a
single random 32-byte master seed via HKDF-SHA256 (empty/zero
salt; outputs clamped per curve):

- X25519 identity priv = `HKDF(seed, info="rcq-recovery-x25519-v1")[0:32]`
- Ed25519 signing priv = `HKDF(seed, info="rcq-recovery-ed25519-v1")[0:32]`

The seed is encoded as a 24-word **BIP39** phrase (standard
2048-word English wordlist), shown once for the user to write
down. The seed lives only in the device secure store, so
uninstalling without recording the phrase still loses the
account (ephemerality preserved). The info strings are fixed for
cross-platform parity (iOS CryptoKit ⇄ Android BouncyCastle ⇄
the web @noble stack all derive identical keys from a phrase).

**Legacy accounts** (created before seed derivation) have no
derivable seed; they instead export their raw
`identity_priv || signing_priv` (64 bytes) as a **48-word** BIP39
phrase. Restore accepts either 24- or 48-word input.

**Restore = prove ownership of the signing key.** A stateless
two-step challenge/response that reveals nothing about whether an
account exists:

`POST /auth/recover/challenge`
```json
{ "signing_key": "<base64 Ed25519 public key>" }
```
→ `{ "challenge": "<opaque short-lived (~120s) token>" }`

`POST /auth/recover`
```json
{
  "signing_key": "<base64 Ed25519 public key>",
  "challenge":   "<from the challenge step>",
  "signature":   "<base64 Ed25519 signature over the challenge string>"
}
```
→ `{ "uin": <int>, "token": "<JWT>" }` — same shape as
`/auth/register` (Section 2.2).

The server verifies the challenge token, verifies the Ed25519
signature over the challenge bytes against the supplied public
key, then returns the UIN bound to that signing key with a fresh
session token. Errors: `400 invalid_challenge` / `missing_key`,
`401 bad_signature`, `404 identity_not_found`. (The `signing_key`
column is indexed for this lookup.)

**Scope of recovery.** Restores the UIN, identity, and
server-side data (contacts, groups, pending requests). Local
message **history is not** restored — it is device-only E2E state
— unless an encrypted history backup is added later. On a
restored device the client re-publishes a fresh prekey bundle and
peers see a key change (surfaced via safety numbers); v=1 keeps
working, v=2 sessions re-bootstrap. Running the same identity on
two live devices at once is a migration, not multi-device: the
v=2 ratchet desyncs (see Section 13). For a per-device identity
that coexists, see Section 5.6.

## 3. User Profile & Visibility

### 3.1 `GET /users/me/info` and `GET /users/{uin}/info`

Returns a `PublicUser` for the requested UIN. The shape depends
on the viewer's relationship to the target.

Always present (the cryptographic identity layer cannot be
hidden, because senders need it to encrypt):

| Field                     | Type        | Notes                                |
|---------------------------|-------------|--------------------------------------|
| `uin`                     | int         |                                      |
| `nickname`                | string      | 1..64 chars                          |
| `identity_key`            | string      | base64 X25519 pub                    |
| `signing_key`             | string      | base64 Ed25519 pub                   |
| `signal_identity_key`     | string|null | base64 libsignal IdentityKey; null = v=1 only |
| `signal_registration_id`  | int|null    | libsignal registrationId             |
| `status`                  | string      | see Section 3.3                      |

Gated by the target's `profile_visibility` setting (default
`everyone`):

| Field            | Type        |
|------------------|-------------|
| `first_name`     | string|null |
| `last_name`      | string|null |
| `age`            | int|null    |
| `gender`         | string|null (also gated by `gender_visibility`) |
| `city`           | string|null |
| `country`        | string|null |
| `about`          | string|null |
| `interests`      | list[str]   |
| `homepage`       | string|null |
| `status_message` | string|null |

Gated separately:

- `last_seen` (datetime|null): governed by `last_seen_visibility`
  (default `everyone`).

Owner-only echoes (always null for third-party callers, so the
owner can render the Settings page without an extra fetch):

`last_seen_visibility`, `gender_visibility`, `profile_visibility`,
`group_invite_policy`, `call_policy`, `read_receipts_visibility`,
`presence_persistent`, `presence_ttl_minutes`.

### 3.2 Visibility scopes

Every visibility-gated field uses the same tri-state enum:

| Value      | Behaviour                                                       |
|------------|-----------------------------------------------------------------|
| `everyone` | Returned to any authenticated viewer.                           |
| `contacts` | Returned only when the viewer has a `Contact(owner=viewer, contact=target)` row. |
| `nobody`   | Never returned to non-owners (the owner always sees their own). |

`gender_visibility` defaults to `nobody` (opt-in to surface);
every other tri-state defaults to `everyone`. `read_receipts_visibility`
and `call_policy` are **client-enforced**: the server stores and
echoes the setting but does not gate any endpoint based on it
(see Section 13.2).

### 3.3 Presence

The `status` enum:

| Value       | Meaning                                                  |
|-------------|----------------------------------------------------------|
| `online`    | Live WS connection; recent heartbeat.                    |
| `away`      | User-chosen "around but not actively at the app".        |
| `dnd`       | Do not disturb; same liveness as online.                 |
| `invisible` | User-chosen hidden. Owner sees `invisible`; other viewers see `offline`. |
| `offline`   | Derived state. The server NEVER writes `offline` to `users.status` during normal operation; it is derived from `last_seen` freshness. |

"Online" is **not** trusted from a stored column. A client must
heartbeat (see Section 7) to stay online. Definitions:

- `PRESENCE_FRESHNESS_SECONDS = 60`. A user with `last_seen <
  now - 60s` is considered offline regardless of their stored
  `status`.
- The stored `status` is consulted only for the sub-state pick
  (`away`/`dnd`/`invisible`) and only when freshness is current.
- `presence_persistent: true` opts the user OUT of the freshness
  gate: their chosen `status` is broadcast to watchers even
  after the WS goes stale.
- `presence_ttl_minutes` is an optional cap on persistent
  presence. NULL or 0 means "forever"; a positive value means
  "show this status for at most N minutes past last_seen, then
  fall back to offline". Allowed values are 0, 30, 60, 180, 480,
  1440 (mirrors the iOS picker).

`POST /presence/status`:

```json
{ "status": "online|away|dnd|invisible|offline", "status_message": "<string|null>" }
```

Side effects:

- Writes `status` (a literal `"offline"` is stored as
  `"invisible"` instead — the column is reserved for user-chosen
  sub-states).
- Writes `status_message` and bumps `last_seen`.
- Fans out a `presence` WS event to the watcher set: every UIN
  that has the caller in their contact list, plus every UIN
  that shares a group with the caller, minus anyone the caller
  has blocked. `invisible` is reported to watchers as `offline`.

Response: `{"ok": true}`.

### 3.4 `PUT /users/me`

Partial update. The body is a `ProfileUpdate` with every field
optional; only fields present in the JSON payload are written.

Editable fields: `nickname`, `first_name`, `last_name`, `age`,
`gender`, `city`, `country`, `about`, `interests` (list of
strings; server stores comma-joined), `homepage`, `status_message`.

Editable settings: `last_seen_visibility`, `gender_visibility`,
`profile_visibility`, `group_invite_policy`, `call_policy`,
`read_receipts_visibility`, `presence_persistent`,
`presence_ttl_minutes`.

Validation:

- All `*_visibility` and `*_policy` fields must be one of
  `everyone`, `contacts`, `nobody`. Bad value → `400`.
- `gender` must be one of `male`, `female`, `other`, or null.
- `presence_ttl_minutes` must be one of `0, 30, 60, 180, 480,
  1440`.

Response: a fresh `PublicUser` rendered from the owner's
viewpoint (so the response includes the owner-only echo fields).

### 3.5 Push tokens and preferences

`POST /users/me/push-token`:

```json
{ "token": "<APNs device token>", "platform": "ios" | "ios-voip" }
```

Idempotent on `(uin, token)` via Postgres `INSERT ... ON
CONFLICT DO UPDATE`; bumps `last_seen` on conflict. `204 No
Content`.

`DELETE /users/me/push-token`: same body shape; removes the
matching row if present (no error if absent).

`GET /users/me/push-preferences`:

```json
{
  "contact_requests":      true,
  "muted_uins":            [<int>, ...],
  "muted_group_ids":       [<int>, ...]
}
```

`PUT /users/me/push-preferences`: partial update; only present
keys are written. Lists are de-duplicated and sorted. Returns
the merged state.

### 3.6 Out of scope on the profile

The model also carries `is_suspended`, `active_days`, and
`last_active_day`. `is_suspended` is admin-set and gates the
WebSocket close code (Section 7). (A few vestigial columns from
the pre-pivot economy layer remain in the table but are dead and
unused — see Section 14.1.)

## 4. Contact Graph

The contact graph is symmetric in storage (two `Contact` rows
per accepted pair) but bilateral in operation (each side can
remove independently).

### 4.1 Model

```sql
contacts:           id, owner_uin, contact_uin, blocked, created_at
                    UNIQUE(owner_uin, contact_uin)

contact_requests:   id, from_uin, to_uin, state ENUM('pending','accepted','declined'), created_at
                    UNIQUE(from_uin, to_uin)
```

### 4.2 `GET /contacts`

Returns the caller's contact list as `ContactRow[]`:

```json
[
  {
    "uin":                  <int>,
    "nickname":             "<string>",
    "status":               "online|away|dnd|offline",
    "status_message":       "<string|null>",
    "blocked":              <bool>,
    "identity_key":         "<base64>",
    "signing_key":          "<base64>",
    "signal_identity_key":  "<base64|null>",
    "gender":               "<string|null>",
    "last_seen":            "<ISO datetime|null>"
  },
  ...
]
```

Notes:

- `status` here is `visible_status(u)` — invisible reads as
  offline, stale `last_seen` reads as offline.
- `gender` and `last_seen` are filtered against the target's
  visibility settings; the viewer is always a mutual contact in
  this endpoint (the row only exists because the caller added
  them), so `everyone` and `contacts` both pass; `nobody` hides.
- `last_seen` is null when the contact is currently online (the
  `status` field already conveys liveness).

### 4.3 `POST /contacts/request`

Request: `{ "to_uin": <int> }`.

Behaviour matrix:

| Precondition                                           | Result                                                 |
|--------------------------------------------------------|--------------------------------------------------------|
| `to_uin == self`                                       | `400` "cannot add yourself"                            |
| `to_uin` does not exist                                | `404` "no such user"                                   |
| Already a mutual contact                               | `409` "already in your contact list"                   |
| Reverse pending request exists (they asked first)      | Auto-accept: both `Contact` rows inserted, both sides notified, returns `{state: "accepted", auto: true}` |
| Outbound pending request already exists                | Idempotent no-op, returns existing                     |
| Outbound declined/accepted request exists              | Re-opens as `pending`                                  |
| None of the above                                      | Creates new `pending`                                  |

Rate limit: `30/hour` per identity (`contact_request` bucket).

Response: `{ "id": <int>, "state": "pending|accepted", "auto"?: bool }`
with HTTP `202 Accepted`.

Side effects:

- On pending creation / re-open: WS `contact_request` event to
  the target. If the target is offline AND their
  `push_preferences.contact_requests` is true, an APNs alert is
  sent ("`<sender_nickname>` wants to add you as a contact",
  thread-id `pending`).
- On auto-accept: WS `contact_response` to the requester. APNs
  fires only if `should_push_for(kind="contact_response_accepted")`
  passes (default true; gated by muted_uins).

### 4.4 `GET /contacts/pending`

Returns inbound pending requests for the caller:

```json
[ { "id": <int>, "from_uin": <int>, "nickname": "<string>", "state": "pending" }, ... ]
```

### 4.5 `POST /contacts/respond`

Request: `{ "request_id": <int>, "accept": <bool> }`.

- `404` if not a recipient of the request.
- Idempotent if the request is no longer pending (returns
  current state without modification).
- On accept: mutual `Contact` rows inserted; WS
  `contact_response` to requester; APNs push if offline and
  preferences allow.
- On decline: `state = "declined"`. WS event still sent; APNs
  is deliberately suppressed (no "X declined your friend
  request" banner).

Response: `{ "state": "accepted" | "declined" }`.

### 4.6 `DELETE /contacts/{contact_uin}`

ICQ-style mutual remove. Drops the caller's row AND the
contact's reverse row (so the peer also stops listing the
caller). If the reverse row existed, a WS `contact_removed`
event is sent to the peer:

```json
{ "type": "contact_removed", "peer_uin": <int> }
```

The server does NOT silence the peer's future sealed-sender
messages — sealed sender means the server doesn't know who sent
what. The iOS client maintains a `RemovedContactsStore` and
drops incoming messages from removed peers client-side after
decrypting and identifying the sender.

`204 No Content`.

### 4.7 `POST /contacts/{contact_uin}/block`

Toggles the `blocked` flag on the caller's row pointing at
`contact_uin`. `404` if not in list. Returns `{ "blocked": <bool> }`.

Blocking is a client-side filter only for messages (same sealed-
sender constraint). On the server, the `blocked` flag is
consulted by group membership flows:

- The group owner cannot have blocked users added to their
  group by anyone else.
- A user is filtered out of the presence watcher set if they're
  on the user's block list.

## 5. Cryptographic Keys & Prekey Publishing

The protocol carries two parallel key layers:

- **v=1 / sealed-sender base layer.** Every account always has a
  long-term X25519 ECDH keypair (`identity_key`) and a long-term
  Ed25519 signing keypair (`signing_key`). These are uploaded at
  `/auth/register`. They are used for the v=1 envelope path
  (per-message ECIES tunnel + Ed25519 signature inside).
- **v=2 / libsignal PQXDH layer.** A complete libsignal key
  bundle (identity, registration ID, signed prekey, Kyber
  prekey, one-time prekeys) is uploaded separately via
  `/keys/bundle`. Peers that have a non-null bundle are
  addressed with v=2 envelopes (X3DH/PQXDH + Double Ratchet
  inside the outer sealed-sender tunnel).

Both layers can be live simultaneously. The server returns
`signal_identity_key` as null when v=2 is not present; the
sender uses that signal to fall back to v=1.

### 5.1 `POST /keys/bundle`

Authenticated. Replaces any existing libsignal material on the
caller's account.

Request:

```json
{
  "signal_identity_key": "<base64 of 33-byte libsignal IdentityKey>",
  "registration_id":     <int, [1..16380]>,
  "signed_prekey": {
    "id":        <int>,
    "public":    "<base64 of 33-byte Curve25519 pub>",
    "signature": "<base64 of identity-key signature over `public`>"
  },
  "kyber_prekey": {
    "id":        <int>,
    "public":    "<base64 of serialized KEMPublicKey>",
    "signature": "<base64 of identity-key signature over `public`>"
  },
  "one_time_prekeys": [
    { "id": <int>, "public": "<base64 of 33-byte pub>" },
    ...
  ]
}
```

Behaviour:

- Writes `signal_identity_key`, `signal_registration_id`,
  signed prekey fields, Kyber prekey fields onto the `User`
  row. Both `*_uploaded_at` timestamps are stamped server-side.
- Wipes the existing OPK pool for this UIN and inserts the
  array from the request.
- `204 No Content`.

This endpoint is intended for first-time bootstrap and full
re-key (a fresh device, or `/auth/register` followed by
`/keys/bundle`). Top-ups go through `/keys/prekeys`.

### 5.2 `POST /keys/prekeys` (replenish)

Authenticated.

Request:

```json
{
  "one_time_prekeys": [
    { "id": <int>, "public": "<base64>" },
    ...
  ]
}
```

Adds OPKs to the existing pool. Idempotent on `prekey_id`
collision — duplicates are silently skipped so a retry of a
partially-uploaded batch is safe. Does not modify identity or
signed prekey. `204 No Content`.

The client is expected to replenish when its pool drops below
~25 (target pool size: 100).

### 5.3 `GET /keys/{uin}/bundle`

Authenticated. Returns what a sender needs to start an X3DH
session with `uin`. Atomically consumes one OPK from the pool.

Response (`200`):

```json
{
  "uin":                  <int>,
  "registration_id":      <int>,
  "signal_identity_key":  "<base64>",
  "signed_prekey":        { "id": <int>, "public": "<base64>", "signature": "<base64>" },
  "kyber_prekey":         { "id": <int>, "public": "<base64>", "signature": "<base64>" },
  "one_time_prekey":      { "id": <int>, "public": "<base64>" } | null
}
```

`404` with body `"user has no signal bundle"` is returned when
the target has not uploaded a libsignal bundle. The sender
treats this as "fall back to v=1 envelope".

`one_time_prekey` is null when the recipient's pool is
exhausted. The sender may proceed without one (X3DH still works
with just the signed prekey, at the cost of one less
contributory secret).

OPK consumption: the endpoint selects the oldest unconsumed OPK
ordered by row id, marks `consumed = true`, and returns it. Two
parallel fetches against the same UIN serialize in the
single-worker event loop today; the multi-worker hardening
(`SELECT ... FOR UPDATE SKIP LOCKED`) is a known TODO in the
source.

Consumed rows remain in the table briefly so a retry of an
in-flight request hits the same row; periodic GC of consumed
rows is not yet implemented.

### 5.4 `GET /keys/me/status`

Pool-health report so the client knows when to top up.

Response:

```json
{
  "has_bundle":               <bool>,
  "one_time_prekey_count":    <int>,
  "target_count":             100,
  "signed_prekey_age_seconds": <int|null>
}
```

### 5.5 Key rotation rules

- **X25519 / Ed25519 base keys** (`identity_key`, `signing_key`):
  fixed for the lifetime of the account. Rotation is only via
  account migration (Section 10) or burn-and-register.
- **libsignal IdentityKey**: rotated only by re-running
  `/keys/bundle` (full re-bootstrap).
- **Signed prekey**: the client is expected to rotate
  periodically (typical cadence: weekly). Each rotation calls
  `/keys/bundle` with the new signed prekey and a fresh OPK
  batch.
- **Kyber prekey** (last-resort): a single periodically-rotated
  key, not a pool. Reuse across sessions is acceptable because
  forward secrecy comes from the EC ephemeral side; Kyber only
  contributes post-quantum hardness, which does not degrade with
  reuse.
- **One-time prekeys**: each is consumed exactly once. Top up
  via `/keys/prekeys` when count drops.

### 5.6 Multi-device (secondary devices)

Everything above is per-UIN with an implicit **primary** device
(libsignal `deviceId = 1`, bundle on the user row). A UIN may also
register **secondary** devices (e.g. the web client) so each runs
its own libsignal session. The whole mechanism is additive and
back-compatible: pre-multi-device clients ignore it and keep using
device 1.

- **Per-device OPK pools.** `one_time_prekeys.device_id` is `NULL`
  for the primary pool (phone) and the device's id (`2..127`) for a
  secondary. The primary fetch/replenish/upload paths scope to
  `device_id IS NULL`, so a phone re-bootstrap never drains a
  secondary's pool and vice versa.

`POST /keys/devices` — register a secondary device. The server
assigns a `device_id` (2..127). The body carries the device's own
libsignal bundle (identity / signed prekey / Kyber prekey / OPK
batch) plus a **`sealed_sender_pub`**: the X25519 OUTER-ECIES key a
sender encrypts the sealed-sender envelope to for *this* device.
(The primary device's outer key is the UIN `identity_key` from
`/users/{uin}/info`; a secondary holds only its own keys and never
the account master key.) → `{ "device_id": <int> }`.

`GET /keys/{uin}/devices` — list a UIN's devices (the primary, when
it has a published bundle, plus all secondaries). A sender uses this
to fan out one ciphertext per device.

`GET /keys/{uin}/devices/{device_id}/bundle` — the prekey bundle for
one device. `device_id = 1` delegates to the legacy
`GET /keys/{uin}/bundle`; `>= 2` consumes that device's own OPK
pool. Bundles carry two additive fields: `device_id` and
`sealed_sender_pub` (old clients ignore both).

A v=2 message is encrypted to exactly ONE libsignal session, so
reaching a UIN on all its devices requires the **sender** to fan
out (one ciphertext per device). Delivery is unchanged: the WS
already fans out to every socket of a UIN (Section 7.2) and the
offline queue is per-UIN, so each device decrypts its own ciphertext
and ignores the rest — no per-device delivery addressing is needed.
A staged rollout is inherent: a recipient is reachable on a new
device only once senders are device-aware (old senders still reach
device 1). This is the same dependency Signal's multi-device has.

## 6. Messaging Protocol

### 6.1 Envelope formats

The server is type-agnostic. From its perspective, an envelope
is a base64-encoded opaque blob plus a small `envelope_type`
discriminator and an addressing tuple (`to_uin` for 1:1,
`group_id` + per-member `to_uin` for groups). The server never
parses the payload.

**Metadata visible to the server per envelope:**

| Field            | Visible to server | Notes |
|------------------|-------------------|-------|
| recipient UIN    | yes               | needed for routing |
| `envelope_type`  | yes               | string discriminator (see below) |
| `received_at`    | yes               | server-stamped UTC                 |
| `group_id`       | yes (group only)  | for routing fanout                 |
| sender UIN       | NO (v=1 + v=2)    | inside the encrypted payload only  |
| payload bytes    | opaque            | ciphertext                         |
| size in bytes    | yes               | byte length of base64 ciphertext   |

**Envelope-type discriminators** (informational; the server does
not enforce the list):

| `envelope_type` | Purpose                                                         |
|-----------------|-----------------------------------------------------------------|
| `message`       | Standard message body (text, attachment refs, edits, etc.)      |
| `nudge`         | "Buzz" — UI animation prompt                                    |
| `delete`        | Tombstone instruction (sender asks recipient to delete a message) |
| `system`        | System messages (group events, etc.)                            |
| `read`          | Read-receipt envelope (client opt-in, see Section 13.2)         |
| `reaction`      | Emoji reaction toggle                                           |
| `bounce`        | Delivery failure relay                                          |
| `visit`         | "Saw your profile" pulse                                        |

Only `message` and `system` envelopes trigger push notifications.
The rest are "delivery-state plumbing or cosmetic" (rate limiter
+ envelope type filter `_PUSHABLE_TYPES`).

**v=1 sealed-sender envelope** (when the recipient has not
uploaded a libsignal bundle). Layout — opaque to the server,
defined by the client:

```
v=1 envelope (base64):
  outer: ECIES(X25519, recipient.identity_key)
    inner plaintext:
      sender_uin           (uint64)
      sender_identity_pub  (32 bytes)
      sender_signing_pub   (32 bytes)
      timestamp            (uint64)
      message_type         (uint8)
      ciphertext           (AES-GCM keyed from ECIES)
      ed25519_sig          (over the rest, by sender_signing_priv)
```

The recipient verifies `ed25519_sig` against
`sender_signing_pub`, cross-checks it against
`/users/{sender_uin}/info.signing_key`, then trusts the sender
identity inside. The server-side `from_uin` field of the
storage row is always null/unused for sealed sends.

**v=2 libsignal envelope** (when both ends have published a
PQXDH bundle). The opaque payload is a standard libsignal
`SealedSenderMessageContent` wrapping a `PreKeySignalMessage`
(first message of a session) or `SignalMessage` (subsequent).
Inside that is a libsignal `Content` message protobuf. See the
upstream libsignal-protocol-rust spec for full wire layout.

The two envelope formats are NOT distinguished on the wire by a
version byte at the server level; the server simply ferries
bytes. The client picks the format based on whether
`signal_identity_key` is present on the recipient's `PublicUser`,
and the recipient picks the parser the same way (or by
trial-decrypt on a known prefix). Implementations MUST NOT
assume the server enforces a version.

### 6.2 Sending

#### 6.2.1 1:1 `POST /messages/sealed`

**Anonymous endpoint by design.** No `Authorization` header is
required or consulted. This is the sealed-sender path — the
server cannot identify the sender. Rate limiting falls back to
client IP (per Section 12), with a soft binding to UIN when the
client happens to send a bearer anyway.

Request:

```json
{
  "to_uin":        <int>,
  "envelope_type": "<string; default 'message'>",
  "payload":       "<base64 of opaque ciphertext>"
}
```

Behaviour:

- `404` if `to_uin` does not exist.
- Rate limit: `120/min` per identity (`messages_send` bucket).
- The envelope is **always queued** in `offline_messages`
  AND attempted via WebSocket. The WS attempt returning "live"
  only means the bytes hit a TCP buffer — the client might
  still lose them mid-flight, so the queue acts as the
  reconciliation source on next drain.
- If the recipient is offline AND `envelope_type ∈ {message,
  system}`, an APNs push fires carrying the envelope as
  `userInfo["env"]` (see Section 8).

Response:

```json
{
  "delivered":   <bool>,    // true if recipient was online at publish time
  "queued":      true,      // always true
  "server_time": "<ISO datetime>"
}
```

The recipient receives the WS notification as:

```json
{
  "type":        "<envelope_type>",
  "payload":     "<base64>",
  "server_time": "<ISO>"
}
```

#### 6.2.2 Group send `POST /messages/group-sealed`

Authenticated only in the sense that the WS fanout uses the
recipient's session; the HTTP endpoint itself is structurally
anonymous, same rationale as `/messages/sealed`. The sender
encrypts the payload **once per member** (skipping self) and
ships all N ciphertexts in one POST.

Request:

```json
{
  "group_id":      <int>,
  "envelope_type": "<string>",
  "payloads": [
    { "to_uin": <int>, "payload": "<base64>" },
    ...
  ]
}
```

Behaviour:

- `404` if the group has no members.
- Rate limit: `60/min` per identity (`messages_group_send`).
- For each entry whose `to_uin` is an actual group member:
  - Queue an `OfflineGroupMessage` row.
  - Attempt WS delivery to that UIN.
- For offline recipients with a pushable `envelope_type`: APNs
  push of their specific ciphertext, unless the group is in
  the recipient's `push_preferences.muted_group_ids`.

Response: same `SendOut` shape as 1:1.

Each ciphertext is sealed to exactly one recipient's identity
key. The server sees N opaque blobs, never any plaintext.

### 6.3 Receiving

#### 6.3.1 `GET /messages/queue`

Authenticated. Drains every queued envelope (1:1 and group)
addressed to the caller.

Behaviour:

- Selects all `offline_messages` and `offline_group_messages`
  for `to_uin = caller`, ordered by `received_at` ascending.
- Sorts the merged list by `received_at`.
- DELETEs every row read in the same transaction (drain semantics).
- Returns the merged list.

Response:

```json
[
  {
    "id":            <int>,
    "envelope_type": "<string>",
    "payload":       "<base64>",
    "received_at":   "<ISO>",
    "group_id":      <int|null>     // null for 1:1
  },
  ...
]
```

**Idempotency:** the drain-and-delete pattern is not idempotent
on the server side. If the response is lost in flight, the
client will not see those envelopes again via `/messages/queue`.
The mitigation is that the same envelopes are also dispatched
via WebSocket when the recipient is online, and the client
de-duplicates by message UUID at the application layer (every
`message` envelope's inner content carries a UUID4 generated by
the sender). Implementations MUST de-duplicate by inner-content
UUID, not by server-row ID.

#### 6.3.2 WebSocket push

The same envelopes are forwarded over WS in real time when the
recipient is connected. Format on WS:

```json
{
  "type":        "<envelope_type>",          // matches the envelope_type field
  "payload":     "<base64>",
  "server_time": "<ISO>",
  "group_id":    <int>                       // present for group sends only
}
```

Ordering guarantees:

- Per-pair ordering is not guaranteed at the protocol level.
  Server-side timestamps are at second-resolution; two messages
  that arrive within the same second from different workers may
  be reordered before being delivered.
- Inside a single libsignal session, the Double Ratchet itself
  provides causal ordering (a v=2 receiver detects and corrects
  reordered messages within the session).
- For v=1, reordering is the application's responsibility; the
  client orders by the inner timestamp.

Acknowledgement model:

- There is no message-level ACK from client to server.
- The HTTP drain is the implicit ACK for queued envelopes.
- The WS path has no ACK at all; clients are expected to
  reconcile against the queue on reconnect.

### 6.4 Group messaging

#### 6.4.1 Per-recipient sealed-sender (current default)

Every group send encrypts the payload once per recipient member
using that member's `identity_key`. This is straightforward but
costs O(N) ciphertexts per send. It is the only mode currently
in production.

A future mode using libsignal's Sender Keys (one ciphertext
fanned out, member-private chain key) is planned for groups
above ~50 members. It is NOT in scope for this v1 spec.

#### 6.4.2 Membership

See Section 7-equivalent endpoints under `/groups/...`:

- `POST /groups` — create.
- `GET /groups` — list groups the caller is a member of.
- `GET /groups/{id}` — full info (members + settings).
- `GET /groups/{id}/preview` — lightweight info for a non-member
  considering joining (carries name, description, member count,
  owner nickname, avatar; does NOT carry membership or history).
- `GET /groups/search?q=...` — name substring search; excludes
  groups the caller is already in.
- `POST /groups/{id}/join` — self-join (open groups only;
  closed groups require an owner-issued invite).
- `POST /groups/{id}/members` — invite (any member can invite,
  subject to the group's invite policy).
- `DELETE /groups/{id}/members/{member_uin}` — kick (admin+) or
  self-leave. Owner-leave promotes oldest member to owner; if
  the group is empty after, the group row is deleted.
- `PATCH /groups/{id}` — partial update of group metadata
  (name/description/avatar: admin+; post_policy, entry_price,
  is_closed, members_hidden: owner only; pinned_text: admin+).
- `DELETE /groups/{id}` — owner only; fans out `group_deleted`
  to every member.

Membership cap: a single user may own at most `MAX_GROUPS_PER_USER
= 5` groups (member-of unlimited).

#### 6.4.3 Group settings

Fields on the `Group` row:

| Field                | Type       | Default     | Editable by      |
|----------------------|------------|-------------|------------------|
| `name`               | string(64) | required    | admin            |
| `description`        | text       | null        | admin            |
| `owner_uin`          | int        | creator     | (transfers on owner-leave) |
| `avatar_seed`        | int        | hash(name)  | (immutable)      |
| `avatar_media_id`    | string|null| null        | admin            |
| `avatar_media_key`   | string|null| null        | admin            |
| `post_policy`        | enum       | `all`       | owner            |
| `entry_price_tokens` | int|null   | null (free) | owner            |
| `is_closed`          | bool       | false       | owner            |
| `members_hidden`     | bool       | false       | owner            |
| `pinned_text`        | string(500)| null        | admin            |
| `pinned_at`          | datetime|null | null     | (auto-stamped)   |
| `pinned_by`          | int|null   | null        | (auto-stamped)   |

#### 6.4.4 Post policy

| Value        | Behaviour                                                              |
|--------------|------------------------------------------------------------------------|
| `all`        | Every member can post. Default.                                        |
| `owner_only` | Broadcast mode. Only the owner can post; members read + react only. Enables the per-message view-count feature (Telegram-style). |

Server enforcement of `post_policy` is currently client-side:
the server's group fanout endpoint does not check
`post_policy` before routing. Closed-broadcast groups rely on
client behaviour to suppress sends from non-owners. **TODO:
confirm whether a server-side check is intended.**

The view-count endpoints (`/groups/{id}/messages/{mid}/viewed`
and `/groups/{id}/view-counts`) are gated to broadcast groups
(404 otherwise).

#### 6.4.5 Closed groups

`is_closed = true` causes `POST /groups/{id}/join` to 403 for
non-owners with `{"code": "group_closed"}`. The only way into
a closed group is `POST /groups/{id}/members` initiated by an
existing member (which itself is subject to the invitee's
`group_invite_policy` from Section 3).

#### 6.4.6 Group invite policy

Every prospective invitee's `group_invite_policy` is honoured
on `POST /groups` (creation) and `POST /groups/{id}/members`
(add). Tri-state same as profile visibility:

- `everyone` (default): anyone can add the user.
- `contacts`: only users in the invitee's contact list can add.
- `nobody`: 403 on every attempt.

#### 6.4.7 Pinned text (plaintext caveat)

`pinned_text` is stored **plaintext** on the server. This is a
deliberate exception to the otherwise-uniform E2EE model. A
brand-new joiner has no libsignal sessions with existing members
yet, so they cannot decrypt any prior content. The pinned-text
banner exists so the rules / welcome / link-of-the-day are
visible immediately upon joining. The exception is scoped to
this single 500-character field. Implementations MUST treat
the pinned text as group metadata, not user message content.

## 7. WebSocket Channel

### 7.1 Handshake

URL: `wss://<api-host>/ws/{uin}?token=<jwt>`

- The path UIN MUST equal the JWT's `sub`. Mismatch → close
  code `4403`.
- Invalid JWT → close code `4401`.
- If the user is `is_suspended = true` → close code `4408`.
- Otherwise the upgrade succeeds and the worker registers the
  socket in its local `_conns` map AND adds the UIN to the
  cluster-wide `ws:online_uins` Redis set.
- The new connection supersedes any prior connection for the
  same UIN on the same worker (old socket closed with code
  `4000` "superseded"). A `supersede` fan-out is published so
  peer workers also drop stale sockets for this UIN.

### 7.2 Cross-worker fanout

A single backend deployment runs multiple uvicorn workers.
WebSocket objects cannot be moved between processes, so
fanout uses Redis pub/sub:

- Channel: `ws:fanout`.
- Envelope: `{"target": "user"|"all"|"supersede", "uin": <int>,
  "payload_text": "<JSON string>"}`.
- Every worker subscribes on first WS use; each publish is
  filtered locally against the worker's `_conns` map.

`is_online(uin)` is answered by `SISMEMBER ws:online_uins`,
which is cluster-wide. False-offline races are possible in the
multi-device-multi-worker case (one device just disconnected
on worker A while another stays connected on worker B; the
SREM races). The worst case is a redundant APNs push.

### 7.3 Heartbeat

The client is expected to send `{"type": "ping"}` on a ~25s
cadence. The server responds with `{"type": "pong", "t": "<ISO>"}`
and bumps `last_seen` for the UIN.

Online presence is **derived** from `last_seen` freshness; a
silent client whose `last_seen` ages past 60s reads as
offline to watchers, even without an explicit disconnect.

When the WS drops (clean disconnect, network drop, force-quit),
the server schedules a debounced offline broadcast with a 60s
grace window (`_OFFLINE_DEBOUNCE_SECONDS`). If the client
reconnects within the window, the scheduled task is cancelled
and no flicker is observed. After the window expires:

- A `presence` WS event with `status: "offline"` is fanned to
  the watcher set.
- Any active 1:1 call registration is cleared; the peer
  receives `call_end` with `reason: "peer_disconnected"`.
- Any audio-room presence is removed; remaining occupants
  receive `room_member_left`.
- Hood-Chat bucket presence is removed.

Clients are expected to reconnect on network changes,
backgrounding cycles, and unexpected close. The iOS client
uses exponential backoff capped at 30s and re-sends `room_enter`
+ similar presence resync on reconnect.

### 7.4 Event types

The WS channel is mostly **server-to-client**. The small
client-to-server set is: `ping`, `typing`, `hood_subscribe`,
`hood_unsubscribe`, `call_*` (signalling), and the audio-room
`room_*` events.

#### 7.4.1 `message`-family (server → client)

Dispatched for every WS-routed envelope (matches the
`envelope_type` chosen by the sender).

```json
{
  "type":        "message" | "nudge" | "delete" | "system" |
                 "read" | "reaction" | "bounce" | "visit",
  "payload":     "<base64>",
  "server_time": "<ISO>",
  "group_id":    <int>     // present for group sends only
}
```

Sender identity is inside the encrypted payload.

#### 7.4.2 `presence`

```json
{
  "type":           "presence",
  "uin":            <int>,
  "status":         "online|away|dnd|offline",
  "status_message": "<string|null>"
}
```

`invisible` is mapped to `offline` for third-party recipients.

#### 7.4.3 `typing`

Server forwards from client to client. The originating client
sends:

```json
{ "type": "typing", "to_uin": <int>, "active": <bool> }
```

Recipient sees:

```json
{ "type": "typing", "from_uin": <int>, "active": <bool> }
```

#### 7.4.4 Contact events

```json
{ "type": "contact_request",  "request_id": <int>, "from_uin": <int>, "from_nickname": "<string>" }
{ "type": "contact_response", "request_id": <int>, "accepted": <bool>, "to_uin": <int> }
{ "type": "contact_removed",  "peer_uin":   <int> }
```

#### 7.4.5 Group events

```json
{ "type": "group_created",             "group": <GroupOut> }
{ "type": "group_membership_changed",  "group": <GroupOut> }
{ "type": "group_deleted",             "group_id": <int> }
```

`GroupOut` shape is the same as the REST `GET /groups/{id}`
response. `group_membership_changed` is the universal
"something about this group's roster or settings changed"
event — clients should re-render their local state from the
embedded object.

#### 7.4.6 Account events

```json
{ "type": "account_burned" }
```

Sent by `DELETE /auth/account` and by `POST /account/migrate`
to every socket still open for the burned UIN. Clients are
expected to wipe local keys and route to the onboarding flow.

#### 7.4.7 Call signalling (1:1 voice/video)

Client sends:

```json
{ "type": "call_offer",                 "to_uin": <int>, "call_id": "<string>", "sdp": "<string>", "media": "audio|video" }
{ "type": "call_answer",                "to_uin": <int>, "call_id": "<string>", "sdp": "<string>" }
{ "type": "call_ice",                   "to_uin": <int>, "call_id": "<string>", "candidate": "<string>" }
{ "type": "call_end",                   "to_uin": <int>, "call_id": "<string>", "reason": "<string>" }
{ "type": "call_renegotiate",           "to_uin": <int>, "call_id": "<string>", "sdp": "<string>", "media": "audio|video" }
{ "type": "call_renegotiate_answer",    "to_uin": <int>, "call_id": "<string>", "sdp": "<string>" }
{ "type": "call_renegotiate_decline",   "to_uin": <int>, "call_id": "<string>" }
```

Server relays with `from_uin` set instead of `to_uin`. On
`call_offer` only, the server runs an atomic check-and-set
against the cluster-wide `calls:active` Redis hash; if either
endpoint is already in a call OR in an audio room, the offer
is rejected and the caller receives:

```json
{ "type": "call_end", "from_uin": <int>, "call_id": "<string>", "reason": "busy" }
```

Media itself is peer-to-peer over WebRTC's DTLS-SRTP. The
server is out of the media path. TURN credentials are minted
via `GET /users/me/turn-credentials` (Section 7.5).

If the recipient is offline on `call_offer`, the server sends a
**VoIP push** (Section 8) carrying the SDP so the iOS app can
present the incoming CallKit UI.

#### 7.4.8 Audio room events

(Audio rooms are a business feature; the WS events are listed
here for completeness because they share the channel.)

`room_enter`, `room_leave`, `room_offer`, `room_answer`,
`room_ice`, `room_speaking`. Server responses include
`room_roster`, `room_member_entered`, `room_member_left`,
`room_enter_rejected`. Detailed semantics belong with the
audio-rooms feature spec — out of scope for this document.

#### 7.4.9 Hood-Chat presence

`hood_subscribe` / `hood_unsubscribe` from client. Server
broadcasts `hood_count` updates to current bucket viewers.

#### 7.4.10 Reactions, read receipts

Reactions and read receipts are transported as standard
sealed-sender envelopes with `envelope_type: "reaction"` or
`envelope_type: "read"`. There is no dedicated server event
type; clients ingest them through the normal message path
and apply local effects.

### 7.5 `GET /users/me/turn-credentials`

Mints short-lived TURN credentials for WebRTC calls. Implements
the TURN REST API auth pattern (HMAC-SHA1 of `<expiry>:<uin>`
using a server-side shared secret).

Response:

```json
{
  "urls":       ["turn:<host>:3478?transport=udp", "turn:<host>:3478?transport=tcp"],
  "username":   "<expiry>:<uin>",
  "credential": "<base64 HMAC>",
  "ttl":        <int seconds>
}
```

When TURN isn't configured server-side, the response is empty
(`urls: []`); the client falls back to STUN-only signalling.

## 8. Push Notifications

RCQ uses Apple Push Notification service (APNs) via the HTTP/2
endpoint with ES256-signed JWTs. Two streams:

### 8.1 Alert + content push (`apns-push-type: alert`)

Topic: `<APNS_BUNDLE_ID>`. Payload shape:

```json
{
  "aps": {
    "alert":          { "title": "RCQ", "body": "New message" },
    "sound":          "default",
    "mutable-content": 1,
    "thread-id":      "<optional string>"
  },
  "env":     "<base64 sealed envelope, when applicable>",
  "envType": "<envelope_type when env is set>",
  "notif_kind": "<optional kind for NSE-side localization>"
}
```

Notes:

- `mutable-content: 1` is always set so the iOS Notification
  Service Extension (NSE) can intercept the push, decrypt
  `env` locally using the keys in the shared keychain group,
  and replace the generic title/body with the real sender +
  message preview before the user sees the banner.
- The payload contains **no sender UIN** (the server doesn't
  know who sent the message). The NSE is the only component
  that learns who sent what, and it runs on the user's device.
- `thread-id` routes the tap to the right surface on the iOS
  side. Convention:
  - `peer-<UIN>` → 1:1 chat with that UIN
  - `pending` → pending contact requests

### 8.2 Silent / background drain

The same alert push doubles as a wake trigger for the NSE; no
separate silent push is required for the queue-drain path. The
client also performs an explicit drain (`GET /messages/queue`)
on app foreground and on WS open.

### 8.3 VoIP push (`apns-push-type: voip`)

Topic: `<APNS_BUNDLE_ID>.voip`. Used only for incoming-call
wake-from-killed via PushKit. Payload is a flat dict:

```json
{
  "call_id":  "<string>",
  "from_uin": <int>,
  "nickname": "<string>",
  "media":    "audio|video",
  "sdp":      "<SDP string>",
  "kind":     "end"        // optional, used for early call_end fanout
}
```

PushKit + CallKit constraints require the iOS handler to call
`reportNewIncomingCall` synchronously upon receipt; a missed
VoIP push violates Apple's contract and revokes the privilege.

### 8.4 Push preferences (server-side gating)

For event kinds the server CAN identify the sender of —
`contact_request`, `contact_response_accepted`,
etc. — the server consults
`should_push_for(recipient, kind, sender_uin)` before firing
the push:

- A `muted_uins` entry for `sender_uin` blocks the push.
- `kind == "contact_request"` is gated by
  `push_preferences.contact_requests` (default true).

Sealed-sender messages cannot pass through this filter (sender
is unknown to the server) and always push when the recipient is
offline. The user mutes them via iOS system settings or by
muting the originating thread inside the app.

### 8.5 Group muting

`POST /messages/group-sealed` respects `muted_group_ids`: the
envelope is queued in `OfflineGroupMessage` regardless, but the
APNs alert is suppressed for muted groups.

### 8.6 Token lifecycle

- Registered via `POST /users/me/push-token` (Section 3.5).
- Pruned on `DELETE /users/me/push-token`.
- Pruned automatically on APNs response codes 400
  `BadDeviceToken`, 410 `Unregistered`, and 403
  `BadEnvironmentKeyInToken`.
- Cross-environment retry: if the primary host (configured via
  `APNS_ENVIRONMENT`) returns `BadEnvironmentKeyInToken` (403)
  or `BadDeviceToken` (400), the same payload is retried
  against the other host before the token is dropped. This
  covers users who installed in sandbox (dev/TestFlight) and
  later moved to production without iOS issuing a fresh token.

## 9. Encrypted Media Blobs

Media (photos, voice notes, video, files, group avatars) is
shipped out-of-band as opaque encrypted blobs. The server sees
only the ciphertext.

### 9.1 Size limits

Uploads are flat-free up to a hard safety cap of
`MAX_BLOB_SIZE = 2 GB` per blob (the per-blob bandwidth/disk
backstop). There is no paid tier and no per-byte charge — the
metered-jeton tier was removed in the 2026-05-27 pivot
(Section 14.1).

### 9.2 `POST /media/upload`

Multipart form:

- `blob`: the raw ciphertext bytes (`File`).

Bearer is optional (uploads are open, IP-rate-limited).

Behaviour:

- `413` if blob size > `MAX_BLOB_SIZE`.
- Write the bytes to `MEDIA_ROOT/<uuid>.bin`. (Production
  migration to R2/S3 is a TODO; local filesystem today.)

Response (`201`):

```json
{
  "media_id": "<32-char hex UUID>",
  "size":     <int>
}
```

### 9.3 `GET /media/{media_id}`

Returns the raw ciphertext (`application/octet-stream`).
`404` if the ID is not a valid UUID hex, or the file is
missing. **There is no auth on download** — anyone holding the
media_id can fetch the blob. The blob is useless without the
per-blob AES key, which travels inside the encrypted message
envelope between sender and recipient(s).

### 9.4 Key exchange

For each piece of media:

1. Sender generates a fresh AES key (typically AES-256-GCM)
   client-side.
2. Sender encrypts the plaintext with that key, producing
   ciphertext blob.
3. Sender uploads ciphertext, receives `media_id`.
4. Sender constructs the message envelope normally
   (Section 6.1). The inner plaintext includes:
   - `media_id`
   - the per-blob AES key
   - MIME type, dimensions, duration, etc.
5. Recipient decrypts the envelope, extracts `media_id` + key,
   fetches `GET /media/{media_id}`, decrypts the blob locally.

The server therefore knows:

- That a blob of N bytes was uploaded.
- The blob's UUID.

The server does NOT know:

- MIME type.
- Content type beyond byte count.
- Which message it belongs to.
- Which recipient(s) hold the key.
- Plaintext bytes.

### 9.5 `GET /media/usage`

Returns the caller's current-month traffic counter for the
Settings readout:

```json
{
  "year_month":     "YYYY-MM",
  "bytes_used":     <int>,
  "max_blob_bytes": <int>
}
```

### 9.6 Group avatars

Group avatars are uploaded as standard encrypted blobs. The
`avatar_media_key` field on `Group` is the base64 AES key
shared among all group members. Since every member can already
read every group plaintext (per-recipient encryption), exposing
the key to the full member set is no further weakening.

## 10. Account Migration & Burn

### 10.1 `POST /account/migrate`

Move every account-bound row from the caller's current UIN
onto a freshly-allocated (or user-owned) UIN. Free — the
pre-pivot jeton cost was removed.

Request (optional body):

```json
{ "target_uin": <int|null> }
```

- If `target_uin` is null/omitted: server allocates a fresh
  random UIN.
- If `target_uin` is set: the caller must own an `OwnedUin`
  row pointing at that UIN (reserved via the UIN shop, Section
  14). Returns `403 {"code": "uin_not_owned"}` otherwise.

Cooldown: `RCQ_MIGRATION_COOLDOWN_SECONDS` (default 0 in dev;
~604800 / 7 days in production). State is held as a Redis key
`migrate:cooldown:<uin>` with TTL so the cooldown is enforced
across workers. Returns `429 {"code": "cooldown",
"remaining_seconds": <int>}` while in window.

#### 10.1.1 What carries over

| Surface                       | Re-keyed | Notes                                  |
|-------------------------------|----------|----------------------------------------|
| `User` row                    | created  | New row with old `nickname`, profile fields, `identity_key`, `signing_key`, status visibilities, push_preferences |
| Contacts (both directions)    | yes      | `Contact.owner_uin` and `Contact.contact_uin` |
| Contact requests              | yes      |                                        |
| Offline message queue         | yes      | `OfflineMessage.to_uin`                |
| Group ownership & membership  | yes      | Both `Group.owner_uin` and `GroupMember.uin` |
| Audio room ownership / mute   | yes      |                                        |
| Poll creators + voters        | yes      |                                        |
| Hood banners                  | yes      |                                        |
| Stories                       | yes      |                                        |
| OwnedUins                     | yes      | Old UIN itself preserved as `OwnedUin(source="migrated")` under the new account |

#### 10.1.2 What does NOT carry over

- **libsignal material is deliberately NOT moved.**
  `signal_identity_key`, `signal_registration_id`, all signed
  / Kyber prekeys, and the OPK pool are set to NULL on the
  new account. The client is expected to re-run
  `/keys/bundle` on next launch under the new UIN. Peers
  re-handshake via X3DH when they next message the new UIN.
- The base X25519/Ed25519 keys (`identity_key`, `signing_key`)
  ARE copied verbatim. This keeps peers' v=1 ECIES sessions
  valid across the swap.
- Device push tokens are dropped (the iOS client re-registers
  under the new UIN).

#### 10.1.3 Side effects

1. WS `{"type": "account_burned"}` is fanned to every socket
   still open for the old UIN before the row is deleted.
2. The old `User` row is deleted. Cascading FKs drop dependent
   rows that have an FK constraint to `users.uin`. Rows that
   reference `users.uin` via a bare BigInteger (no FK) are
   re-keyed manually above.
3. The old UIN is stamped as `OwnedUin(owner=new_uin,
   source="migrated", tier=<derived>)` so it doesn't fall back
   into the allocator pool and so the user can swap back later
   via a second migration.
4. Redis cooldown key for the OLD uin is set with TTL =
   `MIGRATION_COOLDOWN_SECONDS`.

Response:

```json
{
  "new_uin": <int>,
  "token":   "<JWT>"
}
```

The client persists both, drops its old WS connection, and
re-connects under the new UIN.

### 10.2 Burn (immediate wipe)

`DELETE /auth/account` (Section 2.4). No grace period, no soft
delete. WS `account_burned` fan-out followed by row delete and
cascading FK cleanup. The UIN returns to the allocator pool.

## 11. Censorship Circumvention Transport

The censorship-circumvention transport is a network-layer
substitution. It does not touch the messaging protocol above
and has no access to plaintext or session keys.

### 11.1 Architecture

- Direct path: TCP+TLS to `api.rcq.app` (Caddy → uvicorn). Used
  whenever it works.
- Fallback path: `sing-box` (vendored as a library inside the
  iOS app) tunnelling to one of a small pool of relays in
  different ASNs/clouds.
- Path selection: `sing-box`'s built-in `urltest` outbound
  selector probes each candidate periodically and picks the
  lowest-RTT working one. Last-known-good is sticky.

### 11.2 Relay protocol stack

Each relay runs **two** protocols simultaneously, both fronted
behind different SNIs:

1. **VLESS + Reality** (XTLS Reality handshake mimicking a
   real high-reputation TLS site, e.g. a major CDN). Plays
   well in lower-pressure DPI environments.
2. **Hysteria2 + Salamander obfuscation** (QUIC-based, with
   Hysteria2's congestion control and the Salamander
   pre-encryption obfuscation layer). Pierces UDP-allowlist
   DPI regimes that drop VLESS+Reality.

Both protocols are listed inside the same `urltest` selector;
`sing-box` picks whichever currently works.

The protocol-specific wire details (VLESS, Reality, Hysteria2,
Salamander) are defined by the `sing-box` and Xray-core upstream
specifications. RCQ does not modify them. Implementations
reading this spec to write an alternate client should consult
those projects directly.

### 11.3 Relay config publishing

Endpoint: `https://relay.rcq.app/v1/config` (a Cloudflare
Worker; KV-backed). A GitHub Raw mirror at
`raw.githubusercontent.com/<org>/<repo>/<branch>/relays.json` is
the secondary source.

Format:

```json
{
  "version":    <int>,                  // bumped on every config push
  "issued_at":  "<ISO>",
  "relays": [
    {
      "id":         "<string>",
      "protocol":   "vless-reality" | "hysteria2",
      "host":       "<hostname>",
      "port":       <int>,
      "sni":        "<hostname>",
      "fingerprint":"<string>",         // server certificate fingerprint
      "params":     { ... }              // protocol-specific
    },
    ...
  ],
  "sig":  "<base64 Ed25519 signature over the canonical JSON of everything above except `sig` itself>"
}
```

The `sig` is an Ed25519 signature using a hard-coded public
key embedded in the iOS binary. A relay configuration with
invalid signature is rejected outright; this prevents a
network adversary controlling either the Cloudflare or GitHub
endpoint from injecting hostile relay endpoints (which they
could use to terminate the relay tunnel at an attacker-
controlled host — although the inner E2EE would still hold).

### 11.4 Burn-detect / rotation

When all currently-published relays start failing simultaneously
across multiple users, the team pushes a new signed config
(new relays, new SNIs, sometimes new ASNs). Clients re-fetch
on app foreground, on a fixed timer (~6h), and on a streak of
transport-layer failures. Rotation happens with zero App Store
release latency because everything except the protocol
implementations themselves is data, not code.

### 11.5 Layering invariant

The censorship transport sees the byte stream between the iOS
client and `api.rcq.app`. That stream is TLS terminated at the
server. The TLS payload itself is HTTP/2 carrying REST + WS,
and inside that, every message body is end-to-end encrypted as
per Sections 5-6. A compromised relay can correlate traffic
timing for a specific client but cannot read message content
and cannot inject decryptable messages.

This document does not specify the relay-side configuration.
For deeper background on the transport choices, see the team's
public posts: the Habr article (Russian) and the dev.to post
(English) covering the engineering rationale.

## 12. Error Codes & Rate Limits

### 12.1 HTTP error conventions

Errors follow FastAPI's default `HTTPException` shape:

```json
{ "detail": "<string|object>" }
```

Common status codes used by the messaging layer:

| Status | Meaning                                              |
|--------|------------------------------------------------------|
| 400    | Malformed body / invalid enum                        |
| 401    | Missing or invalid JWT                               |
| 403    | Authenticated but not permitted (admin-only / blocked / suspended / closed group) |
| 404    | Target row not found                                 |
| 409    | Conflict (already a contact, group cap reached, UIN already registered) |
| 413    | Blob too large                                       |
| 422    | Pydantic validation failure (rare; usually 400)      |
| 429    | Rate limit exceeded                                  |
| 503    | Admin panel disabled (admin endpoints only)          |

For 429 the response includes a `Retry-After` header with the
suggested back-off in seconds and a body of the form
`{"detail": {"code": "rate_limited", "retry_after": <int>}}`.

Some endpoints return structured error bodies for client UI:

- `403` closed group:
  `{"detail": {"code": "group_closed"}}`
- `403` blocked by owner:
  `{"detail": {"code": "blocked"}}`
- `403` migration target not owned:
  `{"detail": {"code": "uin_not_owned", "uin": <int>}}`
- `409` UIN already registered:
  `{"detail": {"code": "uin_already_registered", "uin": <int>}}`
- `429` cooldown:
  `{"detail": {"code": "cooldown", "remaining_seconds": <int>}}`

### 12.2 Rate limits (messaging-layer endpoints)

All limits are per-identity (UIN for authenticated requests,
client IP for anonymous), sliding window, backed by Redis.
Limits fail-soft: a Redis outage allows the request through.

| Rule                  | Limit       | Window   | Endpoint                              |
|-----------------------|-------------|----------|---------------------------------------|
| `users_search`        | 60          | 60s      | `GET /users/search`                   |
| `contact_request`     | 30          | 3600s    | `POST /contacts/request`              |
| `groups_create`       | 10          | 3600s    | `POST /groups`                        |
| `groups_search`       | 60          | 60s      | `GET /groups/search`                  |
| `group_preview`       | 120         | 60s      | `GET /groups/{id}/preview`            |
| `groups_join`         | 30          | 3600s    | `POST /groups/{id}/join`              |
| `messages_send`       | 120         | 60s      | `POST /messages/sealed`               |
| `messages_group_send` | 60          | 60s      | `POST /messages/group-sealed`         |

Business-feature endpoints carry their own limits, not listed
here.

## 13. Security Model

### 13.1 Threat model

**What the protocol defends against:**

- **Passive eavesdropping at the transport layer.** TLS to the
  edge plus the optional `sing-box` tunnel. A passive observer
  on the user's local network or any AS in the path sees only
  encrypted bytes.
- **Passive eavesdropping at the backend.** The server stores
  ciphertext only for message bodies, media blobs, and group
  fanout. Backend operators with full DB access cannot read
  message contents.
- **Active MITM on the cryptographic handshake.** libsignal's
  X3DH/PQXDH binds session keys to long-term identity keys
  signed at upload time. A network attacker swapping prekeys
  in flight cannot complete a session against a known identity
  without forging the IdentityKey signature.
- **Server compromise of E2EE confidentiality.** A compromised
  backend can drop, delay, or reorder messages, and can hand
  attackers the metadata listed in Section 6.1, but cannot
  produce plaintext.
- **Push provider (APNs) compromise of message content.** The
  push payload carries `env` only — a sealed envelope. An
  attacker with full APNs visibility (Apple or a hypothetical
  TLS-breaking middlebox) sees only the recipient device's
  APNs token and the opaque bytes, not the sender, not the
  body. The NSE decrypts client-side.
- **Active impersonation under the v=1 envelope.** The Ed25519
  signature inside the v=1 sealed envelope is verified against
  the server's published `signing_key`. A server that swaps a
  user's `signing_key` between rotation events is detectable
  (the iOS client caches the key on first contact and warns on
  silent changes). **TODO: confirm whether the iOS client
  surfaces a key-change warning today, or only logs it.**
- **Quantum-future decryption of recorded traffic.** PQXDH
  binds a Kyber KEM into the X3DH handshake. A future
  cryptanalytically-relevant quantum computer cannot derive
  v=2 session keys from recorded handshakes.

**What the protocol does NOT defend against:**

- **Endpoint compromise.** A device with malware, a forensic
  unlock, or a coerced unlock reveals everything — private
  keys, ratchet state, message history. RCQ has no
  per-message-thread passcode or panic-PIN today (the
  panic-PIN work is roadmapped, not shipped).
- **Traffic analysis by the relay operator (when relay path
  is engaged).** A malicious relay sees the timing and size
  of bytes going to `api.rcq.app`. It cannot read the inner
  TLS, but it knows you are using RCQ and roughly when. The
  multi-protocol multi-cloud pool limits trust to any one
  operator.
- **Metadata visible to the backend.** The server learns:
  recipient UIN, envelope timestamps and sizes, group
  membership, contact graph (for contact-request flow), push
  token registrations, IP for anonymous endpoints. A backend
  compromise yields the social graph and timing — not message
  content. The sealed-sender path means the server cannot
  trivially answer "who sent message X to user Y" but can
  often infer it from the timing of the previous outbound
  request on the WS connection that fed the matching POST.
- **Compromise of the JWT secret.** With `JWT_SECRET` an
  attacker can forge tokens for any UIN and use the REST API
  as that user. The damage is bounded by the E2EE layer:
  they can read queued ciphertext addressed to the user but
  cannot decrypt it without device keys. Recovery is a
  secret rotation + forced re-auth.
- **Compromise of the relay-config signing key.** With the
  Ed25519 private key for the relay config, an attacker can
  push a malicious relay list. Clients would then route
  through attacker-controlled relays. The inner E2EE still
  holds, but traffic-analysis power is much greater than for
  a generic relay operator (full visibility over time across
  the user base).
- **Apple-account-level adversaries.** A device under an
  Apple-account coercion can be remotely paired to an
  attacker's iCloud, then unlocked. RCQ stores its keys in
  the device-local keychain (NOT iCloud Keychain) to limit
  this exposure.
- **Pre-key exhaustion as a downgrade gadget.** If a target's
  OPK pool is exhausted, X3DH proceeds without a per-session
  contributory prekey. This is a defined libsignal mode and
  is not a downgrade attack in the cryptographic sense.

### 13.2 Known hazards and design notes

- **NSE dual-decrypt avoidance.** When a push lands, the NSE
  and the main app race to decrypt the same envelope. Double-
  decrypt would advance the Double Ratchet twice and desync the
  session. The iOS client maintains a `PushDecryptCache` keyed
  by message UUID so the second consumer (whichever comes
  second) sees a cache hit and skips ratchet advance. **The
  v=2 ratchet advance happens at most once per envelope; the
  exact location (NSE vs. main app) depends on which path
  picked up the envelope first.**
- **Sealed-sender constraint on server-side filtering.** The
  server cannot apply per-sender filters to v=1/v=2 message
  envelopes because it does not know who sent them. Block
  lists, removed contacts, and per-sender mutes are all
  enforced client-side after decryption. This is a deliberate
  privacy trade-off; the cost is that spam-suppression must
  rely on per-recipient delivery tokens (not yet
  implemented; see TODO at `messages.py:81`) and on
  client-side filtering.
- **`read_receipts_visibility` is client-enforced.** The
  server stores the setting and echoes it to the owner but
  does not gate any endpoint based on it. The read-receipt
  envelope is a sealed-sender message like any other, and the
  server cannot tell that it IS a read receipt (the
  `envelope_type: "read"` discriminator is just a routing
  hint). The iOS client suppresses the send based on the
  owner's setting.
- **`call_policy` is client-enforced.** Same shape: the
  server stores it, peers can read it via `PublicUser` (it's
  one of the always-published fields, not owner-only echoed),
  and clients hide their Call buttons accordingly. There is
  no server-side rejection of `call_offer` based on the
  callee's policy. **TODO: confirm whether a server check is
  intended.**
- **OPK consumption race.** `GET /keys/{uin}/bundle` uses
  SELECT-then-UPDATE without row locking. Two simultaneous
  fetches on the same UIN in the same event-loop tick
  serialize correctly; under multi-worker uvicorn, two
  fetches on different workers could theoretically return the
  same OPK twice. The recipient detects double-spend of an
  OPK as a libsignal session-init failure and re-handshakes.
- **Pinned-text plaintext exception.** Documented in Section
  6.4.7. The server holds group `pinned_text` in cleartext.
  Implementations MUST NOT use this column for user message
  content.
- **No forward secrecy on the v=1 base layer.** The v=1
  envelope uses ECIES with the long-term `identity_key`. A
  per-message ephemeral is part of the ECIES handshake, so
  per-message confidentiality holds, but a future compromise
  of the long-term `identity_key` allows decryption of
  recorded v=1 traffic. v=2 (libsignal) has full forward
  secrecy and post-compromise security via the Double
  Ratchet. Clients SHOULD prefer v=2 whenever the peer
  publishes a libsignal bundle.

## 14. Out of Scope (Non-Messaging APIs)

These routers ride on the auth + identity layer described
above but their endpoints are not part of the messaging
protocol:

- `/audio_rooms` — multi-party voice rooms (mesh WebRTC,
  signalling through the WS channel)
- `/random` — anonymous random-chat pairing
- `/stories` — story feed
- `/nearby` — opt-in geohash check-in for the "people nearby"
  surface
- `/hood/banners` — paid district-banner placements (IAP
  receipt validation; see Section 14.1)
- `/uin/quote` + `/uin/purchase` — UIN shop (any free 3-9 digit
  UIN, IAP-priced by length; the purchase endpoint reuses the
  account-migration helper from Section 10)
- `/reports` — moderation queue, including the bug-bounty
  context tag (`context = "bug_bounty"`); no monetary reward
  is associated with the submission
- `/news`, `/polls`, `/polls/group` — admin-posted feed,
  global polls, per-group polls
- `/referrals` — invite-tracking only; no reward attached
- `/admin` — admin panel (HTTP Basic, separate auth from the
  user JWT)

Each uses the JWT bearer from Section 2 and the WS channel
from Section 7 but has its own dedicated payload contracts.

### 14.1 Pivot 2026-05-27

The 2026-05-27 pivot removed the gamification + economy
layer that had been bolted on during closed beta. The
following routers no longer exist on the production
backend and the matching iOS surfaces are gone from the
client: `/marketplace`, `/uin_auctions`, `/items`,
`/trades`, `/crash`, `/hilo`, `/limbo`, `/pets_hunt`,
`/reputation`, `/jeton_reactions`, `/daily_qa`, `/premium`,
`/hood` (the geohash-bucket chat). The standalone
hood-banner subsystem was retained as the IAP-priced
`/hood/banners` endpoint described above; everything else
in that list is permanently cut.

Paid traffic above the free tier on `/media/upload` was
also removed in the same pass — uploads are now flat-free
up to the per-file safety cap.

Two paid surfaces remain, both currently behind a mock
IAP-receipt shim that accepts any non-empty string as a
placeholder while StoreKit wiring lands:

- **UIN shop** — `POST /uin/quote` returns price + availability
  for a target UIN; `POST /uin/purchase` validates the
  receipt, confirms the UIN is still free, and atomically
  migrates the caller's account onto the new UIN using the
  helper defined in Section 10.
- **Hood banners** — `POST /hood/banners` inserts a banner
  into a geohash-level-6 bucket with a TTL (`1h` / `6h` /
  `24h` / `7d`). Pricing tiers exposed via
  `GET /hood/banners/pricing`. Bucket capacity capped at
  24 active banners; per-UIN create rate limited.

Real StoreKit verification will replace the mock-receipt
gate; the JSON payload field is named `receipt` for
forward compatibility.

## 15. Spec Maintenance

### 15.1 Change process

Changes to this spec land via pull request against
`github.com/rcq-messenger/rcq-spec`. Substantive protocol
changes (new envelope type, new endpoint, breaking change to
an existing endpoint) require:

1. An RFC-style issue describing the change, the motivation,
   and the compatibility story.
2. A PR against this document.
3. A reference implementation in the iOS client and backend
   before the spec change merges.

Editorial fixes (typos, clarifications, missing fields the
implementation already does) may go straight to PR.

### 15.2 Versioning

This document is **v1.3**. The protocol wire major is still v1;
the `.x` suffix tracks doc revisions. Wire-breaking changes would
bump the major. Additive endpoints, new optional fields, and new
envelope types do not require a major bump; they are recorded in
the change log below.

### 15.3 Version history

| Version | Date       | Notes                                       |
|---------|------------|---------------------------------------------|
| v1      | 2026-05-26 | Initial public spec, covering the messaging core as deployed in TestFlight build 54. |
| v1.1    | 2026-05-27 | Pivot pass. Section 14 trimmed: cut routers documented as removed; UIN shop + IAP-priced hood banners documented as the only paid surfaces (mock receipt). No wire-breaking changes to the messaging core. |
| v1.2    | 2026-06-04 | Documented two shipped additive features. New §2.7 Account recovery (opt-in BIP39 seed phrase, `POST /auth/recover/challenge` + `POST /auth/recover` Ed25519 challenge/response; 48-word legacy raw-key export) — corrects the earlier "recovery is not possible" framing. New §5.6 Multi-device (secondary devices: `POST /keys/devices`, `GET /keys/{uin}/devices`, `GET /keys/{uin}/devices/{device_id}/bundle`, per-device OPK pools, `device_id` + `sealed_sender_pub` bundle fields, sender fan-out). No wire-breaking changes. |
| v1.3    | 2026-06-11 | Economy scrub: removed all remaining inline references to the gamification/economy layer that the 2026-05-27 pivot cut but earlier passes had left dangling in the live sections — jeton media pricing (uploads are now flat-free to the 2 GB safety cap, §9.1/§9.2/§9.5), premium media unlock (§9.7 deleted), paid groups (§6.4 join/invite + the related 402/`paid_group_*` error codes), the `equipped_pet`/`trade_policy`/`reputation`/`reputation_visibility` profile fields + `trades_from_*` push prefs (§3), the jeton-reaction note (§7.4), `trade_received` push gating (§8.4), and the wallet/inventory/trades/marketplace/pets/reputation rows in the migration carryover table (§10.1). Migration is now free. §14.1 already documented the pivot; this aligns the rest of the spec with it. No wire-breaking changes. (Cross-island federation — home-island records, `uin@host`, room-host groups, multihoming — is specified separately in `docs/federation-protocol.md` and is not yet folded into this document.) |
