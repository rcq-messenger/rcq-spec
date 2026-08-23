# RCQ Protocol Specification (v1.9)

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
  Extension flow, and UnifiedPush for Android (no FCM).
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

Version: **v1.9**. Last updated: **2026-08-23**. Spec maintainer:
the RCQ team (issues / RFCs against `github.com/rcq-messenger/rcq-spec`).

⚠ **Known gaps.** The endpoint census below was taken on 2026-08-16 against
the live server's 149 paths and has NOT been retaken; for v1.8 only the paths
this revision touches were re-checked. Most of the ones absent here are absent
on purpose (everything under "Out of scope" above, plus federation, which lives
in `federation-protocol.md`). Of the eighteen IN-SCOPE endpoints that census
found undocumented, all but the six below were written up the same day:
multi-device (§2.9, §2.11), registration proof (§2.8), key rotation (§2.10),
capability negotiation (§2.12), server info (§2.13), outgoing contact requests
(§4.8), the sender-key group broadcast (§6.5) and moderator permissions (§6.6).

Those six, still undocumented and small: `/deposit-auth/issue`,
`/deposit-auth/params` (F3 deposit authorisation, together with the optional
`deposit_token` field they mint for `POST /messages/sealed`; §13.2 says what
the mechanism is and that the reference island ships it switched off),
`/gate/check`, `/gate/redeem`, `/link/{token}`, `/health`.
`/groups/{group_id}/polls` is polls, which section 14 puts out of scope, and it
is listed here only because its path lives under groups.

v1.8 closed one endpoint that shipped after that census
(`POST /keys/devices/{device_id}/revoke`, §5.6.3) and the field-level gaps a
path census does not count: `cls`, `ring`, `to_device_id` and `seq` on the
messaging path (§6.1.1, §6.2.1.1, §6.2.3, §6.3.1.3), sealed-payload padding
(§6.1.2), the device key slots with their revoke cooldown and prekey
replenish (§5.6.1 to §5.6.5), and the session denylist (§2.11.1).

Reproduce the list with `GET /openapi.json` and grep this file for each
path. Do that before claiming the spec is current.

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
    `JWT_TTL_SECONDS = 60 * 60 * 24 * 30` (30 days) for an install
    token, 90 days for a linked-device token (§2.11).
  - `dev`: optional string, the install id this session names (§2.9).
    Absent reads as the literal `"primary"` everywhere the island
    keys on it: the drain cursor (§6.3.1.2), the websocket
    registration (§7.1) and the revoke denylist (§2.11.1).
  - `k`: `"phone"` on an install token, absent on a linked-device
    token. It is the only thing separating the two, since both carry
    `dev`.
  - `ep`: optional int, the UIN epoch the token was minted under.
    A number that has changed hands has a higher epoch, which is what
    retires a previous holder's saved bearer (§10.1.3).
- Signed with `JWT_SECRET` (deployment-specific). Tokens are
  rejected on bad signature, missing `sub`, unparseable `sub`, a
  stale `ep`, or a denylisted `dev` (§2.11.1).
- ⚠ `exp` is enforced for a linked-device token only (`dev` present,
  `k` absent). An install token outlives its own `exp`: a messenger
  that logs a phone out for being offline past the TTL stranded every
  long-idle user on `401`, and iOS builds up to 2026-07 answered that
  `401` by silently registering a fresh UIN. An implementation that
  enforces `exp` uniformly rediscovers that.

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

A client that already knows its own UIN should ask §2.14
`POST /auth/refresh` instead: same proof, but bound to the account it
means, so a shared signing key cannot land the session somewhere else.

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

### 2.8 `POST /auth/register/challenge` (registration proof)

Registration mints an identity from public keys the caller supplies. On
its own that lets anyone claim a signing key they do not hold, so the
flow is two-step: ask for a nonce, sign it, register with the signature.

```
POST /auth/register/challenge
  { "signing_key": "<base64 Ed25519 public>" }
→ { "challenge": "<opaque short-lived nonce>" }
```

The nonce is stateless and deliberately says NOTHING about whether that
key or any account already exists, so it cannot be used to probe for
either. `POST /auth/register` then takes the challenge plus an Ed25519
signature over it and refuses if the signature does not verify.

Rate limit: 60 per hour per caller.

### 2.9 `POST /auth/device` (name the install)

A token issued before multi-device carries no `dev` claim, and every such
client keys as "primary". Two installs on one UIN therefore knock each
other's websockets over in a loop and share ONE offline-queue cursor, so
whichever drains first leaves the other with nothing.

This cannot be repaired server-side, because only the client knows which
install it is. So: call this once after updating and keep the token you
get back. The current queue cursor is copied onto the new device id — a
new id starting at zero would be handed the entire backlog again, which
is harmless (clients dedupe by envelope id) but is a pointless
re-download of everything the person already has.

```
POST /auth/device   (bearer: the old token)
  { "device_id": "<client-chosen stable id>", "label": "<optional>" }
→ { "uin": <int>, "token": "<jwt with a dev claim>" }
```

### 2.10 `POST /auth/reissue` (rotate identity keys in place)

Replaces the account's `identity_key` and `signing_key` without changing
the UIN, and returns a fresh token. The contact graph, groups and queue
are untouched; peers re-pin on next contact.

⚠ Existing libsignal sessions do not survive a key rotation — peers
re-handshake. This is not the same operation as §10 migration, which
changes the number and keeps the keys.

### 2.11 Linked devices

```
POST   /devices/link                       issue a linking payload for a second install
GET    /devices                            list this account's devices
DELETE /devices/me                         revoke the device the caller is using
DELETE /devices/{id}                       revoke another device of this account
POST   /keys/devices/{device_id}/prekeys   replenish that device's one-time prekey pool
```

⚠ Each device keeps its OWN one-time prekey pool (§5). They are scoped so
a phone re-bootstrapping its keys cannot drain or wipe a second device's
pool — the two are independent, and a shared pool would mean whichever
device published last silently broke sessions for the other.

Revocation is announced to the account's other devices over the socket,
so a revoked install is dropped live rather than at its next request.

#### 2.11.1 What a session revoke stops

`DELETE /devices/{id}` and `DELETE /devices/me` put the install's `device_id`
on a per-account denylist. A key-slot revoke (§5.6.3) does not touch this
denylist, and this does not touch key slots: they are two separate operations
on the same install.

The denylist is consulted in both directions, and this is the part a third
implementation has to get right.

- **A token already held.** Every authenticated HTTP request and the websocket
  handshake resolve the token's `dev` claim against the denylist and answer
  `401 "device revoked"`. The live socket is closed at the moment of the
  revoke as well, because the handshake check alone left an idle browser tab
  receiving messages, presence and call signalling for hours on the socket it
  already had.
- **A token freshly minted.** `POST /auth/device`, `POST /auth/recover` and
  `POST /auth/refresh` all refuse a revoked `device_id` with
  `401 {"detail": {"code": "device_revoked"}}`. Checking a token on the way in
  is not the same as refusing to make a new one: the web client keeps no token
  on disk and mints one at start-up from its signing key (§2.14), so a mint
  endpoint that skipped this handed the disconnected browser a brand-new valid
  session and the revoke did not survive a page reload.

Proving the signing key says who is asking, never from where. The denylist is
the only thing between a disconnected install and a fresh session for the same
account, so it fails closed: if it cannot be read, the mint is refused rather
than allowed.

The denylist entry lives 90 days (`DEVICE_TTL_SECONDS`, a compiled-in constant
on the reference server, and the same clock the linked-device registry and the
linked-device token of §2.5 run on). The whole per-account set shares one
expiry, so each further revoke on the account refreshes it for every id already
in it.

⚠ **The entry expiring is the end of the revoke, not the end of the install.**
A revoke erases nothing the install holds. Any install still holding the
account's `signing_key` mints a fresh session by proving it (§2.14), and once
the entry has aged out that mint succeeds under the same `device_id` as before.
This is the other half of the sentence above: the denylist is the only thing
between a disconnected install and a fresh session, and it is a 90-day thing.
An owner who wants a device out permanently has to rotate what it holds
(§2.10), which is what actually invalidates its proof, rather than relying on
the revoke alone.

⚠ **A revoke does not stop push.** Neither call removes the install's rows in
`device_tokens` (§3.5), so wakes carrying `env`, the sealed envelope of a new
message, keep going to it until it deletes its own registration or APNs reports
the token dead (§8.6). Combined with the paragraph in §5.6.3 about the install
keeping what it already decrypted, this means a revoke stops the account's API
and socket surface, not delivery to a device that is still holding keys. An
operator or a client that needs delivery stopped has to call
`DELETE /users/me/push-token` from that install, which a disconnected install
has no reason to do.

⚠ A revoke can only ever be as good as the id it names. A linked session must
keep presenting the `device_id` it was issued: an install that re-mints under
an id of its own choosing appears in no registry, and the owner's "disconnect"
button becomes a control that changes nothing. That is why a linked session may
not rename itself through `POST /auth/device`
(`409 {"detail": {"code": "linked_device_cannot_rename"}}`), while a native
install may.

### 2.12 `POST /users/me/capabilities`

How a client tells the island what it can parse. Idempotent, so clients
fire it on every start without tracking whether they already did.

```
POST /users/me/capabilities
  { "sender_keys": true }
→ 204
```

★ This is not decoration: `sender_keys` is what §6.5 group broadcast
routes on. A member whose client has not advertised it is deliberately
skipped by the broadcast and covered by the legacy per-member fan-out
instead, because they cannot parse a `gmsg` and would simply see nothing.

### 2.13 `GET /server/info`

What this island is and what it has switched on — read before the client
offers a feature that an operator may have disabled. Self-hosted islands
answer with their own values.

Capabilities are additive, and a client reads the keys it knows. The default for
an absent key is per key, not one blanket rule, and the first-party clients
agree on it:

| Absent key | Reads as | Why |
|------------|----------|-----|
| `random_chat`, `reports`, `nearby` (historical), `registration_policy` | permissive (`true` / `"open"`) | An island that predates the flag still runs the feature. Hiding it would remove a surface that works. |
| `uin_shop`, `hall_of_fame`, `deposit_auth` | `false` | These are surfaces that exist on the flagship and on nothing else. Offering them on an island that never heard of them renders a shop and a wall of fame with no endpoints behind them. |
| `envelope_class` | `false` | §6.2.4 says what it promises and why its default has to run this way. |
| `anon_keys`, `group_log`, `vault` (with `vault_max_blob_bytes`, `vault_max_slots`) | `false` | Each says the island runs a stage of the core-metadata plan (anonymous key lookups; one log per room, `/messages/group-log/*`; the vault of §4.9). An island that has not said so is asked the old way, never the new one: a wrong guess there is a silenced room or an unreadable list, not a 404. |

⚠ On iOS `uin_shop` is a hard decode: an answer without the key fails the whole
capability decode and the client keeps the set it already had, rather than
falling back to a default. A third implementation should treat the key as
required in practice and always send it.

### 2.14 `POST /auth/refresh` (a token without storing one)

Same proof as recovery (§2.7), but the caller names the UIN it wants and
gets a token only if that account actually carries the key.

```
POST /auth/recover/challenge     { "signing_key": "<base64 Ed25519 pub>" }
→ { "challenge": "..." }

POST /auth/refresh
  {
    "uin":         <int>,
    "signing_key": "<base64 Ed25519 pub>",
    "challenge":   "<from the challenge step>",
    "signature":   "<base64 Ed25519 signature over the challenge string>",
    "device_id":   "<optional: the install asking>"
  }
→ { "uin": <int>, "token": "<JWT>" }
```

Errors: `400 invalid_challenge`, `401 bad_signature`,
`404 identity_not_found`. Rate limit: 60 per hour per caller.

**Why it is not §2.7.** `/auth/recover` resolves a signing key to the
OLDEST account carrying it — the right rule for "I lost my device, take me
home", and the wrong one for a client that already knows which account it
is: a key shared by more than one account (which happens, since
registration accepted unproven keys for a long time) would send the
session to somebody else's UIN. Naming the UIN removes the ambiguity and
gives nothing away — possession of the private key is still the only thing
that mints a token.

**What it is for.** A client that can mint a token on demand does not need
to keep one. The web client stores no session token between visits
(`docs/web-storage-inventory.md`): a 30-day bearer sitting beside the keys
that can produce it is one more thing to lose and buys its owner nothing.
It also ends a session at the token's expiry instead of the account's —
before this, a browser simply fell out of its account after 30 days.

⚠ Not an end-run around revocation. A revoked install's `device_id` stays
denylisted, so the token this returns is refused exactly as the old one
was, and the client signs itself out.

If `device_id` names an install with no queue cursor, one is created at the
account watermark — never at zero, or the next drain replays the entire
queue as notifications (the 2026-08-13 drain-floor bug).

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
{ "token": "<APNs device token | UnifiedPush endpoint URL>",
  "platform": "ios" | "ios-voip" | "android-up",
  "device_id": "<stable per-install id>"   // optional
}
```

Idempotent on `(uin, token)` via Postgres `INSERT ... ON
CONFLICT DO UPDATE`; bumps `last_seen` and clears any recorded push
failure on conflict. `204 No Content`.

For `platform: "android-up"` the `token` is the whole address: the
HTTPS endpoint URL the device's UnifiedPush distributor handed out
(see §8.7). There is no provider key anywhere on the server.

`DELETE /users/me/push-token`: same body shape; removes the
matching row if present (no error if absent).

`GET /users/me/push-health`:

```json
{ "devices": [
  { "platform":      "android-up",
    "host":          "ntfy.sh",          // host only, never the full endpoint
    "last_error":    "507",              // null once a wake gets through
    "last_ok":       "<ISO-8601 | null>",
    "registered_at": "<ISO-8601>" }
] }
```

What the server's last wake attempt to each registered device did.
Android push depends on a third-party distributor the user chose, and
when that distributor stops accepting wakes the user's experience is
"notifications stopped" with nothing to look at; this is the surface a
client uses to say so. The endpoint path is never echoed back — for a
UnifiedPush topic the path IS the wake secret.

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

### 4.8 `GET /contacts/outgoing` (requests you sent)

Section 4.4 covers the requests waiting for YOU. This is the other half:
the ones you sent and nobody has answered. Without it a client can only
show a request from the receiving side, which is why "did that even go
out?" had no answer in the UI.

```
GET    /contacts/outgoing              → [ { to_uin, nickname, created_at } ]
DELETE /contacts/outgoing/{to_uin}     withdraw a request you sent
```

Withdrawing removes the pending row on both sides; it is not a block and
leaves no trace for the other person beyond the request disappearing.

### 4.9 The vault: `PUT|GET|DELETE /vault/{slot}`

Stage 4 of the core-metadata plan takes the contact list off the island. What
survives a reinstall, and what the account's own devices converge on, is the
vault: a small set of opaque slots per account that hold ciphertext the client
sealed and a version the island counts. The island holds no key and no schema
for the contents; it cannot tell a contact list from a room key.

```
GET    /vault                                                 -> 200 {"slots": [{"slot": "<hex>", "version": <int>}, ...]}
PUT    /vault/{slot}  {"blob": "<base64>", "version": <int>}  -> 200 {"version": <int>}
GET    /vault/{slot}                                          -> 200 {"blob": "<base64>", "version": <int>}
                                                              -> 404 {"detail": {"code": "no_slot", "version": <int>}}
DELETE /vault/{slot}?version=<int>                            -> 204
```

`slot` is 32 lower-case hex characters chosen by the client (anything else is
422). `blob` is base64 of at most `vault_max_blob_bytes` decoded (256 KB on the
flagship; 413 above that, 400 when it is empty or not base64). An account may
hold `vault_max_slots` live slots (32; 400 `slot_limit` on the next; an existing
slot can always be rewritten). Both caps are in §2.13. `GET /vault` lists the
live slots and their versions, no blobs.

**The version rule.** A write names the version it was based on: the one the
client read, or 0 only when the island answered that the slot has never
existed. The island stores the blob as that version plus one, or refuses with
`409 {"detail": {"code": "stale", "version": <current>}}` and stores nothing.
There is no path by which a write lands on top of a version its author never
saw: the refused client re-reads, merges on its own terms and retries. The
island never compares contents and never merges.

**A version is never reused.** A delete names the version it is based on
(`version` is required; stale is 409) and leaves a tombstone: the slot reads
404 with the tombstone's version in the body, and the next write must name
that version, not 0. Without this a slot deleted and re-created would count
1, 2, 3 again, and a device that remembered "version 3" from before the delete
would take the new version 3 for "nothing changed". Deleting what is already
gone is 204 whatever version it names, so a retried delete cannot fail. A
never-written slot reads 404 with version 0.

The rule is the lesson of report #605 (2026-08-17), where two devices each
published their own half of an account-level list and each silently
un-published the other's, because the island refused only a write with an
OLDER timestamp and a write carried no notion of what it was based on.

**Sync between the account's devices.** Every accepted write and every delete
sends `{"type": "vault_changed", "slot": "<hex>", "version": <int>}` to every
session of the account (§7.4.4), carrying the new version (on a delete, the
tombstone's). The writer sees its own nudge and ignores it by version; the
other devices re-read the slot. ⚠ The nudge is pub/sub to live sockets, with
no queue and no replay: a device whose socket was down at that moment never
hears it. A client therefore re-reads the slots it uses on every socket
(re)connect, not only at boot, and `GET /vault` makes that one small request.
Writes are per merged state, never per entry: importing three hundred
contacts is one write.

**Derivation (first-party clients).** Slot name and key come from the
account's long-term X25519 identity private key, not from the recovery seed:
a browser linked from a phone, a legacy raw-key account and anyone who asked
the client to forget the phrase have no seed, while every device of an account
holds `identity_priv` (the link blob of §2.11 carries it, and for a seed
account it is itself `HKDF(seed)`, §2.7). Same HKDF-SHA256 shape as §2.7, 32
zero bytes of salt:

```
slot = hex( HKDF(identity_priv, zeros32, "rcq.vault.slot.v1|" + name, 16) )
key  =      HKDF(identity_priv, zeros32, "rcq.vault.key.v1|"  + slot, 32)
blob = 0x01 || nonce(12) || ChaCha20-Poly1305(key, nonce, padded,
                                 aad = "rcq.vault.v1|" + slot + "|" + version)
```

`name` is a client-side label (`"contacts"` for the contact list); the island
sees only the derived hex. `padded` is a 4-byte big-endian length, the
plaintext, and zero fill to the next 512-byte boundary, so the island learns a
size class rather than a size. The version in the AAD means the island cannot
relabel one version as another; it can still serve an older consistent
(blob, version) pair, which a client detects by refusing any version lower
than the last one it saw for the slot.

⚠ `POST /auth/reissue` (§2.10) rotates `identity_priv` and with it every slot
name and key. The island empties the account's vault in the same transaction
(every slot would be unreachable under the new derivation, and ciphertext
under a key the user just retired has no business staying). The client that
rotates reads its slots before the call and writes them back, under the new
derivation, after it.

**What the island learns.** That an account holds N slots of these size
classes and when they change. Nothing about the contents; slot names are
client-derived noise rather than labels. Slots live exactly as long as the
account: they follow it through §10.1 and go with it in §10.2.

**What the logs hold.** A slot name is a stable per-account pseudonym, so the
access logs mask `/vault/<hex>` the way they mask `/users/<uin>` (§12).

**Rate limits.** Per account and hour: `vault_list` 600, `vault_get` 1200,
`vault_put` 240, `vault_delete` 60 (429 with `Retry-After`), plus a 64 MB/day
byte budget on writes. Capability `vault` in §2.13, absent reads as `false`.

**Status.** Island side live since `2026.08.23.8`. What the clients keep in
the `contacts` slot, and the staged retirement of §4.1 and §4.2 (the vault
ships first and empty; clients mirror the server list into it; the server list
goes read-only; it drops) is the rest of stage 4 and is documented as each
step ships.

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
  "has_bundle":                <bool>,
  "one_time_prekey_count":     <int>,
  "target_count":              100,
  "signed_prekey_age_seconds": <int|null>,
  "signal_identity_key":       "<base64>|null"
}
```

`signal_identity_key` is the libsignal identity currently published in the
account's **primary** slot (device 1). Additive: an island that predates the
field omits it and a client reads null.

A starting install reads `has_bundle` and `signal_identity_key` TOGETHER before
it publishes anything. Four answers, and they are not three:

| `has_bundle` | `signal_identity_key` | What it means | What the install does |
|--------------|-----------------------|---------------|-----------------------|
| `false`      | null                  | Nobody holds the slot. | Publish (§5.1). |
| `true`       | equal to its own      | The slot is already this install's. | Nothing. It is device 1. |
| `true`       | some other key        | Another install of the account owns the slot. | Claim a secondary slot (§5.6.1). |
| `true`       | absent                | The island predates the field. | Leave the slot alone. |

⚠ **The last row is the one to get right.** A null `signal_identity_key` has
two causes and they call for opposite actions: the account has no libsignal
material at all, or the island is too old to report what is in the slot.
`has_bundle` is what separates them, and it predates the field. Reading null as
"free" on an old island makes the second install of the account call
`POST /keys/bundle`, which replaces whatever is there (§5.1). Peers then build
sessions against whichever install wrote last and the other one's messages stop
opening, which is exactly the 1:1 delivery break this field was added to
prevent.

An old island also has no device registry to claim a secondary slot in
(`POST /keys/devices` answers `404` there, §5.6.1), so an install that finds
that row keeps the material it already has and reaches new peers over v=1,
which every install of the account can open.

The field is the caller's own public key, so it discloses nothing they cannot
already read out of their own bundle.

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

⚠ All of the above is the PRIMARY slot. A secondary slot (§5.6) has no
rotation endpoint at all: `POST /keys/devices/{device_id}/prekeys` refills its
one-time pool and nothing updates its signed prekey, its Kyber prekey or its
identity, since `POST /keys/bundle` writes the primary slot and
`POST /keys/devices` mints a NEW slot rather than updating the named one
(§5.6.1). A secondary therefore keeps the signed prekey it registered with for
the life of the slot. Retiring the slot and claiming another is the only way to
replace that material, and it costs a slot number out of the 2..127 range
permanently (§5.6.3).

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

A slot is claimed, listed and retired through §5.6.1 to §5.6.3. The two
remaining endpoints are the per-device prekey replenish (§5.6.5) and the
per-device bundle fetch:

`GET /keys/{uin}/devices/{device_id}/bundle` — the prekey bundle for
one device. `device_id = 1` delegates to the legacy
`GET /keys/{uin}/bundle`; `>= 2` consumes that device's own OPK
pool. Bundles carry two additive fields: `device_id` and
`sealed_sender_pub` (old clients ignore both).

A v=2 message is encrypted to exactly ONE libsignal session, so
reaching a UIN on all its devices requires the **sender** to fan
out (one ciphertext per device). Delivery is device-aware since the
fan-out shipped. The sender labels each copy with `to_device_id`
(§6.2.3) and the offline queue hands each device only the copies
addressed to it plus the unaddressed ones (§6.3.1). The WS still fans
out to every socket of a UIN (Section 7.2) and carries the label in the
frame, so a device drops a copy that is not its own without trying to
decrypt it. Both halves are additive: a sender that omits the label, or
an island that does not store it, falls back to the original "every
device gets every copy" behaviour.

A staged rollout is inherent: a recipient is reachable on a new
device only once senders are device-aware (old senders still reach
device 1). This is the same dependency Signal's multi-device has.

#### 5.6.1 Claiming a slot: `POST /keys/devices`

Authenticated. Registers the calling install as a secondary device of the
caller's own account. The body is the §5.1 bundle plus two fields:

| Field               | Type          | Meaning |
|---------------------|---------------|---------|
| `sealed_sender_pub` | string, req.  | base64 X25519 public key. Senders encrypt the OUTER sealed-sender envelope for this device to it. The primary device's outer key is the UIN `identity_key` from `/users/{uin}/info`; a secondary holds only its own keys and never the account master key. |
| `label`             | string / null | free text the owner types. ⚠ Served to ANY authenticated caller through §5.6.2, not only to the owner: a string like `"Web (Chrome)"` is a browser and OS fingerprint the account's contacts can read. Not identity, and not private either. |

```
POST /keys/devices
  { ...§5.1 bundle..., "sealed_sender_pub": "<base64>", "label": "Web (Chrome)" }
→ 201 { "device_id": <int> }
```

The server assigns the id as `max(device_id) + 1` over every row of the
account, starting at 2. Clients never assert an id of their own: two installs
registering at the same moment would collide on one, and a collision puts two
ratchets under one address, which is the failure the whole slot mechanism
exists to prevent.

⚠ Not idempotent. Every call mints a new slot. Persist the returned
`device_id` before anything else in the bootstrap can fail. An id the server
handed out and the client did not write down is a row nobody ever drains, plus
a second registration on the next launch.

Errors: `404` when the UIN does not exist, `409 "device limit reached"` once
slot 127 is taken (libsignal caps `deviceId` at 127).

An island older than this route also answers `404`. A client that gets `404`
here and finds a different identity in the primary slot (§5.4) leaves that slot
alone and stays where it is: its existing sessions keep working, and new peers
reach it over v=1, which every install of the account can open.

#### 5.6.2 The device list: `GET /keys/{uin}/devices`

Authenticated. Every device of `uin` a sender should fan out to.

```json
{
  "uin": 100200300,
  "devices": [
    { "device_id": 1, "label": "primary",      "signal_identity_key": "<base64>" },
    { "device_id": 3, "label": "Web (Chrome)", "signal_identity_key": "<base64>" }
  ]
}
```

| Field                 | Meaning |
|-----------------------|---------|
| `device_id`           | libsignal deviceId. 1 is the primary, 2..127 are secondaries. |
| `label`               | the literal string `primary` for device 1, otherwise the label that device registered with, or null. Not identity: it is free text the owner typed. |
| `signal_identity_key` | the libsignal identity that device publishes right now. Additive, null on an older island. |

Device 1 appears only when the account has a published libsignal bundle.
Revoked slots do not appear at all. Rows are ordered by `device_id` ascending.

★ `signal_identity_key` is here so a sender can ask "is the install I share a
ratchet with still the one behind this slot?" without reading a bundle. A
bundle read consumes one of that account's one-time prekeys (§5.3), and a probe
that re-reads a bundle on a timer to answer a question whose answer is almost
always "unchanged" drains a pool that only refills while its owner's client is
online. An emptied pool costs every later X3DH with that account its one-time
contributory secret, so the probe would erode the exact property it exists to
protect. Compare this field; fetch the bundle only when it differs from the
identity the existing session was built on.

`404` here means either that the UIN does not exist or that the island predates
the route. Both read as "no device registry": send one unaddressed copy, as
before slots existed. A timeout or a dead relay is **not** a `404` and must not
be cached as an empty list, or the peer is held on the single-copy path while
one of their installs hears nothing.

#### 5.6.3 Retiring a slot: `POST /keys/devices/{device_id}/revoke`

Authenticated, acts on the caller's own account. `204 No Content`.

What a revoke does:

- the slot leaves `GET /keys/{uin}/devices`, so senders stop fanning out to it
  at their next roster fetch (client rosters are cached for minutes, so this is
  not instant);
- `GET /keys/{uin}/devices/{device_id}/bundle` answers `404`, so no new session
  can be established against it;
- that slot's one-time prekeys are deleted, and
  `POST /keys/devices/{device_id}/prekeys` answers `404`, so the install cannot
  refill them;
- every session of the account is told over the socket (`device_slot_revoked`,
  §7.4.6) and woken by push.

What a revoke does **not** do. It means "stop talking to it", not remote
erasure: the install keeps everything it already decrypted. Copies already
deposited in the offline queue against that slot (§6.3.1) are still handed out
to whoever drains with that `dev`. And it does not touch the install's session:
the token stays valid, and disconnecting a session is the separate call in
§2.11.

Slot 1 is refused with `400`:

```json
{ "detail": { "code": "primary_slot" } }
```

Slot 1 is the account's primary bundle on the user row, the thing every legacy
sender encrypts to. Replacing it is a fresh `POST /keys/bundle` upload (§5.1),
not a slot operation. It is not `POST /auth/reissue` (§2.10): that rotates the
account's base X25519 and Ed25519 pair and leaves the libsignal material where
it is. The two sets are independent, as §5.5 and §10.1.2 both record.

Errors: `400 primary_slot`, `404 "no such device"` (unknown, not yours, or
already revoked), `403 revoke_cooldown` (§5.6.4).

**Why the row outlives the revoke.** The slot number stays reserved. Allocation
counts revoked rows (§5.6.1), so recycling a number would hand it to a new
install while a sender's cached roster and any queued copy still point the old
one at it: ciphertext sealed to the retired install's keys, delivered to an
install that cannot open it, with no bubble and no error for anyone to report.
At the moment of revocation the row is reduced to the `(uin, device_id)` pair
plus `revoked_at`. The other columns are blanked in place rather than dropped:
the label goes to null, the keys to empty strings, the ids to zero. `created_at`
is NOT NULL and cannot go, so it is folded forward onto the revoke instant,
which stops the row recording how long the device lived. That lifespan is the
part that says something about the person; the pair is all the one remaining
reader (the id allocator of §5.6.1) needs. The reference server
releases the number itself after 180 days by default
(`RCQ_DEVICE_REVOKED_MAX_AGE_DAYS`), far past every cache and every queued
copy.

#### 5.6.4 The revoke cooldown

`POST /keys/devices/{device_id}/revoke` and `DELETE /devices/{id}` (§2.11) pass
through the same gate:

- a **native install** revokes anything, immediately. Whoever holds the account
  keys is the account, and no denylist changes that;
- a **linked session** revokes anything younger than itself, immediately. An
  owner kicking out an intruder must never wait;
- a **linked session** revokes something older than itself only once it has
  survived the cooldown: 24 hours by default, `RCQ_REVOKE_COOLDOWN_SECONDS` on
  the island;
- a **linked session** inside its cooldown revoking a target whose birth the
  island cannot read is refused, same as for an older target.

**How the island tells the two apart, and it is not the `dev` claim.** Every
install carries one, phones included (§2.9), so the claim proves nothing. The
discriminator is the linked-device registry: `POST /devices/link` is the only
writer, and it stamps the row with the `created_at` this gate reads. A caller
whose `dev` names a row in that registry is a linked session; a caller whose
`dev` is `"primary"`, is absent, or names nothing in the registry is a native
install and passes the gate untouched.

**Where the target's age comes from**, since the two revokes act on different
registries and the ids do not map onto each other (§6.3.1):

| Call | Target | Birth read from |
|------|--------|-----------------|
| `DELETE /devices/{id}` | an install id (string) | that row's `created_at` in the linked-device registry; nothing for an id not in it |
| `POST /keys/devices/{device_id}/revoke` | a key slot (int 2..127) | that slot's `created_at` in the device table (§5.6.1) |

So a young linked session comparing itself against a key slot is comparing two
timestamps from two different registries, which is exactly what the rule
intends: it asks whether the thing being removed predates the session removing
it, whatever kind of thing it is.

Until then, `403`:

```json
{ "detail": { "code": "revoke_cooldown", "wait_seconds": <int> } }
```

The threat is a stolen link. A session just attached to the account must not be
able to throw the owner out before the owner has had a chance to see it in the
device list and act. Blocking new sessions outright was considered and dropped:
when the phone is the thing that was lost, there is nobody left to approve one.

Read `wait_seconds` rather than assuming 24 hours. A self-hosted island sets
its own.

A session can always disconnect itself. `DELETE /devices/me` is not gated.

#### 5.6.5 Refilling a slot's pool: `POST /keys/devices/{device_id}/prekeys`

Authenticated, acts on the caller's own account. Same body as the primary
replenish of §5.2, and `204 No Content` on success:

```
POST /keys/devices/3/prekeys
  { "one_time_prekeys": [ { "id": 501, "public": "<base64>" }, ... ] }
→ 204
```

Idempotent on `prekey_id`: an id the slot already holds is skipped rather than
replaced, so a client that retries a lost request does not disturb a key a
sender may already have fetched.

`404 "no such device"` covers all three failures at once: the slot does not
exist, it belongs to another account, or it has been revoked. The island does
not distinguish them, and neither should a client: all three mean stop
refilling this slot.

The primary pool is NOT reachable here. `device_id = 1` is not a row in the
device table, so it answers `404`; the primary refills through §5.2. The two
pools are scoped apart on purpose (§5.6), and a client that confuses them
drains one while believing it filled the other.

## 6. Messaging Protocol

### 6.1 Envelope formats

The server is type-agnostic. From its perspective, an envelope is a
base64-encoded opaque blob plus a storage class (§6.1.1), a small
`envelope_type` discriminator and an addressing tuple: `to_uin` and an
optional `to_device_id` for 1:1, `group_id` plus a per-member `to_uin`
for groups. The server never parses the payload.

**Metadata visible to the server per envelope:**

| Field            | Visible to server | Notes |
|------------------|-------------------|-------|
| recipient UIN    | yes               | needed for routing |
| `envelope_type`  | yes               | ingest alias, kept forever (see below and §6.1.1) |
| `cls`            | yes               | 3-value storage class, what the island branches on (§6.1.1) |
| `received_at`    | yes               | server-stamped UTC                 |
| `group_id`       | yes (group only)  | for routing fanout                 |
| `to_device_id`   | yes, when sent    | which device of the recipient this copy is for (§6.2.3) |
| `seq`            | yes (1:1 only)    | server-allocated per-mailbox sequence (§6.3.1.3) |
| sender UIN       | NO (v=1 + v=2)    | inside the encrypted payload only  |
| payload bytes    | opaque            | ciphertext                         |
| size in bytes    | yes               | byte length of the base64 ciphertext, padded to a bucket by the sender (§6.1.2) |

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
| `secscreen`     | Secure-mode state for a thread                                  |
| `skdm`          | Sender-key chain distribution (§6.5)                            |
| `sknack`        | Sender-key recovery request (§6.5)                              |
| `call`          | Cross-island call signalling (`federation-protocol.md` §5d), and the legacy way to ask for a ringing wake (§6.2.1.1) |
| `gmsg`          | Sender-key group broadcast (§6.5)                               |
| `carbon`        | Copy of your own send, to your other devices                    |
| `homerec`       | Silent sync of a signed home-island record                      |
| `profile`       | Cross-island name/picture refresh (§5e)                         |
| `contactreq`    | Cross-island contact request (§5f)                              |

Queueing, push and the dormant sweep do not branch on this string. They branch
on the 3-value storage class the island derives from it (§6.1.1). A handful of
smaller rules do still read the string itself, and §6.1.1 lists them.

**v=1 sealed-sender envelope** (when the recipient has not
uploaded a libsignal bundle). Layout — opaque to the server,
defined by the client:

⚠ This layout was written down wrong until v1.8: it described a packed binary
struct sealed with AES-GCM, and no client has ever sent that. What the three
clients agree on, byte for byte, is JSON at both levels. Anyone who
implemented the old text could not open a single message.

```
v=1 envelope: base64( utf8( outer JSON ) )

  outer JSON:
    { "v": 1,
      "ek": base64(ephemeral X25519 public, 32 bytes),
      "ct": base64( nonce(12) || ChaCha20-Poly1305 ciphertext || tag(16) ) }

  key    = HKDF-SHA256(ikm  = X25519(ephemeral_priv, recipient.identity_key),
                       salt = ephemeral_pub || recipient.identity_key,
                       info = "RCQ-1to1-v1", 32 bytes)
  AEAD   = ChaCha20-Poly1305, nonce random 12 bytes, aad = ephemeral_pub

  inner plaintext (the sealed bytes):
    { "from":      <sender UIN, int>,
      "from_host": "<the sender's island host>",
      "spub":      base64(sender Ed25519 signing public, 32 bytes),
      "sig":       base64(Ed25519 over  ephemeral_pub || envelope_bytes ),
      "env":       base64(envelope_bytes),
      "_pad":      "<filler, optional; see 6.1.2>" }

  envelope_bytes = utf8 of the application envelope JSON (the message itself)
```

The nonce lives inside `ct` because CryptoKit's `combined` representation on
iOS is exactly `nonce || ciphertext || tag`, and the other two clients match
it rather than carry a separate field.

The recipient decodes the outer JSON, derives the same key from `ek` and its
own identity private key, opens `ct`, then verifies `sig` against `spub` over
`ek || env` and cross-checks `spub` against the sender's published
`signing_key` (`/users/{from}/info`, or `/federation/keys/{from}` on the
island named by `from_host`). Only then is `from` trusted. `sig` covers
`ek || env` and NOT the inner JSON, which is what lets `_pad` be added
without breaking any existing decoder. The server-side `from_uin` field of
the storage row is always null/unused for sealed sends.

**v=2 libsignal envelope** (when both ends have published a PQXDH bundle).

⚠ Also written down wrong until v1.8. RCQ does NOT put a libsignal
`SealedSenderMessageContent` on the wire. It wraps a plain libsignal message
in the SAME outer envelope v=1 uses, with its own HKDF info string, and does
its own sealed-sender inside:

```
v=2 envelope: base64( utf8( outer JSON ) )

  outer JSON:  { "v": 2, "ek": ..., "ct": ... }     exactly as v=1
  key:         HKDF-SHA256(..., info = "RCQ-1to1-v2")
  AEAD:        ChaCha20-Poly1305, same shape as v=1

  inner plaintext (the sealed bytes):
    { "from": <sender UIN, int>,
      "kind": "prekey" | "signal",
      "msg":  base64(the libsignal PreKeySignalMessage or SignalMessage body),
      "dev":  <sender device id, omitted when 1>,
      "_pad": "<filler, optional; see 6.1.2>" }
```

The outer key is the recipient DEVICE's `sealed_sender_pub` from its bundle
(§5.6.1). For device 1 that key IS the account's long-term X25519 identity key,
the same one v=1 seals to; for a secondary slot it is that device's own key,
since a secondary never holds the account master key. The libsignal ratchet
lives entirely inside `msg`. `kind` tells
the receiver which libsignal type `msg` holds, and `dev` names WHICH of the
sender's devices holds the other half of the ratchet, since a ratchet belongs
to one pair of devices (§5.6). An absent `dev` means device 1, which is what
every build in the field already assumed.

There is no signature here: libsignal authenticates the sender through the
session itself, so `from` is trusted only after `msg` opens against a session
whose identity matches.

The two envelope formats are distinguished by the `v` field of the outer JSON,
which the CLIENT reads; the server never parses either and simply ferries
bytes. A sender picks the format from whether `signal_identity_key` is present
on the recipient's `PublicUser`. Implementations MUST NOT assume the server
enforces a version.

#### 6.1.1 Storage class (`cls`)

Since server `2026.08.22.15` the island no longer branches on `envelope_type`
for the three decisions that decide a message's fate: whether it is QUEUED,
whether it is PUSHED, and whether the dormant sweep may delete it. It records a
3-value **storage class** beside the type and branches on that. The class is
what a self-hoster or a second implementation has to get right; the type string
is an alias that feeds it.

The type string has not become inert. Five smaller rules still read it:

| Rule | Where |
|------|-------|
| `envelope_type: "call"` is an alias for `ring: true` | §6.2.1.1 |
| a deposit typed `call` is reframed as `message` on the socket frame | §6.2.1.1 |
| the `owner_only` post gate fires on `message` and lets every other type through | §6.4.4 |
| a group's slowmode is charged on `message` only, so reactions, reads and edits are never held back | both group endpoints |
| the one-hour TTL that reaps `sknack` group rows | §6.3.1 |

Only the last is a retention decision, and it is called out again below.

| `cls` | Name      | Kinds that map to it |
|-------|-----------|----------------------|
| `0`   | ephemeral | `typing`, `read`, `visit`, `presence`, `nudge`, `bounce` |
| `1`   | content   | `message`, `reaction`, `edit`, `delete`, `system`, `secscreen`, `gmsg`, `call`, `carbon`, `homerec`, `profile`, `contactreq`, and every kind the island does not recognise |
| `2`   | critical  | `skdm`, `sknack`, and every future key-distribution kind |

Only the ephemeral and critical lists are enumerated in the island's code.
Content is the fall-through, which is why the four types after `call` above are
on that row: nothing names them, so they land there with every unknown kind.

⚠ **`carbon` and `homerec` land in content, and content pushes.** That is a
behaviour change nothing in their own descriptions predicts: `homerec` is a
silent record sync (§6.1) and a `carbon` is the echo of your own send to your
own devices (§7.4.11), so a user now gets a banner for a note they just typed
themselves on the other device. §7.4.11 tells a client to type notes to self
`carbon` rather than `message` precisely to avoid that, and the reason it gives
stopped holding when the pushable set widened. It is stated here rather than
fixed here: this document records what the island does.

The lists cover kinds no shipped client currently deposits (`typing` and
`presence` ride the socket as events, §7.4.3 and §7.4.2). Classifying them
costs nothing and means a client that does deposit one is filed correctly.

What the class decides:

|                                     | ephemeral (0) | content (1) | critical (2) |
|-------------------------------------|---------------|-------------|--------------|
| Queued for an offline recipient, 1:1 | yes          | yes         | yes          |
| Queued for an offline recipient, group | only if not dormant | only if not dormant, or a wake is going out | yes |
| Push or wake fired                  | no            | yes         | no           |
| Exempt from the group dormant sweep | no            | no          | yes          |

The two queueing rows differ because the group queue writes one row per member
and the 1:1 queue writes one. See the dormant paragraph below, and §6.2.2 for
what happens when a member is dormant AND has muted the group.

**Retention.** Every row that is written falls under the 30-day TTL of §6.3.1,
whatever its class. The class neither shortens nor lengthens it. What the class
does change is whether a GROUP row is written for a given member at all, which
is the dormant rule below.

**Push.** Content is the pushable class and the only one. Ephemeral kinds are
delivery-state plumbing or cosmetic pings: never worth waking a phone, and a
recipient who misses one loses nothing. Critical kinds carry key material and
must arrive without ever raising a banner.

**Dormant sweep.** The 14-day dormant rule on the GROUP queue (§6.3.1) skips
critical rows: they are kept for every member, dormant or not. The write side
mirrors it, so a dormant member's ephemeral copy is not queued at all and their
content copy only when a push is about to wake them for it (waking somebody for
a row nobody stored is a notification for a message that never arrives). Key
material is exempt because a member who loses an `skdm` cannot read a single
later broadcast, and their client cannot tell "no messages" from "cannot
decrypt". A few hundred bytes per chain is not what fills that table.

**Sending it.** `POST /messages/sealed` accepts `cls` directly (§6.2.1). A
sender that knows what it is sending should state the class, so that an opaque
or future kind is classified by the sender rather than guessed by the island.

**The legacy mapping.** `envelope_type` stays the ingest alias and is accepted
forever: old clients and peer islands send only it, and islands upgrade
independently. When a deposit carries no `cls`, or a `cls` outside `0..2`, the
island derives one from `envelope_type` by the table above. The same derivation
is the read-side fallback for rows written before the column existed, so `cls`
is never null in a drain response even on a mixed table.

⚠ **An unrecognised kind falls to content (1), never to ephemeral.** A future
kind from a lagging peer is then kept, delivered and pushed rather than
silently dropped.

The group endpoints (§6.2.2, §6.5) do not take `cls`. They always derive it
from `envelope_type`, and a `cls` sent there is ignored. Both DO take
`envelope_type`: on `POST /messages/group-broadcast` it is optional and
defaults to `"message"`, it is the only thing the class is derived from there,
and it never reaches the queue, since a broadcast row is always stored and
framed as `gmsg` (§6.5).

⚠ One retention rule still keys on `envelope_type` and not on the class: the
one-hour TTL that reaps `sknack` group rows (§6.3.1). A client that stops
labelling recovery requests `sknack` gets the 30-day TTL for them instead.

⚠ The pushable set widened when the class landed. Push used to fire for exactly
`{message, system, secscreen}`. Content also covers `reaction`, `edit`,
`delete`, `gmsg` and unknown kinds, so those now wake an offline recipient too.
The wake carries the envelope (§8.1) and the receiving client decides what, if
anything, to display: the server cannot read the envelope, so it has no basis
for the distinction it used to draw by kind.

`call` is no longer a class of its own: a legacy `call` deposit is content, and
it rides the socket framed as `message`, exactly like a text message. The queue
row still keeps the legible type it was deposited under (§6.2.1.1). Only the
class and the frame are equalised, not the stored string. The ringing is driven
by the `ring` request flag, which is never stored at all.

#### 6.1.2 Sealed payload padding (`_pad`)

A sealed blob still leaks its LENGTH. The outer wire is fixed width apart from
the sealed bytes, so the deposited payload grows with the message, and that
size is visible to the island, written into the queue row, and carried into
every backup of it.

Clients remove the fingerprint by padding the INNER plaintext, the bytes fed to
the AEAD seal, up to a coarse size bucket before sealing. The filler rides in a
`_pad` key on the inner JSON object:

```json
{ "from": 100200300, "from_host": "api.rcq.app", "spub": "...", "sig": "...",
  "env": "...", "_pad": "AAAAAAAA...A" }
```

The filler is ASCII `A`, which JSON never escapes, so the padded length is
exact to the byte. An empty pad key costs exactly 10 bytes (`,"_pad":""`), and
the sender sizes the filler as `bucket - unpadded - 10`.

⚠ **That 10 assumes compact serialization: no space after the comma, none
after the colon.** It is what all three clients emit, and it is the number the
arithmetic above is built on. A serializer that pretties its output by default
writes `, "_pad": ""` (12 bytes) and lands two bytes past every bucket. Python's
`json.dumps` is the obvious way to get this wrong; it needs
`separators=(",", ":")`.

Buckets, shared by all first-party clients: **256, 1024, 4096, 16384, 65536
bytes**, then multiples of 65536. The sender picks the smallest bucket that
holds `unpadded + 10`, which is what keeps the filler from going negative on a
message that lands just under a rung: such a message is pushed up to the next
rung rather than left unpadded. Coarse on purpose: an observer learns only
which rung a message landed on, and an identically sized text lands on the same
rung whatever composed it.

⚠ **The pad goes INSIDE the seal, never after it.** The `ct` field is
`nonce(12) || ciphertext || tag(16)`, and an opener treats everything after the
nonce as ciphertext whose last 16 bytes are the tag. Bytes appended to `ct`
push the real tag into the region the opener reads as ciphertext, and the
opener then reads the filler as the tag. Authentication fails and NOTHING can
open the message, not even the intended recipient. Padding after the AEAD tag
is not a weaker version of this scheme, it is a broken one.

**Padding is transparent to old decoders**, which is why it could ship one
client at a time. The v=1 signature is over `ephemeral_pub || envelope_bytes`,
not over the inner JSON, and every receiver reads the inner object by named
keys and ignores keys it does not know. A padded message opens byte for byte on
a client that has never heard of `_pad`. Both sealed wire versions are padded:
each has its own inner JSON object (§6.1) and `_pad` is added to whichever one
is being sealed, so the rule and the buckets are the same in both.

Do not assume `_pad` is the last key. Two of the three clients append it last,
and the third serializes an unordered dictionary. Only the byte count matters.

**Padding is a sender-only policy.** Receivers never look at buckets, never
check that a payload sits on one, and do nothing with `_pad` but ignore it. An
implementation may pad differently, or not at all, with no interop risk. The
shared ladder buys uniformity between clients, not correctness.

Which kinds are padded is local policy for the same reason. All three
first-party clients pad `text`, `photo`, `video`, `file`, `location`, `edit`,
`poll` and `carbon`: the kinds whose size tracks what the user wrote or
attached. Receipts, reactions and signalling are left alone. They are tiny,
frequent, and their size carries no content, so buying them uniformity would
spend relay bytes for nothing.

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
  "cls":           <int 0|1|2, optional>,
  "ring":          <bool, default false>,
  "payload":       "<base64 of opaque ciphertext>",
  "to_device_id":  <int, optional>
}
```

`cls` is the storage class of §6.1.1. Absent, or outside `0..2`, means "derive
it from `envelope_type`". `ring` is a request instruction, never stored
(§6.2.1.1). `to_device_id` names one of the recipient's libsignal devices
(§6.2.3). All three are additive; an island that predates them ignores them and
behaves exactly as it did before.

Behaviour:

- `404` if `to_uin` does not exist.
- Rate limit: `120/min` per identity (`messages_send` bucket).
- The envelope is **always queued** in `offline_messages`
  AND attempted via WebSocket. The WS attempt returning "live"
  only means the bytes hit a TCP buffer — the client might
  still lose them mid-flight, so the queue acts as the
  reconciliation source on next drain.
- The deposit allocates the row's `seq` (§6.3.1.3) inside its own
  transaction. `503 "seq allocation collided, retry"` is possible and the
  client should retry: it means the island's per-mailbox counter drifted,
  and the deposit was rolled back rather than allowed to overwrite a
  queued envelope.
- Waking, in this order and no other. If `ring` is set (or `envelope_type` is
  the legacy `"call"`), the ONLY wake this deposit can produce is the ringing
  one, and it fires only when the account has no live socket anywhere. A ring
  deposit never raises a message push, whether the account was online or not
  (§6.2.1.1). Otherwise, if the deposit is content class and any device of the
  recipient lacks a socket, an APNs or UnifiedPush wake carries the envelope
  to those devices as `env` (see Section 8).

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
  "type":         "<envelope_type>",
  "payload":      "<base64>",
  "server_time":  "<ISO>",
  "to_device_id": <int>       // present only for a fan-out copy (§6.2.3)
}
```

`type` is the deposited `envelope_type` with one substitution: a deposit typed
`call` is framed as `message` (§6.2.1.1).

#### 6.2.1.1 `ring`: waking a socket-less recipient

`ring: true` asks the island to wake the recipient's devices RINGING instead of
posting a message banner. It is an instruction to that island, acted on and
never stored: no column holds it and no drain returns it. The deposit is
otherwise an ordinary content-class row.

- The ring fires **only when the account has no live socket**. A recipient
  whose app is in the foreground already has the envelope from the socket send;
  neither the VoIP wake nor the UnifiedPush call wake can skip an individual
  connected device, and the client cannot dedupe a ring against the socket copy
  because it has no call id until it decrypts. Waking while a socket is up
  would ring twice.
- A ring deposit never also raises a message push, in either branch. The
  island decides on `ring` first and the content-class push is the ELSE of
  that decision, so a ring to an account that is online produces neither wake.
  The socket copy is the delivery in that case.
- The row is queued like any other, so the offline drain still delivers the
  envelope if the wake is late or lost.
- **One ring per call, and the sender is what guarantees it.** The wake is
  account-wide: it cannot be aimed at one device and the island does not
  deduplicate it, so N ring deposits to the same recipient fire N rings. A
  fan-out (§6.2.3) that set `ring` on every device copy would ring the callee
  once per copy. The shipped clients never meet this: a call signal is a single
  v=1 copy sealed to the account identity key, with no `to_device_id` at all,
  which every install can open. An implementation that fans a call signal out
  per device must set `ring` on exactly one of the copies.
- The wake is the same VoIP plus UnifiedPush pair a same-island `call_offer`
  fires (§8.3, §8.7). It carries `kind: "sealed"`, the recipient `to_uin`,
  `envType: "call"`, and the sealed envelope verbatim under `env`. Above 3500
  characters of payload the envelope is left out and the bare wake is sent:
  APNs caps a VoIP push at 5 KB and ntfy caps a message at 4 KB, and an offer
  envelope carries a whole SDP, so an oversized push would be rejected outright
  and the device would not ring at all. Without the envelope the app still
  comes up, connects its socket and drains the deposit. A beat slower, but it
  rings.

**What a ring discloses.** The recipient's island learns that a call is
arriving for this user, at this instant. Before this mechanism the deposit was
indistinguishable from a text message, and it is not indistinguishable now.

It still does NOT learn who is calling, on which island they live, the call id,
whether the call is audio or video, or the SDP. All of that is inside the
sealed envelope, which the island cannot open, so a wake must never invent any
of it. In particular there is no caller nickname in the payload: a same-island
VoIP wake carries one because that island knows the caller, and this one
genuinely does not. The client shows a generic incoming call until it decrypts
the envelope itself.

**And what it discloses to the push provider**, which is a second party and
easy to forget. The ring travels as a VoIP push through APNs or as a wake to
the recipient's UnifiedPush distributor, and that payload carries `to_uin` and
`envType: "call"` in the clear beside the sealed `env` (§8.3). So Apple, or
whoever runs the distributor, sees which account is being called and that the
wake is a CALL rather than a message. It does not see the caller, the call id,
the media type or the SDP, all of which stay sealed. The two plaintext fields
are there for a reason: a multi-account device holds one token and has to know
which local account to swap in before it can decrypt anything, and a client
that cannot tell a call wake from a message wake cannot raise a call screen in
time. §13.1 has the general shape of what a push provider sees.

The trade was accepted because a censor watching the wire can already infer a
call from packet timing and size, and a call that does not ring is not a call.

**The legacy form.** `envelope_type: "call"` asks for exactly the same wake,
and always will: a client that predates `ring` has no other way to ask. The
island rings when `ring` is true OR the type is `"call"`. The only difference is
what gets written down. A `ring` deposit is stored under whatever type it
declared (`"message"` in every first-party client); a `"call"` deposit is stored
under that legible type. Both are content class.

⚠ **The WebSocket frame for a call deposit is typed `message`, not `call`.**
The deposit type is an instruction to the island; the frame type is how the
recipient's client routes the envelope, and every shipped client accepts sealed
envelopes only from an explicit list of frame types that does not contain
`call`. A frame typed `call` is dropped in silence by a running app, which is
the worst case rather than the harmless one: the wake only fires when nothing
is connected, so calling somebody whose app was open would ring nothing at all.
The island therefore rewrites `call` to `message` on the socket frame. Every
client routes the envelope by its inner kind, so the label costs the client
nothing.

**Which signals ring.** Only the ones that must reach a closed app: the offer,
which is the call, and the end, which takes a ring down when the caller gives
up before pickup. `call_answer`, `call_ice` and the renegotiate and ICE-restart
pairs mean something only to an app that is already awake holding this call.
All three first-party clients draw the line at exactly those two, and an
implementation has to agree with them or a call wakes a killed phone on one
platform and not another. Ringing on every signal would wake the peer's phone
several times per call and hand their island one more timing disclosure each
time.

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
- For offline recipients, when the deposit is content class (§6.1.1): an
  APNs or UnifiedPush wake carrying their specific ciphertext, unless the
  group is in the recipient's `push_preferences.muted_group_ids`. Whom the
  island is willing to wake also decides whom it keeps the row for: a
  dormant member (§6.3.1) is queued only when a wake is going out to them,
  so nobody is notified about a message that was never written down.
  Critical-class rows are queued for every member, dormant or not.

⚠ **Muted plus dormant is silent loss, not a silent banner.** The two rules
compose in one direction only. Muting the group removes the member from the
wake set; being dormant removes them from the keep set; the row is written for
the union of those two sets, so a member who is in neither gets no row at all.
For a member who is present, muting costs them a banner and nothing else, which
is what a mute is for. For a member who has been away past
`OFFLINE_GROUP_DORMANT_DAYS`, muting also costs them the message. Nothing
signals it: the sender sees `queued: true` (it is true for the group, not for
that member) and the member sees a group that resumes at their return.
Key-distribution rows are exempt, since they are critical class and kept for
everybody.

Response: same `SendOut` shape as 1:1.

Each ciphertext is sealed to exactly one recipient's identity
key. The server sees N opaque blobs, never any plaintext.

#### 6.2.3 Addressing one device (`to_device_id`)

A v=2 session is a Double Ratchet between one PAIR of devices, so a ciphertext
opens on exactly one install of the recipient and on no other. A sender that
wants to reach a recipient on all their devices encrypts the message once per
device (§5.6) and posts each copy as its own `POST /messages/sealed`, naming
the target in `to_device_id`.

| Field          | Type                          | Meaning |
|----------------|-------------------------------|---------|
| `to_device_id` | int, optional, default absent | The recipient's libsignal `deviceId` (1 = primary, 2..127 = a linked device, §5.6) that this copy was sealed to. |

Absent (or explicitly `null`) means "whichever device can read it": every
device of the recipient is handed the row and the one holding the key opens it.
That is the shape of a v=1 seal (encrypted to the account `identity_key`, which
every install holds), the shape a sender uses when it cannot obtain the
recipient's device list, and the shape of every deposit made before this field
existed. Senders SHOULD omit the key rather than send `null`; both are treated
identically, and omitting it is what an island that predates the field has seen
all along.

A sender learns the list from `GET /keys/{uin}/devices` and fetches one bundle
per device (§5.6.2).

⚠ A sender that cannot read the device list must fall back to ONE unaddressed
v=1 copy, not to a single v=2 copy for device 1. A device nobody sealed to
hears nothing at all, and the send still reports `delivered`, which is the same
silent loss as not sending, only harder to notice.

**The server does not validate the id.** It is a routing label, not a claim. A
copy addressed to a device that does not exist is served to nobody; it is
reaped once every device's cursor has passed its id (§6.3.1.2), because the ack
prefix is computed over the rows a device is actually served and such a row is
in nobody's set. A revoked libsignal slot is nonetheless not recycled for 180
days by default (§5.6.3), well past both the queue TTL and any sender's cached
device roster: handing the number to a new install would deliver the retired
install's ciphertext to something that cannot open it, with no error anywhere.

**Group sends carry no device addressing.** `POST /messages/group-sealed` has
no `to_device_id` on its per-recipient entries, the group queue row has no such
column, and the drain does not filter group rows. Every device of every member
is handed every group row.

**Live delivery is not filtered either.** The WS frame carries `to_device_id`
when the deposit did, and every socket of the account receives every copy
(§6.3.2). Filtering live delivery would mean teaching the connection manager
which libsignal device sits behind each socket, for no gain: the addressee is
stated in the frame, and the other devices drop the copy without attempting a
decrypt.

Push carries the same label as `toDev` beside `env` (§8.1), for the same
reason. A fan-out message wakes every install and only one of them holds the
ratchet; without the label the others try, fail, and raise the generic "New
message" banner that is reserved for a real decryption problem.

**Compatibility.** The field is additive in both directions.

- An OLD island ignores it on the deposit, has no column to store it in, and
  serves rows without it. A device-aware sender's copies all arrive as
  unaddressed copies, so every device of the recipient is handed all of them
  and opens the one it can. Nothing is lost; N-1 copies per message are
  downloaded for nothing.
- An OLD sender omits the field and produces exactly the legacy row, which
  every island routes to every device.
- An OLD receiver ignores the unknown field on a row. In practice it also omits
  `dev` on the drain and is therefore served as device 1 (§6.3.1), so the only
  addressed copies it ever sees are its own.

#### 6.2.4 Island capability: `capabilities.envelope_class`

`GET /server/info` (§2.13) carries `capabilities.envelope_class`. `true`
promises exactly two things:

- the island accepts `cls` and `ring` on `POST /messages/sealed`;
- the island serves `cls` and `seq` beside `envelope_type` and `id` on the
  queue drain (§6.3.1).

It is a permanent property of the codebase, not an operator toggle: an island
either runs a build that knows these fields or it does not. The reference
server answers `true` from `2026.08.22.15`.

**The rule for a sender.** An absent `envelope_class` reads as **false**, never
as "probably yes" (§2.13 has the per-key defaults). The flag was born together
with `ring`, so an island that omits it is an island that does not know `ring`,
and assuming otherwise leaves a cross-island call silent on a closed phone.
This is the opposite of the permissive default the feature-surface flags take,
and for the opposite reason: guessing wrong there hides a working surface,
guessing wrong here breaks a call.

So, when depositing to another island:

- Only a decoded `envelope_class: true` counts. The field absent, the field
  false, a non-200, an unparseable body, a failed fetch and a timed-out fetch
  all mean "treat as old".
- An island treated as old gets the legacy form for a waking call signal:
  `envelope_type: "call"`, the only thing such an island rings for.
  `ring: true` may ride along, since an old island ignores an unknown field.
- The asymmetry is deliberate. A wrong "old" costs one legible `call` row on an
  island that could have stored the quieter type. A wrong "new" costs a phone
  that never rings.
- `cls` needs no gate at all. An island that does not know it ignores it and
  derives the same value from `envelope_type`, which every client keeps
  sending.

All three first-party clients probe once per peer host, memoise a `true` for an
hour and anything else for ten minutes (an island does not un-learn a
capability, but a slow answer or a blocked route must not brand it old for the
rest of the session), and warm the probe when a call starts so the offer does
not pay a round trip for it. The probe travels the same transport the deposit
does, so an island that is blocked for a direct fetch but reachable through the
circumvention transport (Section 11) is not mistaken for an old one. A
same-island send never probes.

### 6.3 Receiving

#### 6.3.1 `GET /messages/queue`

Authenticated, PER DEVICE. Returns every queued envelope (1:1 and
group) addressed to the caller that this device has not yet drained.
Each install drains independently through its own cursor, so a phone and
a linked web session each receive every message instead of whichever
drains first removing them for the other. The cursor itself, where a new
install starts, and when a queued row is reaped are all in §6.3.1.2.

Retention (server policy, not wire): a background sweep deletes queued
rows older than `OFFLINE_QUEUE_TTL_DAYS` (default 30). GROUP rows carry
a second rule — they are also deleted once the recipient has not
connected for `OFFLINE_GROUP_DORMANT_DAYS` (default 14, `users.last_seen`
being refreshed on WS connect, heartbeat and disconnect). Group fan-out
writes one row per member, so without it a busy group multiplies its
traffic by its entire membership and holds the product for a month,
overwhelmingly for accounts that never return to drain it. The 1:1 queue
is exempt: a direct message is worth holding the full TTL. A client that
has been away longer than the dormant window should therefore expect
group history to resume from its return, not from its departure. The
critical class (§6.1.1) is exempt from the dormant rule as well: key
material is kept for every member, dormant or not.

Group rows typed `sknack` carry a third rule, a TTL of
`OFFLINE_SKNACK_TTL_SECONDS` (default 3600) instead of the 30 days. A client
that meets a broadcast under a key id it does not hold cannot tell whose id it
is, so it asks every sender-key-capable member, and on a large group that is
hundreds of queued rows to reach one person. The requests are worthless once
stale: the asking client re-fires per key id every ten minutes and again after
a restart, so an hour-old copy will never be the one that recovers anybody.
Delivery is unaffected, since anyone online gets it live and anyone draining
within the hour still finds it. The sweep runs on its own interval, so in
practice a request survives up to that long rather than exactly this TTL.

Query params:

- `ack` (bool, default `false`).
- `dev` (int, default `1`): the CALLING device's libsignal `deviceId`.

⚠ Two different device identifiers meet on this endpoint and they are not
interchangeable.

| Identifier           | Where it comes from | What it keys |
|----------------------|---------------------|--------------|
| install id           | the token's `dev` claim, or `"primary"` for a phone / direct login (§2.9) | the drain cursor and the websocket registration |
| libsignal `deviceId` | the `dev` QUERY parameter; 1 for the primary, 2..127 for a linked device (§5.6) | which ciphertexts this device is handed |

The first says which INSTALL is asking, the second says which RATCHET it
holds. Neither is derived from the other: a phone that has never called
`POST /auth/device` is install `"primary"` and libsignal device 1, while a
linked web session has its own install id and its own libsignal id, assigned
by different endpoints.

Behaviour:

- Selects `offline_messages` / `offline_group_messages` for
  `to_uin = caller` with `id >` this device's cursor, ordered by
  `received_at` ascending, merged and re-sorted by `received_at`.
- 1:1 rows are filtered to `to_device_id IS NULL OR to_device_id = dev`.
  A copy addressed to a sibling device is WITHHELD: this device cannot open
  it, and handing it over would only park an undecryptable row in front of
  its cursor.
- Group rows are not filtered; they carry no device addressing (§6.2.3).
- `ack=false` (legacy drain-on-fetch): advances THIS device's cursor
  past every returned row in the same transaction, then returns them.
- `ack=true` (recommended): returns the rows WITHOUT advancing the
  cursor. The client persists them, then calls `POST
  /messages/queue/ack` (§6.3.1.1) with the ids it stored.

Response (both modes):

```json
[
  {
    "id":            <int>,
    "envelope_type": "<string>",
    "cls":           <int 0|1|2>,
    "seq":           <int|null>,
    "payload":       "<base64>",
    "received_at":   "<ISO>",
    "group_id":      <int|null>,    // null for 1:1
    "to_device_id":  <int|null>     // the device this copy was sealed to; null = any
  },
  ...
]
```

`cls` is the storage class of §6.1.1, derived for rows written before the
column so it is never null. `seq` is the per-mailbox sequence of §6.3.1.3:
present on 1:1 rows written since `2026.08.22.15`, null on older rows and on
group rows. An island that does not advertise `envelope_class` (§6.2.4) returns
neither field.

`to_device_id` is echoed so a client can tell "this one is not mine" apart from
"this one is mine and broken". The first is acked and dropped, the second is
left queued for a retry. An island that predates the `dev` filter hands out
every copy, so a receiving client still checks the field rather than trusting
the filter to have run.

⚠ `dev` defaults to 1, which is right for a phone and wrong for everything
else. A linked device that omits it is served the PRIMARY's copies, and if it
then acks them it advances its own cursor past its own copies, which are
unreachable from then on. A client that does not yet know its libsignal device
id must not drain at all: the queue holds everything until it does.

**Idempotency / delivery guarantee.** `ack=false` is at-most-once: if
the response is lost in flight the cursor has already advanced and
those rows are gone. `ack=true` is at-least-once: a lost fetch OR a
lost ACK simply leaves the rows for the next fetch. In BOTH modes the
same envelopes may also arrive via WebSocket, and an envelope may be
redelivered, so implementations MUST de-duplicate by the inner-content
UUID4 (generated by the sender), never by server-row `id`. New clients
SHOULD use `ack=true`; it is the loss-free path and all first-party
clients use it.

#### 6.3.1.1 `POST /messages/queue/ack`

Authenticated, PER DEVICE. Advances this device's drain cursor past the
envelopes it has persisted. Reaps any queued row now below the minimum cursor
across all the user's devices. It takes the same `dev` query parameter as the
drain, with the same meaning and the same default:

```
POST /messages/queue/ack?dev=<int>
```

**The cursor advances over the contiguous acked PREFIX, not over
`max(direct_ids)`.** The server lists the ids it would serve THIS device above
its current cursor, in id order, and walks that list while each id is present
in the acked set. The first missing id stops the walk. Everything past that
hole stays queued and comes back on the next drain, which is what a queue is
for. The cursor only ever moves forward, so a stale or out-of-order list is
harmless, and ids the device was never served are ignored.

⚠ This is not an optimisation, it is the safety property the endpoint exists
for. The cursor is a single watermark and the drain asks for `id > cursor`, so
anything left below it is unreachable for good. A client that acks a SUBSET
(say the sender-key distributions it could process, but not the group messages
interleaved between them) would otherwise move the watermark to the highest id
in that subset and bury every unacked row underneath. One account lost 532
group messages over nine days that way: they were still on disk, still
addressed to it, and no request could ever return them again. It looked to the
user like the group simply stopped at a date.

⚠ Ack with the SAME `dev` the drain was served under. The prefix is computed
over the rows this device is served, and the server rebuilds that set from
`dev`. Ask under another id and a sibling's copies, which were never handed
over and can therefore never be acked, become the first hole: the cursor stops
there permanently and this device redrains the same rows forever. Group ids are
unaffected (group rows are not device-scoped), but the two axes advance in one
call, so wedging the direct axis is enough.

Request:

```json
{ "direct_ids": [<int>, ...], "group_ids": [<int>, ...] }
```

`direct_ids` are `offline_messages.id`, `group_ids` are
`offline_group_messages.id`; the two tables have independent
auto-increment ids, so they MUST be reported separately.

Response: `{ "deleted": <int> }` (rows reaped by the resulting
min-cursor cleanup).

**A row this device can never open must still be acked.** Two cases are
terminal rather than transient:

- a 1:1 row whose `to_device_id` names another device (only reachable from an
  island that predates the `dev` filter): it belongs to a sibling, ack it and
  drop it;
- an unaddressed 1:1 row that a LINKED device cannot open: it was sealed by a
  pre-fan-out sender to the account key that only the primary holds, and no
  amount of redelivery makes it readable here.

Leaving either queued makes it the hole the prefix stops at. Every other
failure (a transient decrypt error, a failed local write) MUST be left unacked,
because the next drain may well succeed.

#### 6.3.1.2 The per-device drain cursor

One row per (account, INSTALL), not per libsignal device:

| Column           | Meaning |
|------------------|---------|
| `uin`            | the account |
| `device_id`      | the install id: the token's `dev` claim, or `"primary"` (§2.9) |
| `last_direct_id` | highest `offline_messages.id` this install has acked |
| `last_group_id`  | highest `offline_group_messages.id` this install has acked |
| `updated_at`     | when it last moved |

Two axes because `offline_messages` and `offline_group_messages` have
independent auto-increment ids that collide.

**When it moves.** On `POST /messages/queue/ack`, over the contiguous acked
prefix (§6.3.1.1); or on an `ack=false` fetch, past every row returned. Forward
only.

**Where a new install starts: the account watermark, never zero.** The
watermark is the furthest any cursor of this account has reached. Reinstalling
mints a NEW install id, so starting such a device at zero replays up to the
whole 30-day queue as fresh notifications, including messages the person had
deleted on the old install, whose local tombstones died with it. It reads as
the app hoarding history somewhere; it is the island's own queue, handed out
again to something it considers a brand-new device. Anything genuinely
undelivered sits ABOVE that mark and still arrives, which is what the queue is
for.

The same answer applies at all three doors that touch it: the fetch, the ack,
and the cursor row the ack creates. Answering it in only one of them is a live
bug, not a cosmetic one: a device that read from the right floor but wrote a
cursor of 0 for the axis it had nothing to ack on was handed the entire queue
on that axis at its next fetch.

**The first drain writes the cursor row before returning any rows.** If the row
were left unwritten until the ack, a sibling's ack in between could raise the
account watermark and this device would be rebased onto the higher mark,
burying the very rows it is holding.

**Reaping.** A queued row is deleted once EVERY live cursor of the account has
passed it (`id <= min(cursor)`). Cursors nobody is behind any more are dropped
first:

| Cursor state | Dropped after |
|--------------|---------------|
| untouched    | 30 days       |
| untouched while a sibling cursor of the account is fresher than 7 days | 7 days |

A cursor with no `updated_at` predates the column and is left alone until it
next acks.

⚠ **The two rules have different exemptions, and only one of them is safe for a
lone cursor.** The 7-day leash is computed against the account's freshest
cursor, so it can never fire on that cursor itself and therefore never drops an
account's only one. The 30-day rule has no such exemption: it is checked first
and consults nothing about siblings, so an account whose single cursor has gone
untouched for 31 days loses it. The next drain from that install finds no
cursor, and the account watermark is then computed over an empty set, which
reads as zero.

That is less alarming than it sounds, and saying it precisely matters. Every
ack reaps the rows all live cursors have passed, so on a single-device account
the rows below the lost cursor are already gone; a floor of zero serves only
the surviving rows, which are exactly the ones this install had not drained.
Losing a LONE cursor therefore replays nothing. The window that does re-serve
is the multi-device one: when every cursor of an account has gone stale and
all are dropped together, a returning install is re-served the rows it had
drained but a lagging sibling had not (the slice between the old minimum and
its own old cursor). Clients dedupe by envelope id, so this costs transfer,
not duplicate messages.

The shorter leash exists because the two cases are different animals. A phone
switched off for a fortnight is indistinguishable from a dead install only
while it is the account's ONLY device. The moment a sibling cursor keeps
moving, the still one belongs to an install that is gone (reinstalled,
uninstalled, wiped), and holding everybody's sealed envelopes for it is stored
metadata bought for nobody. The TTL sweep of §6.3.1 backstops cursors abandoned
without unlinking.

**What happens when a dropped install comes back.** The rules key on the age of
the cursor and on nothing else: not on a push registration, not on an unlink.
An install that is merely switched off looks exactly like one that is gone. So
a phone off for eight days beside a desktop that kept draining loses its
cursor, and the rows below the surviving minimum cursor are reaped behind it.
When that phone returns it still holds its install id, finds no cursor, and is
started at the account watermark, which is now the desktop's position. It is
served what arrived after that mark. Everything deposited during its absence
and already drained by the desktop is gone from the island, and there is no
backfill endpoint to ask for it (§6.3.1). The phone shows no gap and no error:
the thread simply resumes at its return. This is the cost of the leash, and it
is the reason 7 days applies only while a sibling is demonstrably alive and 30
days applies otherwise.

**What a fresh install sees.** It registers or links, gets a token carrying its
install id, and drains with its own libsignal `dev`. It is served the rows
deposited since the account's furthest device last acked, minus the copies
addressed to its siblings. It is NOT served history: there is no backfill
endpoint, and the queue is a delivery buffer rather than an archive. A client
that wants the older thread on a new install has to bring it itself (Section 10
migration, or its own backup).

⚠ `POST /auth/device` (§2.9) copies the calling install's CURRENT cursor onto
the new install id (and falls back to the account watermark when there is none
to inherit), so naming an install that has been draining as `"primary"` does
not replay its backlog.

#### 6.3.1.3 `seq`: the durable per-mailbox sequence

Every 1:1 queue row written since `2026.08.22.15` carries `seq`, a sequence
that counts only within ONE recipient's mailbox. It is served beside `id` and
does not replace it.

Why it exists: `id` is a global auto-increment over the island's whole 1:1
queue, so the gap between any two of your own rows measures how much traffic
the island carried in between. That is a volume oracle sitting in every row of
your queue and in every dump of it. A per-mailbox counter says nothing about
anybody else.

⚠ **It is NOT derived from `MAX(seq)`.** The counter lives in its own row, one
per mailbox, which the queue sweep never touches. A counter seeded from
`MAX(seq)` over the queue would reseed to zero the moment the sweep emptied a
quiet mailbox, and the fresh rows would then land BELOW every device's stored
cursor, where a cursor-based fetch can never reach them. That is silent,
permanent message loss. Anyone re-implementing the island must keep the counter
durable and independent of whether the mailbox currently holds any rows; a
`MAX()`-derived counter passes every test that does not include a sweep.

The counter is allocated inside the deposit's own transaction, so two
concurrent deposits to the same recipient serialise on the mailbox row and get
distinct numbers. `(to_uin, seq)` is unique as the loud backstop: if the
counter ever drifts, the deposit fails with `503` and the client retries,
rather than a queued envelope being overwritten.

**How a client uses it.** Today: it reads it, stores it, and acts on nothing.
All three first-party clients capture `seq` beside `id` and use it for no
decision, which is worth stating plainly so a third implementation does not go
looking for the rule it is missing. Rows arrive ordered by `received_at`,
de-duplication is by the inner-content UUID, and the cursor is `id`. `seq` is
there to let a later revision order or de-duplicate within one mailbox without
a wire change, and to keep the island's global row id out of that job.

- Read `seq` when present, fall back to `id` when it is null, and store both.
- The drain cursor and `POST /messages/queue/ack` still work in `id`. `seq` is
  an ordering token, not a cursor.
- ⚠ **`seq` is gappy, and that is correct.** A message to a recipient with N
  devices is N separate deposits, one per device, and each draws its own number
  from the one mailbox counter. A device drains only the rows addressed to it,
  so it sees 6, then 9, then 12. Expired rows leave holes too. A gap is NOT a
  missed message, and a client that raises "messages may be missing" on one
  will cry wolf on every multi-device account. De-duplication stays on the
  inner-content UUID, as §6.3.1 already requires.

**Lifecycle.** The counter follows the account. `POST /account/migrate` (§10.1)
moves it to the new UIN, because the rekeyed queue rows keep their old numbers
and a fresh counter at the new UIN would allocate 1 and collide with them on
the first post. A burn deletes it, so a recycled UIN starts its mailbox clean.

#### 6.3.2 WebSocket push

The same envelopes are forwarded over WS in real time when the
recipient is connected. Format on WS:

```json
{
  "type":         "<envelope_type>",   // matches the envelope_type field
  "payload":      "<base64>",
  "server_time":  "<ISO>",
  "group_id":     <int>,               // present for group sends only
  "to_device_id": <int>                // present only for a fan-out copy
}
```

`to_device_id` is present only when the deposit named a device. Delivery is NOT
filtered by it: every socket of the account receives every copy, and a device
that is not the addressee drops the frame without attempting a decrypt
(§6.2.3). A frame with no `to_device_id` is for whoever can read it.

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

- The WS path has no ACK; clients reconcile against the queue on
  reconnect (and de-duplicate by inner UUID).
- For the HTTP queue, `ack=false` uses the fetch itself as the
  implicit ACK; `ack=true` uses an explicit `POST /messages/queue/ack`
  (§6.3.1.1) so a lost response cannot drop messages. See §6.3.1.

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
  - `?members=0` returns every group **without its roster**: `members` comes
    back empty and `member_count` carries the number. This is what a chat list
    actually needs, and the roster is the expensive half of a group payload —
    every member with two base64 keys, which on a group of a couple of thousand
    people is hundreds of kilobytes on every poll. The default stays ON, so a
    client written before this parameter existed is unaffected.
  - ⚠ A client that opts out **must** fetch the roster from `GET /groups/{id}`
    before anything that encrypts per recipient. Sealing against an empty
    roster produces no ciphertexts at all, and the send paths cannot tell that
    apart from a group with nobody in it: the message is reported as sent and
    reaches no one.
- `GET /groups/{id}` — full info (members + settings). Always carries the
  roster; this is where a roster-less client comes to get one.
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
  (name/description/avatar: admin+; post_policy, is_closed,
  members_hidden: owner only; pinned_text: admin+). (`entry_price`
  is still accepted by the owner-only set but is **vestigial** — the
  column survives the 2026-05-27 economy pivot but is no longer charged.)
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
| `entry_price_tokens` | int|null   | null (free) | owner (vestigial; column present but unused since the 2026-05-27 economy pivot) |
| `is_closed`          | bool       | false       | owner            |
| `members_hidden`     | bool       | false       | owner            |
| `pinned_text`        | string(500)| null        | admin            |
| `pinned_at`          | datetime|null | null     | (auto-stamped)   |
| `pinned_by`          | int|null   | null        | (auto-stamped)   |

Every group payload also carries `member_count`, which is the size of the
roster whether or not the roster itself was sent (see `?members=0` above).

#### 6.4.3a Roster rows

Each entry of `members[]`:

| Field                 | Notes                                                          |
|-----------------------|----------------------------------------------------------------|
| `uin`, `nickname`     |                                                                 |
| `role`                | `owner` / `admin` / `member`                                    |
| `permissions`         | subset of `delete` / `members` / `info`; empty for a plain member |
| `status`              | live presence, `invisible` reported as `offline`                |
| `identity_key`, `signing_key` | X25519 + Ed25519, base64 — what a sender encrypts to     |
| `signal_identity_key` | non-null = this member runs libsignal (Stage 3 eligible)        |
| `sender_keys`         | this member understands the `gmsg` / `skdm` group path          |
| `avatar_media_id`, `avatar_media_key` | profile picture, gated by MEMBERSHIP rather than by the contact list: sharing a group is the relationship here, the same one that already exposes the nickname on this row |

#### 6.4.4 Post policy

| Value        | Behaviour                                                              |
|--------------|------------------------------------------------------------------------|
| `all`        | Every member can post. Default.                                        |
| `owner_only` | Broadcast mode. Only the owner can post; members read + react only. Enables the per-message view-count feature (Telegram-style). |

Server enforcement is now real, and it is enforced on the type
rather than on the endpoint: both group deposit paths reject a
post to an `owner_only` group from an IDENTIFIED caller who is
not the owner, with `403 "owner_only: only the group owner may
post"`. Only `envelope_type: "message"` is gated, so reactions,
reads, edits and deletes keep flowing from every member and a
broadcast group stays interactive.

The two paths differ in how strict they are, because they differ
in whether the caller can hide:

- `POST /messages/group-broadcast` (§6.5) requires a bearer, so
  the gate is absolute there.
- `POST /messages/group-sealed` (§6.2.2) is structurally
  anonymous, and an anonymous post is let through. Every shipped
  client sends a token for an `owner_only` message send, so this
  closes the "any member can post through the web client" hole
  today, and it is left open only so a client that predates the
  change is not broken. A modified native client that omits the
  token still gets past it, and the clients re-check the rule on
  receipt regardless (§6.6).

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

### 6.5 Sender keys: one ciphertext for the whole group

§6.4 seals a group message once per member. That is O(N) crypto and O(N)
upload for the sender, and on a group of two thousand it is the reason
posting felt like uploading a file. Sender keys make it O(1): the sender
encrypts ONCE under a chain key the members already hold, and the island
fans the same bytes out.

**Chain.** A sender owns one chain per (group, sender), identified by a
16-byte `kid` and an epoch `e`. Message keys ratchet forward per message
index `i`:

```
mk_i  = HMAC-SHA256(ck_i, 0x01)
ck_i+1 = HMAC-SHA256(ck_i, 0x02)
```

Forward-only: holding `ck_i` gives every later message and no earlier
one. The chain is rotated (new `kid`, `e+1`) when a member who held it
leaves, so a removed member cannot read what is posted after they go.

**Distribution.** The chain key travels per-member, sealed to each member
individually, never over the broadcast. It is deposited through
`POST /messages/group-sealed` (§6.2.2) with `envelope_type: "skdm"` and one
entry per member, NOT through `POST /messages/sealed`. That matters for
retention: it puts the rows in the group queue, which is the table the
one-hour `sknack` TTL and the critical-class dormant exemption both act on.
The envelope inside is:

```json
{ "kind": "skdm", "gid": 42, "kid": "<b64 16B>", "e": 0,
  "i": 7, "ck": "<b64 32B chain key at index i>" }
```

`i` is the first index that member can decrypt, so somebody added
mid-conversation gets the chain from the point they joined and not the
history before it. A member who receives a `gmsg` for a `kid` they do not
hold answers with `sknack` (`{kind, gid, kid}`) and the sender re-sends
the `skdm`. An `sknack` is deposited the same way an `skdm` is, through
`POST /messages/group-sealed` with `envelope_type: "sknack"`, fanned to every
sender-key-capable member because the asking client cannot tell whose `kid` it
met. A queued `sknack` group row is reaped after an hour rather than after the
queue's 30 days (§6.3.1); the asking client re-fires while it still needs the
key.

⚠ `skdm` and `sknack` are the critical class, exempt from the dormant-queue
sweep. See §6.1.1: dropping one costs that member the whole group, silently,
because the client cannot tell "no messages" from "cannot decrypt".

**Wire.** The broadcast payload is base64(JSON):

```json
{ "v": 1, "kid": "<b64 16B>", "e": 0, "i": 7,
  "n": "<b64 12B nonce>", "ct": "<b64 ChaCha20-Poly1305 ct||tag>" }
```

AAD is the ASCII string `rcq.gmsg.v1|<gid>|<kid>|<e>|<i>`.

★ The sender's Ed25519 signature over `AAD || envelope-bytes` lives
INSIDE the AEAD, not beside it. Every member holds the chain key, so the
chain key alone proves only "someone in this group wrote this" — the
signature is what says WHO, and putting it inside means a member cannot
strip or swap it without breaking the tag.

**Transport.**

```
POST /messages/group-broadcast
  { "group_id": 42, "envelope_type": "message", "payload": "<base64 gmsg wire>" }
→ { "delivered": <int>, "queued": <int>, "server_time": "<iso>" }
```

`envelope_type` is optional and defaults to `"message"`. It is the DECLARED
INNER type, and the island reads it for three things only: the storage class
(§6.1.1), the `owner_only` post gate (§6.4.4) and the group's slowmode, both of
which fire on `"message"` and let anything else through. It is never stored. The
queue row and the socket frame are always typed `gmsg`, whatever was declared,
because that is what tells a receiving client to decode through the chain
rather than through a sealed-sender opener.

Since `gmsg` is content class, an offline member is woken exactly as they are
on the per-member path: the same wake, the same `muted_group_ids` gate, and the
same rule tying the wake set to the keep set for a dormant member (§6.2.2,
§8.5). Unlike the per-member path, everyone gets the identical envelope, so a
wake here carries the one ciphertext the whole group shares.

⚠ This endpoint requires authentication, unlike every other deposit path.
Sealed sender is impossible here by construction: one ciphertext for the group
means the island must be told which group to fan it to, and `kid` already
pseudonymises the sender to the island. `401` without a bearer.

Rate limit 120/min (`messages_broadcast`), the same budget as a 1:1 send,
because it is now one small POST per message whatever the group size.

**Who is skipped.** The island fans out only to members whose client has
advertised `sender_keys` (§2.12). Everyone else is deliberately left out
of the broadcast and covered by the sender's legacy per-member fan-out in
the same send, because a client that cannot parse `gmsg` would otherwise
receive bytes it can only discard. Both halves ship together; this is the
"dual send".

### 6.6 `POST /groups/{group_id}/members/{member_uin}/permissions`

Moderator capabilities, a subset of `delete | members | info`:

| cap       | what it allows                                  |
|-----------|-------------------------------------------------|
| `delete`  | retract another member's message for everyone   |
| `members` | remove members                                  |
| `info`    | edit name, description, picture, pinned message |

The owner holds all three implicitly and is the only caller who may grant
them. ⚠ `members` is about taking people OUT. Any member may pull someone
IN (`POST /groups/{id}/members`) — an admin gate there would make small
groups feel locked, and the owner's block list is enforced regardless.

Recipients re-check the same rule on receipt; a moderator action is not
trusted because the sender claims it.

## 7. WebSocket Channel

### 7.1 Handshake

URL: `wss://<api-host>/ws/{uin}?token=<jwt>`

- The path UIN MUST equal the JWT's `sub`. Mismatch → close
  code `4403`.
- Invalid JWT → close code `4401`.
- A token whose `dev` claim is on the account's revoke denylist (§2.11.1), or
  whose `ep` names a previous holder of the number, → close code `4401`. The
  socket runs the same `authorize_session` check every authenticated REST
  request runs; before it did, a revoked browser could not call the API and
  could still sit on a socket receiving messages, presence and call
  signalling.
- If the user is `is_suspended = true` → close code `4408`.
- ⚠ None of these codes reach the client. The refusal happens BEFORE the
  handshake is accepted, so the peer sees an HTTP `403` and gets no close
  code at all. They are written down because they are what the island logs
  and what an accept-then-close implementation would send. `4000`
  (superseded) is the only code a shipped client acts on, and it arrives on
  an accepted socket.
- Otherwise the upgrade succeeds and the worker registers the
  socket in its local `_conns` map AND adds the UIN to the
  cluster-wide `ws:online_uins` Redis set.
- The new connection supersedes any prior connection for the same
  **(UIN, install)** pair on the same worker (old socket closed with code
  `4000` "superseded"). A `supersede` fan-out is published so peer workers
  also drop stale sockets for that pair.

  ⚠ The install, not the account. Superseding by UIN alone is what made a
  phone and a browser knock each other off the socket all day, and it is
  incompatible with per-device delivery (§6.2.3): both installs must be able
  to hold a socket at the same time to be handed their own copies. The
  install is the `dev` claim of the token (§2.5); a token without one is
  filed under `"primary"`, which reproduces the old single-device behaviour
  exactly for a client that has never named itself.

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

**Presence is also tracked per install**, in a second cluster-wide set holding
the install ids of `uin` that currently hold a socket anywhere (one set per
account, key name hashed, 180s TTL refreshed by every client frame). This is
what lets the push paths wake the devices that did NOT get the socket copy
while leaving the connected one alone (§6.2.1): the account-wide answer alone
meant a desktop left open suppressed the wake for the phone in the user's
pocket. The install ids here are the same ones the token's `dev` claim carries
(§2.5), so they line up with the push-token `device_id` of §3.5 and with the
drain cursor of §6.3.1.2. A push token that recorded no `device_id` cannot be
placed on either side of that comparison and is skipped whenever anything is
connected, which is exactly what the account-wide check used to do.

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
  "type":         "message" | "nudge" | "delete" | "system" |
                  "read" | "reaction" | "bounce" | "visit" |
                  "carbon",   // note-to-self and own-device echoes
  "payload":      "<base64>",
  "server_time":  "<ISO>",
  "group_id":     <int>,      // present for group sends only
  "to_device_id": <int>       // present only for a fan-out copy (§6.2.3)
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
{ "type": "vault_changed",    "slot": "<32 hex>", "version": <int> }
```

`vault_changed` goes to every session of the account whose slot moved (the
new version; on a delete, the tombstone's), never to anyone else; see §4.9.

#### 7.4.5 Group events

```json
{ "type": "group_created",             "group": <GroupOut> }
{ "type": "group_membership_changed",  "group": <GroupOut> }
{ "type": "group_membership_changed",  "group_id": <int> }
{ "type": "group_deleted",             "group_id": <int> }
```

`GroupOut` shape is the same as the REST `GET /groups/{id}`
response. `group_membership_changed` is the universal
"something about this group's roster or settings changed"
event — clients should re-render their local state from the
embedded object.

⚠ Above **100 members** that event carries `group_id` alone and no `group`.
The snapshot runs about 350 bytes per member and is sent once PER member, so
on a group of two thousand a single join became gigabytes of fan-out and
stalled call signalling behind it for tens of seconds. A client that only
knows the fat form reads `group`, finds nothing, and does nothing — picking
the change up on its next refresh, which is the intended degradation.

⚠ An empty `members[]` in any of these is **not** a statement that the roster
is empty, and in particular not that the reader was removed from the group.
Roster-less payloads are normal now, from both `?members=0` and the compact
form above.

#### 7.4.6 Account events

```json
{ "type": "account_burned" }
```

Sent by `DELETE /auth/account` and by `POST /account/migrate`
to every socket still open for the burned UIN. Clients are
expected to wipe local keys and route to the onboarding flow.

Key-slot events:

```json
{ "type": "device_registered",   "device_id": <int>, "label": "<optional>" }
{ "type": "device_rekeyed",      "device_id": 1 }
{ "type": "device_slot_revoked", "device_id": <int>, "label": "<optional>" }
```

Sent to every socket of the account when a key slot is claimed (§5.6.1), when
the identity in the primary slot is replaced by a **different** one, and when a
slot is retired (§5.6.3). Each also sends a push wake so devices that are not
connected still hear it. The push alert body carries no label and no device
detail, because it travels through APNs or the push host in the clear.

★ Why the account is told at all: an install restored from a seed phrase was
invisible. It appeared in no list and announced nothing, so whoever held the
phrase could read as a full device unnoticed. The slot claim is the one step
such an install cannot skip if it wants to send or read v=2, so it is where the
account finds out.

A first-time bundle upload is silent, and so is re-uploading the same identity
(an ordinary signed-prekey rotation, §5.5). Only a change of identity in the
primary slot announces.

The linked-session registry announces on the same channel:

```json
{ "type": "device_linked",  "device_id": "<string>", "label": "<optional>" }
{ "type": "device_revoked", "device_id": "<string>" }
```

Note the id here is the opaque string of §2.11, not a libsignal slot number.
`device_revoked` goes to the account's other devices so their device list
refreshes live; the revoked session may or may not receive its own, since its
socket is closed at the same instant. Nothing may depend on it hearing that:
being cut off is the message.

These event types are additive. A client that does not know one ignores it and
refreshes on its next visit to the device screen, as before.

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
{ "type": "call_ice_restart",           "to_uin": <int>, "call_id": "<string>", "sdp": "<string>" }
{ "type": "call_ice_restart_answer",    "to_uin": <int>, "call_id": "<string>", "sdp": "<string>" }
```

`sdp` is the **raw SDP text**, not a serialised session description; the
message type says whether it is an offer or an answer.

`candidate` is a **JSON string**, and the candidate line inside it is under the
key `sdp` — not `candidate`, which is what a browser calls the same field:

```json
"{\"sdp\":\"candidate:842163049 1 udp 1677729535 …\",\"sdpMLineIndex\":0,\"sdpMid\":\"0\"}"
```

Getting either of those wrong produces a call that rings, answers, and then
carries no media, with nothing logged anywhere to say so. All three shipped
clients encode them identically.

`call_ice_restart` re-gathers a connection whose path broke (a network change
mid-call) and is answered with `call_ice_restart_answer` in place, without
ringing again. Only one endpoint should start a restart — both see the failure
at the same moment, and two simultaneous restarts leave each side holding an
offer it cannot apply. The shipped clients restart from the **caller** side.

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

`call_offer` is delivered to **every** device of the callee, so all of them
ring. When one answers, the server sends the others:

```json
{ "type": "call_end", "from_uin": <int>, "call_id": "<string>", "reason": "answered_elsewhere" }
```

The device that answered is skipped, so it does not cancel itself. A client
receiving this reason should stop ringing silently: nothing ended for the user,
another of their own devices took the call.

Other `reason` values in use: `declined`, `no_answer`, `busy`, `unavailable`
(the callee's `call_policy` does not admit the caller), `failed`,
`setup_failed`, `ended`, `remote_ended`.

If the recipient is offline on `call_offer`, the server sends a
**VoIP push** (Section 8) carrying the SDP so the iOS app can
present the incoming CallKit UI, and a **UnifiedPush** wake
(§8.7) carrying the same payload with `"type": "call"` so an
Android client can raise a full-screen incoming-call UI. A
`call_end` that finds the recipient offline is pushed the same
way with `"kind": "end"`, so an incoming-call UI raised by the
offer push is dismissed rather than left ringing.

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

#### 7.4.10 Reactions, read receipts, delivery receipts

Reactions and read receipts are transported as standard
sealed-sender envelopes with `envelope_type: "reaction"` or
`envelope_type: "read"`. There is no dedicated server event
type; clients ingest them through the normal message path
and apply local effects.

**Delivery receipt** (2026-08-18). Inner kind `"delivered"`,
same shape as the read receipt:

```json
{ "kind": "delivered", "targetIDs": ["<uuid>", ...] }
```

Sent by the RECIPIENT's client on ingest of a 1:1 message,
whether or not the thread was opened. The original sender
lifts those bubbles from SENT to DELIVERED, and never
downgrades: a read receipt may arrive first.

⚠ Why a client-to-client receipt and not a server signal.
`SendOut.delivered` answers one question, once — "did the
recipient have a live socket at the instant of this deposit"
— and nothing revisits it, so a message written while the
peer was offline keeps a single tick forever. The island
cannot correct itself later either: a sealed deposit is
unauthenticated, so when the recipient finally drains the
queue the island does not know who sent the row it is
handing over and has nobody to notify. Only the recipient's
own client knows.

⚠ The OUTER `envelope_type` stays `"read"`. It is already
outside `_PUSHABLE_TYPES` and already in every client's
live-routing set; a new outer label would be routed by no
client until the whole field updated, which for a receipt
means the tick stays broken for precisely the oldest builds.
The inner `kind` carries the meaning.

1:1 only. A group message has as many recipients as it has
members and one tick cannot stand for all of them.

⚠ Receivers MUST tolerate an unknown inner `kind` rather
than failing the decode. A throw there turns every future
wire addition into a landmine whose blast radius depends on
which caller happens to hold the row — one message, or a
whole queue drain.

#### 7.4.11 Notes to self are carbons

A note written in Saved Messages is addressed to the
author's own uin, which is what puts it on their other
devices. It MUST be sent with `envelope_type: "carbon"`,
not `"message"`: under sealed sender the island cannot tell
a note from a stranger's letter, so a `"message"` label
makes it push, and the author's own phone rings for what
they just typed.

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
  "toDev":   <int, only for a fan-out copy>,
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
- `toDev` carries the deposit's `to_device_id` (§6.2.3) when it had one.
  A fan-out message wakes every install of the account and only one of them
  holds the ratchet; without the label the others attempt the decrypt, fail,
  and raise the generic "New message" banner that is reserved for a real
  decryption problem.

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

A ringing deposit (§6.2.1.1) fires the same VoIP push with a different,
discriminated payload, because the island cannot open the envelope and so has
none of the fields above:

```json
{
  "kind":    "sealed",
  "to_uin":  <int>,
  "envType": "call",
  "env":     "<base64 sealed envelope, omitted above 3500 chars>"
}
```

`kind: "sealed"` is the discriminator. A client that does not know it has no
`call_id` or `sdp` to act on and falls into its malformed-payload path, which
reports and ends on iOS and drops on Android: the pre-2026-08-15 behaviour of
not ringing, never a crash. `to_uin` rides in the clear for the same reason the
message push carries it, so a multi-account device knows which local account to
swap in before it can decrypt anything.

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

Both group endpoints respect `muted_group_ids`:
`POST /messages/group-sealed` and `POST /messages/group-broadcast`
(§6.5) drop a muted member from the wake set before firing anything.

⚠ For a member who has been away past the dormant window, that also
drops their queue row. The wake set and the keep set are the same
decision on this path, so muting a group while dormant loses the
message rather than just the banner. §6.2.2 has the whole rule and
why it is built that way. For a member who is merely offline, the
envelope is queued as normal and only the alert is suppressed, which
is what this section used to say for everyone.

### 8.6 Token lifecycle

- Registered via `POST /users/me/push-token` (Section 3.5).
- Pruned on `DELETE /users/me/push-token`.
- Pruned automatically on APNs response codes 400
  `BadDeviceToken`, 410 `Unregistered`, and 403
  `BadEnvironmentKeyInToken`.

### 8.7 UnifiedPush (Android)

Google services are unreachable in the target region, so the Android
client does not use FCM. It registers a **UnifiedPush endpoint**: a
plain HTTPS URL issued by whatever distributor the user runs (ntfy.sh,
a self-hosted ntfy, a WebPush distributor). The server is deliberately
dumb — it HTTP-POSTs the wake to that URL. There is no provider API
key and no hardcoded gateway; the endpoint URL is the whole address.
Registration rides the same `POST /users/me/push-token` with
`platform: "android-up"` (§3.5), and so inherits the burn cascade and
the `DELETE` cleanup.

Wake payload (JSON body):

```json
{ "v": 1, "type": "msg" | "call", "to_uin": <int>,
  "title": "<string>", "body": "<string>",
  "env":   "<base64 sealed envelope>",   // opaque, already E2E-encrypted
  "envType":    "message" | "gmsg" | "secscreen" | "system",
  "thread_id":  "<string>",   "notif_kind": "<string>",
  "group_id":   <int>,        "group_name": "<string>" }
```

`type: "call"` carries the flat call dict (`call_id`, `from_uin`,
`nickname`, `media`, `sdp`) instead, mirroring the VoIP push of §8.3.
The push server sees ciphertext only: the same opaque envelope APNs
carries, so the exposure matches Apple's on the iOS path.

Request headers: `Content-Type: application/json`, plus RFC 8030
`TTL` (86400s for a message wake, 60s for a call wake — a stale call
wake is worthless) and `Urgency: high`. `TTL` is mandatory for WebPush
endpoints; omitting it makes Mozilla autopush reject the POST with 400.

Response handling, per endpoint:

| Status | Action |
|--------|--------|
| 2xx | delivered |
| 404, 410 | registration is gone — drop the endpoint row |
| 408, 429, 5xx (incl. 507) | retry with jittered backoff (~30s total), then record the failure |
| anything else | permanent rejection — record it, keep the endpoint |

The retry schedule is not optional politeness. Public ntfy answers
`507` when the topic has no currently connected subscriber, and `429`
when a rate bucket is drained — and ntfy charges that bucket to the
**subscriber**, so users sharing a carrier NAT share one bucket. Both
states flap within seconds, and dropping the wake on first failure
loses a notification the distributor would have accepted moments later.
Neither check exempts an authenticated publisher, so a paid account on
the public instance does not change the arithmetic; an operator who
needs reliable Android push should run their own push server.

Delivery is scheduled off the request path: the sender's HTTP request
never waits on a third-party push server. The final outcome per
endpoint is recorded and exposed through `GET /users/me/push-health`
(§3.5).

**Embedded distributor (Android client, since v0.74).** The reference
client ships its own distributor rather than requiring the user to
install one: a receiver answering REGISTER / UNREGISTER in-process, and
a foreground service holding one WebSocket to the operator's own push
server (`push.rcq.app` for the flagship). It mints its topic from a
CSPRNG and returns `https://<push-host>/<topic>?up=1` as the endpoint,
so everything above is unchanged — on the wire the server cannot tell an
embedded distributor from ntfy, and does not need to. On reconnect the
client resumes from the last delivered message id, so a wake published
while the device was offline is replayed from the push server's cache
instead of being lost. Any other UnifiedPush distributor stays
selectable: this is a default, not a lock-in.

An operator running their own island should run their own push server
too. The settings that matter are the two that made the public instance
unusable: `visitor-subscriber-rate-limiting` OFF, a per-visitor request
bucket sized for group fan-out, and the island's own address exempt from
that bucket.
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
| Audio room ownership          | yes      |                                        |
| Poll creators + voters        | yes      |                                        |
| Per-mailbox `seq` counter     | yes      | It has to. The re-keyed queue rows keep their old `seq`, so a counter restarting at 1 under the new number would collide with them and `503` the first deposit (§6.3.1.3). |
| Drain cursors                 | yes      | `QueueCursor.uin`. Also mandatory: the queue moves, and a new number with no cursors has an account watermark of zero, which replays the entire migrated queue as fresh notifications (§6.3.1.2). |
| Advertised capabilities       | yes      | `sender_keys` (§2.12), so group broadcast keeps reaching them. |
| Moderation reports            | yes      | Both as reporter and as target: history follows the person, or migrating would launder it. |
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
- **Secondary key slots go with the old row.** `devices` and
  `one_time_prekeys` carry a cascading foreign key to `users.uin`, so
  deleting the old user row deletes them. The account arrives at the new
  number with no device registry and no prekey pools, primary or secondary,
  and every install re-bootstraps: the first one to publish takes slot 1
  (§5.4) and the others claim fresh secondaries, with new numbers. A sender
  holding a cached device roster for the old UIN is holding it for a UIN
  that no longer exists.
- **The linked-device registry and its revoke denylist do not move.** Both
  are Redis state keyed by the old UIN (§2.11.1). Linked sessions are
  disconnected anyway: their tokens name the old `sub` under an epoch that
  has just been retired, and the `account_burned` event goes to every socket
  still open on it. They must be linked again.
- The signed home-island record is dropped rather than re-keyed: it asserts
  something about the old number specifically, and the client republishes a
  fresh one on next boot.

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
| 503    | Admin panel disabled (admin endpoints only); sealed-deposit `seq` collision, retryable (§6.3.1.3) |

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
- `400` primary key slot (§5.6.3):
  `{"detail": {"code": "primary_slot"}}`
- `401` revoked install asking for a NEW token (§2.11.1):
  `{"detail": {"code": "device_revoked"}}`. The same install presenting the
  token it already holds gets `401` with the plain string `"device revoked"`.
- `403` revoke cooldown (§5.6.4):
  `{"detail": {"code": "revoke_cooldown", "wait_seconds": <int>}}`
- `409` linked session renaming itself (§2.11.1):
  `{"detail": {"code": "linked_device_cannot_rename"}}`

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
| `messages_broadcast`  | 120         | 60s      | `POST /messages/group-broadcast`      |

Business-feature endpoints carry their own limits, not listed
here.

⚠ **`messages_send` counts POSTs, and a fan-out is one POST per recipient
DEVICE** (§6.2.3). Messaging somebody with four installs spends four of the
120, so the real ceiling is 30 messages a minute to that recipient, and a
`503` retry on a `seq` collision spends another. A sender that reads 120 as
"messages per minute" will meet the limiter well before it expects to. The
budget is per identity, and for the anonymous sealed path the identity is the
client IP, so several installs behind one relay exit share it.

⚠ **The device-slot endpoints carry no limit of their own.**
`POST /keys/devices` (§5.6.1), `POST /keys/devices/{device_id}/revoke` (§5.6.3)
and `POST /keys/devices/{device_id}/prekeys` (§5.6.5) are authenticated and
otherwise unmetered on the reference island. That matters most for the claim:
it is not idempotent and the slot range stops at 127, so a client that
re-registers in a loop burns an account's whole range and gets `409 "device
limit reached"` for good. Self-hosters should know this; clients should
persist the id they were handed before anything else can fail.

⚠ The `503` on a `seq` collision (§6.2.1) carries a plain-string `detail`, not
the structured `{"code": ...}` shape the rest of §12.1 uses. Retry it on the
status code, not on a code field that is not there.

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
- **Push provider (APNs, or an Android UnifiedPush distributor)
  compromise of message CONTENT.** The body is inside `env`, a
  sealed envelope, and the provider cannot open it. The NSE
  decrypts client-side. The payload is not `env` alone, though,
  and the plaintext fields around it are worth listing because
  an operator threat-modelling their island needs them: the
  recipient `to_uin`, the envelope type (`envType`), the
  routing hint (`thread-id`, which encodes `peer-<UIN>` or
  `group-<id>`), the target device (`toDev`) on a fan-out copy,
  and for a call wake the fact that it IS a call (§8.3). Each
  is there for a reason a client cannot work around: a
  multi-account device holds one token and must pick a local
  account before it can decrypt anything, and a call has to
  raise a call screen before decryption. So a provider with
  full visibility learns WHO is being messaged, WHEN, whether
  it is a call, and which conversation it belongs to. It does
  not learn the sender or the body. The group NAME used to
  ride here too and no longer does (§6.2.2).
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
  privacy trade-off; the cost is that spam-suppression has to
  work without knowing the sender. The mechanism for that ships
  and is off by default: `GET /deposit-auth/params` and
  `POST /deposit-auth/issue` mint anonymous blinded tokens
  (RSA blind signatures, gated by proof-of-work), and
  `POST /messages/sealed` accepts one in an optional
  `deposit_token` field, verifying and spending it single-use.
  Issuance is unlinkable to the deposit, so the island can meter
  senders without identifying them. Both endpoints answer `404`
  while the island has the feature switched off, which the
  reference server does, and `capabilities.deposit_auth`
  (§2.13) is how a client finds out. Until an operator enables
  it, per-IP limits and client-side filtering are the whole
  defence.
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
  is associated with the submission. Three endpoints face the
  reporter rather than the operator. `GET /reports/mine`
  returns that account's own reports and never the internal
  `resolution_notes`; each carries `reply` + `replied_at` (the
  LAST operator answer) and `thread`, the whole exchange
  oldest-first as `{id, from_admin, body, created_at}`. A
  client that predates the thread reads `reply` alone and
  still shows the newest answer. `POST /reports/mine/{id}/messages`
  (`{"body": "…"}`, 1–4000 chars, 20/hour) adds the reporter's
  own turn: only on their own report, only while its status is
  `open` — a closed one answers 409 with code `closed` and
  stays readable. Deliberately NOT gated on the island's
  "reports open" switch: intake can be closed while a
  conversation already under way must still be finishable.
  `DELETE /reports/mine/{id}` lets a reporter withdraw one of
  their own, refusing with 409 while a report about ANOTHER
  user is still open, so an accusation cannot be filed, act,
  and then be erased. None of this is delivered as a chat
  message: the server holds no keys and composes no envelopes,
  so a server-written "message" would be exactly the
  capability this protocol promises the operator does not
  have. The push that announces an answer carries no part of
  its text
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

This document is **v1.8**. The protocol wire major is still v1;
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
| v1.4    | 2026-07-31 | Android push documented at last: new §8.7 UnifiedPush (endpoint registration with `platform: "android-up"`, wake payload, mandatory RFC 8030 `TTL`, the retry/prune table and why `507`/`429` from a public ntfy are retryable rather than fatal), `GET /users/me/push-health` and the widened `POST /users/me/push-token` in §3.5, and the offline-queue retention rules in §6.3.1 (30-day TTL plus the 14-day dormant-recipient rule that group rows are subject to and 1:1 rows are not). Documents shipped behaviour; no wire-breaking changes. |
| v1.5    | 2026-07-31 | §8.7 gains the embedded distributor the Android client ships since v0.74 (own topic, own push server, resume-from-id on reconnect) and the operator guidance that goes with running one. No wire change: an embedded distributor is indistinguishable from ntfy on the wire. |
| v1.6    | 2026-08-04 | Call signalling brought up to what the clients actually send (§7.4.7): the `call_ice_restart` / `call_ice_restart_answer` pair, the encoding of `sdp` (raw text) and of `candidate` (a JSON string whose candidate line is under the key `sdp`) — the two details a third implementation cannot guess and whose absence yields a silent call — multi-device ringing and the `answered_elsewhere` end reason, the enumerated end reasons, and the UnifiedPush call wake alongside the iOS VoIP push. Also corrects §0 and §15.2, which still stamped the document v1.3 (2026-06-11) after the v1.4 and v1.5 revisions. No wire change: all of it documents shipped behaviour. |
| v1.7    | 2026-08-17 | Reports became a conversation (§14): `GET /reports/mine` now carries `thread` — the whole exchange, oldest first — beside the `reply` older clients read, and `POST /reports/mine/{id}/messages` lets the reporter write back on their own open report (20/hour, 409 `closed` on a resolved one, deliberately not gated on the island's reports-open switch). Documents shipped behaviour; additive, no wire break. |
| v1.8    | 2026-08-22 | Three shipped, additive areas the document had no words for. **Device addressing:** `to_device_id` on the sealed deposit and on the queue row, the `dev` query parameter that decides which copies a device is served, the ack rule that advances over the contiguous acked prefix rather than `max(id)` (and the 532 lost group messages that taught it), the per-device drain cursor with its account-watermark floor and its reaping leash (§6.2.3, §6.3.1, §6.3.1.1, §6.3.1.2); §5.6 corrected, since it asserted that no per-device delivery addressing was needed. **Device key slots:** claiming a slot and its non-idempotence, the device list and the `signal_identity_key` that lets a sender check an install without spending a one-time prekey, slot retirement and what it does and does not stop, the shared revoke cooldown and its stolen-link threat model, the session denylist enforced on a token presented AND on a token minted, and the key-slot WS events (§5.4, §5.6.1 to §5.6.4, §2.11.1, §7.4.6). **Stage-2 envelope metadata:** the 3-value storage class `cls` the island now branches on instead of `envelope_type` and what it decides for push and the dormant sweep, the `_pad` filler inside the sealed plaintext and why padding after the AEAD tag makes a message unopenable, the `ring` flag that wakes a socket-less recipient without typing the deposit "call" and exactly what it discloses, `capabilities.envelope_class` and why its absence has to read as false while the feature-surface capabilities read the other way, and the durable per-mailbox `seq` served beside `id` (§6.1.1, §6.1.2, §6.2.1.1, §6.2.4, §6.3.1.3). All of it documents shipped behaviour and all of it is additive: `envelope_type` and `id` are accepted and served forever, an older island ignores the new fields and behaves as it did, and an older client that never sends or reads them is unaffected. No wire break. **Corrections, and they are not small:** the v=1 and v=2 envelope layouts in §6.1 described formats no client has ever sent (a packed binary struct sealed with AES-GCM for v=1, a bare libsignal `SealedSenderMessageContent` for v=2); both are now written from the three shipping clients, which agree byte for byte, and anybody who implemented the old text could not open a single message. §7.1 still said a socket supersedes by UIN, which contradicts per-device delivery and is what used to knock a phone and a browser off each other; it supersedes by (UIN, install). |
| v1.9    | 2026-08-23 | The vault (§4.9): `PUT|GET|DELETE /vault/{slot}`, opaque client-sealed slots per account with the version rule from report #605 (a write names the version it was based on, 409 otherwise), the `vault_changed` socket nudge (§7.4.4), the first-party derivation of slot name and key from `identity_priv` rather than the seed and why, the padded sealed layout, and the rollback check. Capability `vault` and the two stage flags that were already live but undocumented, `anon_keys` and `group_log`, join the §2.13 table with their shared absent-reads-false rule. Additive; no wire break. |
