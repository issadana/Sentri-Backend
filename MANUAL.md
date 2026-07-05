# Sentri Backend — User & Integration Manual

This manual explains how to use every part of the Sentri (Neural Firewall) API: the
authentication flow, each REST endpoint with request/response examples, the real-time
WebSocket log protocol, and the Server-Sent Events (SSE) chat stream. For installation
and configuration, see [README.md](README.md).

> **Base URL**
>
> - Production: `https://api.sentri-security.cloud`
> - Local (Docker): `http://localhost:8000`
> - Local (dev server): `https://localhost:8000` (self-signed cert)
>
> The examples below use `$BASE` as a stand-in for the base URL.

---

## Table of contents

1. [Authentication model](#1-authentication-model)
2. [Getting started: register & log in](#2-getting-started-register--log-in)
3. [Authentication endpoints](#3-authentication-endpoints)
4. [User profile](#4-user-profile)
5. [Detection settings](#5-detection-settings)
6. [Blacklist](#6-blacklist)
7. [Hardware metrics](#7-hardware-metrics)
8. [Firewall logs (REST)](#8-firewall-logs-rest)
9. [Firewall logs (WebSocket, real-time)](#9-firewall-logs-websocket-real-time)
10. [AI assistant (SSE chat)](#10-ai-assistant-sse-chat)
11. [Error format & status codes](#11-error-format--status-codes)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Authentication model

Sentri uses **JWT** with two token types:

| Token         | Lifetime | Used for                                                                     |
| ------------- | -------- | ---------------------------------------------------------------------------- |
| Access token  | 1 week   | Every protected request. Sent as `Authorization: Bearer <token>`.            |
| Refresh token | Long     | Obtaining a new access token, and logout. Tracked server-side and revocable. |

**Passing the token.** Protected endpoints read the token from the
`Authorization: Bearer <access_token>` header. Clients that cannot set headers
(browser `EventSource`, browser WebSockets) may instead append `?token=<access_token>`
to the URL — this is supported on the SSE chat endpoint and the WebSocket log stream.

Passwords are hashed with **bcrypt**; the plaintext is never stored.

---

## 2. Getting started: register & log in

```bash
# Register — returns access + refresh tokens and the new user
curl -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"hanine","email":"hanine@test.com","password":"password123"}'

# Log in with an existing account
curl -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"hanine@test.com","password":"password123"}'
```

Save the `access_token` from the response and send it on every protected call:

```bash
ACCESS="<access_token from login>"
curl "$BASE/auth/me" -H "Authorization: Bearer $ACCESS"
```

---

## 3. Authentication endpoints

### POST `/auth/register`

Create a new account. On success a default settings row is created for the user, and
tokens are returned.

**Request body**

| Field      | Type   | Rules                                |
| ---------- | ------ | ------------------------------------ |
| `username` | string | required, ≤ 100 chars, unique        |
| `email`    | string | required, valid email, ≤ 255, unique |
| `password` | string | required, ≥ 8 chars                  |

**Response `201`**

```json
{
  "message": "User registered successfully",
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "user": { "id": 1, "username": "hanine", "email": "hanine@test.com" }
}
```

Errors: `400` invalid input · `409` email or username already exists.

### POST `/auth/login`

```json
// Request
{ "email": "hanine@test.com", "password": "password123" }
```

**Response `200`**

```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "user": {
    "id": 1,
    "username": "hanine",
    "email": "hanine@test.com",
    "is_admin": false
  }
}
```

Errors: `400` missing fields · `401` invalid credentials.

### GET `/auth/me` 🔒

Returns the current user. Requires an **access** token.

```json
{ "id": 1, "username": "hanine", "email": "hanine@test.com", "is_admin": false }
```

### POST `/auth/refresh` 🔒 (refresh token)

Send the **refresh** token to get a fresh access token.

```bash
curl -X POST "$BASE/auth/refresh" -H "Authorization: Bearer $REFRESH"
```

```json
{ "access_token": "eyJhbGciOi..." }
```

Errors: `401` refresh token invalid or revoked.

### POST `/auth/logout` 🔒 (refresh token)

Revokes the presented refresh token server-side. Returns `204 No Content`.

```bash
curl -X POST "$BASE/auth/logout" -H "Authorization: Bearer $REFRESH"
```

---

## 4. User profile

### PUT `/users/me` 🔒

Update the username and/or password. Changing the password requires the current one.

**Request body** (all fields optional)

| Field              | Notes                              |
| ------------------ | ---------------------------------- |
| `username`         | New username (must be unique).     |
| `current_password` | Required if changing the password. |
| `new_password`     | New password, ≥ 8 chars.           |

```bash
curl -X PUT "$BASE/users/me" -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"password123","new_password":"newpassword123"}'
```

**Response `200`**

```json
{
  "message": "User updated successfully",
  "user": {
    "id": 1,
    "username": "hanine",
    "email": "hanine@test.com",
    "is_admin": false
  }
}
```

Errors: `400` bad input · `401` current password incorrect · `409` username taken.

---

## 5. Detection settings

Each user has one settings row (created automatically at registration) that controls how
the on-device firewall behaves.

| Field                 | Type  | Default | Meaning                                                     |
| --------------------- | ----- | ------- | ----------------------------------------------------------- |
| `block_threshold`     | float | `0.20`  | Score ≥ this ⇒ block. Range `0–1`.                          |
| `warn_threshold`      | float | `0.10`  | Score in (`warn`, `block`] ⇒ warn / ambiguous. Range `0–1`. |
| `flood_detection`     | bool  | `true`  | Enable packet-flood detection.                              |
| `syn_flood_detection` | bool  | `true`  | Enable SYN-flood detection.                                 |
| `flood_pkt_per_sec`   | int   | `1000`  | Flood trigger threshold (packets/sec). Must be > 0.         |
| `syn_flood_per_sec`   | int   | `100`   | SYN-flood trigger threshold. Must be > 0.                   |
| `bf_model_enabled`    | bool  | `true`  | Enable the brute-force model.                               |
| `dos_model_enabled`   | bool  | `true`  | Enable the DoS model.                                       |
| `max_log_entries`     | int   | `200`   | Client-side log retention cap. Must be > 0.                 |
| `log_system_traffic`  | bool  | `false` | Whether to log system (OS) traffic.                         |

### GET `/settings` 🔒

Returns all fields above. `404` if no settings row exists.

### PUT `/settings` 🔒

Partial update — send only the fields you want to change. Values are validated
(thresholds in `0–1`, positive integers where required).

```bash
curl -X PUT "$BASE/settings" -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"block_threshold":0.8,"warn_threshold":0.5,"flood_pkt_per_sec":1500}'
```

```json
{ "message": "Settings updated successfully" }
```

Errors: `400` out-of-range value · `404` settings not found.

---

## 6. Blacklist

Per-user list of blocked source IPs. Entries can be added manually **or** automatically
by the firewall-log ingestion path (any `blocked` source IP is auto-added — see
[§9](#9-firewall-logs-websocket-real-time)).

### GET `/blacklist` 🔒

```json
[
  {
    "id": 12,
    "ip": "185.220.101.5",
    "reason": "brute_force",
    "bf_score": 0.92,
    "dos_score": 0.03,
    "notes": "Auto-added from firewall log",
    "added_at": "2026-07-06T14:23:01.000000"
  }
]
```

### POST `/blacklist` 🔒

| Field    | Type   | Rules                                   |
| -------- | ------ | --------------------------------------- |
| `ip`     | string | required, valid IPv4/IPv6               |
| `reason` | string | optional, ≤ 20 chars (default `manual`) |
| `notes`  | string | optional, ≤ 255 chars                   |

```bash
curl -X POST "$BASE/blacklist" -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.10","reason":"manual","notes":"Suspicious traffic"}'
```

Response `201` returns the created `entry`. Errors: `400` invalid IP/fields ·
`409` IP already blacklisted (a user cannot list the same IP twice).

### DELETE `/blacklist/<id>` 🔒

Removes one entry by id. `204` on success, `404` if not found.

### DELETE `/blacklist` 🔒

Clears the caller's entire blacklist. `204` on success.

---

## 7. Hardware metrics

Devices push periodic snapshots of their resource usage.

### POST `/hardware-metrics` 🔒

| Field           | Type   | Required |
| --------------- | ------ | :------: |
| `cpu_usage`     | number |    ✔     |
| `ram_used_mb`   | int    |    ✔     |
| `ram_total_mb`  | int    |    ✔     |
| `battery_level` | number |          |

```bash
curl -X POST "$BASE/hardware-metrics" -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"cpu_usage":42.5,"ram_used_mb":4096,"ram_total_mb":8192,"battery_level":76}'
```

Response `201`: `{ "message": "Hardware metric saved", "id": 501 }`.

### GET `/hardware-metrics` 🔒

Returns history, newest first. Optional `from_date` / `to_date` query params
(ISO-8601) filter by `recorded_at`.

```bash
curl "$BASE/hardware-metrics?from_date=2026-07-01T00:00:00" \
  -H "Authorization: Bearer $ACCESS"
```

---

## 8. Firewall logs (REST)

The REST write path is kept for tooling and back-compat; the mobile app writes via the
[WebSocket](#9-firewall-logs-websocket-real-time). Both share the same validation and
post-processing (auto-blacklist).

### The log object (wire contract)

| Field              | Type   | Notes                                                   |
| ------------------ | ------ | ------------------------------------------------------- |
| `action`           | string | **required** — `blocked` \| `warned` \| `allowed`       |
| `src_ip`           | string | valid IP when present                                   |
| `dst_ip`           | string | valid IP when present                                   |
| `src_port`         | int    |                                                         |
| `dst_port`         | int    |                                                         |
| `protocol`         | int    | one of `0` (other), `1` (ICMP), `6` (TCP), `17` (UDP)   |
| `size_bytes`       | int    |                                                         |
| `duration`         | number | flow duration (seconds)                                 |
| `fwd_pkts`         | int    | forward-direction packet count                          |
| `bwd_pkts`         | int    | backward-direction packet count                         |
| `fwd_rate`         | number | forward packet rate (packets/sec)                       |
| `selected_model`   | string | ≤ 100 chars                                             |
| `selected_score`   | number | range `0–1`                                             |
| `all_model_scores` | object | `{ "BF_v1": 0.92, "DoS_Hulk": 0.12 }`; each value `0–1` |
| `threat_type`      | string | ≤ 50 chars                                              |
| `service_name`     | string | ≤ 100 chars                                             |
| `app_name`         | string | ≤ 100 chars                                             |
| `app_package`      | string | ≤ 200 chars                                             |
| `is_system`        | bool   | default `false`                                         |
| `created_at`       | string | device ISO-8601 timestamp (falls back to server time)   |

Over-long strings are trimmed/truncated rather than rejected. Invalid enum values
(`action`, `protocol`), out-of-range scores, and malformed IPs are rejected with `400`.

### POST `/firewall-logs` 🔒

Creates a single log.

```bash
curl -X POST "$BASE/firewall-logs" -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
        "src_ip":"185.220.101.5","dst_ip":"10.0.0.4",
        "src_port":52341,"dst_port":443,"protocol":6,"size_bytes":1460,
        "duration":0.734,"fwd_pkts":12,"bwd_pkts":9,"fwd_rate":16.35,
        "selected_model":"BF_v1","selected_score":0.92,
        "all_model_scores":{"BF_v1":0.92,"DoS_Hulk":0.12},
        "action":"blocked","threat_type":"brute_force",
        "created_at":"2026-07-06T14:23:01.000Z"
      }'
```

Response `201`: `{ "message": "Firewall log saved", "id": 90211 }`. A `blocked` log with a
`src_ip` triggers auto-blacklisting (see below).

### GET `/firewall-logs` 🔒

Paginated, filterable, newest first. Every row includes `id`, `created_at`, and
`received_at`.

| Query param    | Description                          |
| -------------- | ------------------------------------ |
| `limit`        | page size, `1–1000` (default `200`)  |
| `offset`       | rows to skip (default `0`)           |
| `action`       | filter by action                     |
| `threat_type`  | filter by threat type                |
| `service_name` | filter by service                    |
| `app_name`     | filter by app                        |
| `from_date`    | ISO-8601 lower bound on `created_at` |
| `to_date`      | ISO-8601 upper bound on `created_at` |

```bash
curl "$BASE/firewall-logs?action=blocked&limit=50" \
  -H "Authorization: Bearer $ACCESS"
```

---

## 9. Firewall logs (WebSocket, real-time)

The primary ingestion path. Raw WebSocket JSON (not Socket.IO).

```
wss://<host>/ws/logs?token=<access_jwt>
```

The JWT is validated **on the handshake** from the `token` query param or the
`Authorization: Bearer` header. A missing/invalid/expired token closes the socket with
code **1008**.

### Client → server messages

```jsonc
// Submit a batch of 1–100 log objects (see §8 for the log shape)
{ "type": "log_batch", "logs": [ { "action": "blocked", "src_ip": "185.220.101.5", ... } ] }

// Keepalive — the client sends this every ~25s
{ "type": "ping" }
```

### Server → client messages

```jsonc
{ "type": "ack", "count": 3, "ids": [90211, 90212, 90213] }   // batch persisted
{ "type": "pong" }                                            // reply to ping

// Emitted when a blocked src_ip is auto-blacklisted
{ "type": "blacklist_update", "action": "added", "ip": "185.220.101.5",
  "reason": "brute_force", "bf_score": 0.92, "dos_score": 0.03 }

// Errors — code ∈ batch_too_large | invalid_log | rate_limited | token_expired | server_error
{ "type": "error", "code": "invalid_log", "message": "action must be one of blocked|warned|allowed" }
```

### Limits & behavior

- **Rate limit:** 5 `log_batch` messages per second per connection. Exceeding it sends
  `rate_limited` and closes with **1008**.
- **Batch size:** max 100 logs per batch (`batch_too_large`; connection stays open).
- **Message size:** max 128 KB per frame (closes with **1009**).
- **Per batch:** every log is validated → bulk-inserted in one transaction → ids
  assigned → blocked source IPs auto-blacklisted (broadcast to the user's live sockets)
  → ambiguous logs (`warn_threshold < selected_score ≤ block_threshold`) queued for
  review → commit → `ack` sent. If any log fails validation the **whole batch** is
  rejected.
- **Token expiry mid-session:** server sends `{"type":"error","code":"token_expired"}`
  and closes; the client should refresh its token and reconnect with backoff.
- **Idle timeout:** ~5 minutes with no message closes the socket with **1000** (a live
  client's 25s pings keep it open).

### Minimal browser client

```js
const ws = new WebSocket(
  `wss://api.sentri-security.cloud/ws/logs?token=${accessToken}`
);

ws.onopen = () => {
  ws.send(
    JSON.stringify({
      type: "log_batch",
      logs: [
        {
          action: "blocked",
          src_ip: "185.220.101.5",
          protocol: 6,
          selected_score: 0.92,
          created_at: new Date().toISOString(),
        },
      ],
    })
  );
};

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.type === "error" && msg.code === "token_expired") {
    // refresh the access token, then reconnect
  }
};

// keepalive
setInterval(() => ws.send(JSON.stringify({ type: "ping" })), 25000);
```

---

## 10. AI assistant (SSE chat)

A stateless security assistant. Each request is answered on its own with **no
conversation memory**. Powered by Groq (`llama-3.3-70b-versatile`) via LangChain.

### GET `/api/mobile_chat` 🔒

| Query param | Required | Description                                                |
| ----------- | :------: | ---------------------------------------------------------- |
| `prompt`    |    ✔     | The user's message.                                        |
| `token`     |          | JWT, for `EventSource` clients that cannot set the header. |

Returns a `text/event-stream`. Because JavaScript's `EventSource` cannot set an
`Authorization` header, pass the token in the query string:

```js
const es = new EventSource(
  `${BASE}/api/mobile_chat?prompt=${encodeURIComponent(
    "Is 185.220.101.5 dangerous?"
  )}` + `&token=${accessToken}`
);

es.addEventListener("init", (e) => console.log("started"));
es.addEventListener("message", (e) => process(JSON.parse(e.data).token)); // streamed tokens
es.addEventListener("end", (e) => {
  console.log(JSON.parse(e.data).response);
  es.close();
});
es.addEventListener("error", (e) => es.close());
```

**Event frames**

| Event     | Data                                           | Meaning                         |
| --------- | ---------------------------------------------- | ------------------------------- |
| `init`    | `{ "status": "started" }`                      | Stream opened.                  |
| `message` | `{ "token": "...partial text..." }`            | A chunk of the reply (batched). |
| `end`     | `{ "status": "completed", "response": "..." }` | Final full reply.               |
| `error`   | `{ "message": "..." }`                         | Streaming failure.              |

Errors: `400` empty prompt · `401` missing/invalid JWT · `500` if `GROQ_API_KEY` is not
configured or the upstream call fails.

Quick test with curl:

```bash
curl -N "$BASE/api/mobile_chat?prompt=hello&token=$ACCESS"
```

---

## 11. Error format & status codes

Errors are JSON with an `error` message:

```json
{ "error": "Invalid credentials" }
```

WebSocket errors use the frame `{ "type": "error", "code": "...", "message": "..." }`.

| Status | Meaning                                                |
| ------ | ------------------------------------------------------ |
| `200`  | OK.                                                    |
| `201`  | Created.                                               |
| `204`  | Success, no content (logout, deletes).                 |
| `400`  | Invalid input / validation error.                      |
| `401`  | Missing, invalid, or expired token; wrong credentials. |
| `403`  | Forbidden (e.g. admin-only route).                     |
| `404`  | Resource not found.                                    |
| `409`  | Conflict (duplicate email/username/IP).                |
| `500`  | Server error.                                          |

| WS close code | Meaning                                       |
| ------------- | --------------------------------------------- |
| `1000`        | Normal close (idle timeout).                  |
| `1008`        | Policy violation (auth failure / rate limit). |
| `1009`        | Message too big (> 128 KB).                   |

---

## 12. Troubleshooting

**`401 Unauthorized` on a protected call.** The access token is missing, malformed, or
expired (access tokens last 1 week). Obtain a new one via `POST /auth/refresh` using your
refresh token.

**WebSocket closes immediately with 1008.** The handshake token is missing/invalid.
Ensure the URL includes `?token=<access_jwt>` (or send the `Authorization` header for a
native client).

**WebSocket closes with 1008 while streaming.** You exceeded the 5 batches/sec rate
limit. Throttle client sends, or aggregate more logs per `log_batch` (up to 100).

**Whole batch rejected with `invalid_log`.** One log in the batch failed validation — the
batch is atomic. Check `action` (`blocked|warned|allowed`), `protocol` (`0|1|6|17`),
`selected_score` in `0–1`, and that any IPs are valid.

**Chat returns `500`.** `GROQ_API_KEY` is not set in the environment. Add it to your
`.env` / deployment config (see [README → Configuration](README.md#configuration)).

**Browser warns about the certificate in local dev.** The dev server (`run.py`) uses an
ad-hoc self-signed certificate. This is expected — accept it, or run via Docker
(plain HTTP on `localhost:8000`).

**`postgres://` connection fails.** SQLAlchemy 2 requires the `postgresql://` scheme;
the app normalizes `postgres://` automatically, but verify `DATABASE_URL` is otherwise
correct and the database is reachable.
