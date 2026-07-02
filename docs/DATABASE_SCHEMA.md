# Database Schema

Reference for tables that aren't obvious from the models alone. See
`app/models.py` for the full ORM definitions and `migrations/versions/` for the
migration history.

## `firewall_logs`

Real-time firewall-log write path. The columns map **1:1** to the wire contract
emitted by the Flutter client (`lib/core/websocket/firewall_log_ws_service.dart`,
`TrafficBloc._toLogJson`) over `wss://<host>/ws/logs`, plus the server-owned
`id` / `user_id` / `received_at`. Rows are written by the WebSocket `log_batch`
handler (and the REST `POST /firewall-logs` compatibility endpoint) and read
back through `GET /firewall-logs`.

```sql
CREATE TABLE firewall_logs (
    id                BIGSERIAL PRIMARY KEY,
    user_id           INTEGER NOT NULL REFERENCES users(id),
    src_ip            VARCHAR(45),
    src_port          INTEGER,
    dst_port          INTEGER,
    protocol          SMALLINT,              -- 0/1/6/17 (other/ICMP/TCP/UDP)
    size_bytes        INTEGER,
    selected_model    VARCHAR(100),
    selected_score    REAL,                  -- [0,1]
    all_model_scores  JSONB,                 -- {"BF_v1":0.92,"DoS_Hulk":0.12}
    action            VARCHAR(10) NOT NULL,  -- blocked|warned|allowed
    threat_type       VARCHAR(50),
    service_name      VARCHAR(100),
    app_name          VARCHAR(100),
    app_package       VARCHAR(200),
    is_system         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL,  -- device clock (from payload)
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_fwlogs_user_created ON firewall_logs (user_id, created_at DESC);
CREATE INDEX ix_fwlogs_user_action  ON firewall_logs (user_id, action);
```

Notes:

- `created_at` is the **device** timestamp taken from the payload (trusted for
  ordering); `received_at` is the server's own `now()` at insert time.
- No `dst_ip` column — the client never sends one (by design).
- `id` and `created_at` are always present in the `GET /firewall-logs` response
  because the client's `FirewallLog.fromJson` requires them.

## WebSocket protocol — `wss://<host>/ws/logs?token=<access_jwt>`

Implemented in `app/routes/firewall_logs.py`. Raw WebSocket JSON (not
Socket.IO). The JWT is validated on the handshake from the `token` query param
or the `Authorization: Bearer` header; a bad/expired token closes with **1008**.

**Client → server**

- `{"type":"log_batch","logs":[ {<log>}, ... ]}` — 1..100 log objects.
- `{"type":"ping"}` — keepalive (client sends every 25s).

**Server → client**

- `{"type":"ack","count":N,"ids":[...]}` — after a batch is persisted.
- `{"type":"pong"}` — reply to ping.
- `{"type":"blacklist_update","action":"added","ip":...,"reason":...,"bf_score":...,"dos_score":...}`
  — when a blocked `src_ip` is auto-blacklisted.
- `{"type":"error","code":...,"message":...}` — `code` ∈
  `batch_too_large | invalid_log | rate_limited | token_expired | server_error`.

**Limits / behavior**

- Rate limit: 5 `log_batch`/sec per connection (else `rate_limited` + close 1008).
- Batch > 100 logs → `batch_too_large` (batch skipped, connection stays open).
- Message > 128 KB → close 1009.
- Each batch: validate every log → bulk INSERT in one transaction → assign ids →
  auto-blacklist blocked source IPs → optionally queue ambiguous logs into
  `unknown_events` (status `pending`) when
  `warn_threshold < selected_score <= block_threshold` → commit → send `ack`.
- Mid-session token expiry → `{"type":"error","code":"token_expired"}` + close;
  the client refreshes its token and reconnects with backoff.
- Idle > ~5 min with no message → close 1000 (a live client pings every 25s).
