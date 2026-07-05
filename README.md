# Sentri — Neural Firewall Backend

Sentri is the backend service for the **Neural Firewall** — an AI-assisted, on-device
firewall companion. It ingests real-time firewall traffic decisions from mobile clients,
persists them, auto-blacklists malicious source IPs, exposes device hardware telemetry,
manages per-user detection settings, and streams an AI security assistant over
Server-Sent Events.

The service is a **Flask** application backed by **PostgreSQL**, secured with **JWT**
authentication, and served in production by **gunicorn (gevent)** behind an **nginx**
TLS reverse proxy.

- **Live API:** `https://api.sentri-security.cloud/`
- **Interactive API docs (Swagger):** `https://api.sentri-security.cloud/apidocs/`
- **WebSocket log stream:** `wss://api.sentri-security.cloud/ws/logs?token=<JWT>`

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Quick start (Docker)](#quick-start-docker)
- [Local development (without Docker)](#local-development-without-docker)
- [Configuration](#configuration)
- [Database migrations](#database-migrations)
- [API overview](#api-overview)
- [Project layout](#project-layout)
- [Deployment](#deployment)
- [Further documentation](#further-documentation)

---

## Features

- **JWT authentication** — register / login / refresh / logout with access + refresh
  tokens; refresh tokens are tracked server-side and can be revoked.
- **Real-time firewall log ingestion** over a raw WebSocket (`/ws/logs`) with batching,
  per-connection rate limiting, message-size caps, and mid-session token-expiry handling.
- **Automatic IP blacklisting** — any source IP that produces a `blocked` decision is
  auto-added to the user's blacklist, and connected clients are notified live.
- **Per-user detection settings** — block/warn thresholds, flood & SYN-flood detection,
  per-model toggles, and log-retention preferences.
- **Hardware telemetry** — devices push CPU, RAM, and battery snapshots for history and
  charting.
- **AI security assistant** — a stateless chatbot streamed over Server-Sent Events,
  powered by Groq (`llama-3.3-70b-versatile`) via LangChain.
- **Self-documenting API** — Swagger UI is generated automatically at `/apidocs/`.
- **Container-first** — one-command startup with Docker Compose; migrations run
  automatically on boot.

---

## Architecture

```
                       ┌──────────────────────────────────────────┐
   Mobile client       │              Sentri Backend              │
  (Flutter app)        │                                          │
        │  REST / JWT   │   Flask app (app/)                       │
        ├──────────────►│   ├─ /auth        JWT auth               │
        │               │   ├─ /users       profile                │
        │  WebSocket    │   ├─ /blacklist   IP blacklist           │
        ├──────────────►│   ├─ /settings    detection config       │
        │  /ws/logs     │   ├─ /hardware-metrics  telemetry        │
        │               │   ├─ /firewall-logs     REST + WS ingest │
        │  SSE          │   └─ /api/mobile_chat    AI assistant     │
        └──────────────►│                                          │
                        │   gunicorn (gevent)  ──►  PostgreSQL      │
                        └──────────────────────────────────────────┘

  Production:  Client ──HTTPS/WSS :443──► nginx (Let's Encrypt) ──HTTP :8000──► gunicorn
```

---

## Tech stack

| Layer            | Technology                                            |
| ---------------- | ----------------------------------------------------- |
| Language         | Python 3.12                                           |
| Web framework    | Flask 3                                               |
| ORM / migrations | SQLAlchemy 2 + Flask-Migrate (Alembic)                |
| Database         | PostgreSQL 16                                          |
| Auth             | Flask-JWT-Extended (bcrypt password hashing)          |
| WebSockets       | Flask-Sock (raw WS)                                    |
| AI / streaming   | LangChain + Groq (SSE)                                 |
| API docs         | Flasgger (Swagger UI)                                  |
| Prod server      | gunicorn + gevent                                     |
| Packaging        | Docker + Docker Compose                               |

---

## Quick start (Docker)

The fastest way to run the entire stack (app + PostgreSQL) locally. **Docker must be
running.**

```bash
# 1. Clone
git clone <your-repo-url> Sentri-Backend
cd Sentri-Backend

# 2. (Optional) create a .env for real secrets — see Configuration below.
#    Without it, the compose file uses safe dev defaults.
cp .env.example .env      # then edit values

# 3. Build and start everything in the background
make up                    # == docker compose up -d --build
```

That's it. The app applies database migrations automatically on boot, then starts serving:

- API root: <http://localhost:8000/>
- Swagger UI: <http://localhost:8000/apidocs/>
- WebSocket: `ws://localhost:8000/ws/logs?token=<JWT>`

### Handy Make targets

```bash
make up        # build + start all services (detached)
make logs      # tail live logs
make ps        # show container status
make migrate   # run DB migrations manually
make db-shell  # open a psql shell in the Postgres container
make stop      # stop containers (data kept)
make down      # stop + remove containers (DB volume kept)
make clean     # stop + remove containers AND the DB volume (DESTRUCTIVE)
```

Run `make` (or `make help`) at any time to list all targets.

---

## Local development (without Docker)

Use this when you want to run Flask directly against a local PostgreSQL instance.

### Prerequisites

- Python 3.12+
- PostgreSQL 16 (running locally, with a database created)

### Steps

```bash
# 1. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate           # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
#    Edit .env — set DATABASE_URL to your local Postgres, plus the secrets below.

# 4. Apply database migrations
export FLASK_APP=run.py
flask db upgrade

# 5. Run the development server
python run.py
```

The dev server (`run.py`) binds to `0.0.0.0:8000` with an **ad-hoc HTTPS certificate**
(so `https://localhost:8000/`), which lets physical devices on your LAN reach it. Your
browser will warn about the self-signed cert — that is expected in development.

> **Port note:** port `8000` is used instead of `5000` to avoid the macOS AirPlay
> Receiver, which holds port 5000.

---

## Configuration

Configuration is read from environment variables (loaded from a `.env` file via
`python-dotenv`). See [`.env.example`](.env.example) for a template.

| Variable         | Required | Description                                                                 |
| ---------------- | :------: | --------------------------------------------------------------------------- |
| `DATABASE_URL`   |   Yes    | PostgreSQL connection string. `postgres://` URLs are auto-normalized to `postgresql://`. |
| `SECRET_KEY`     |   Yes    | Flask session/signing secret.                                               |
| `JWT_SECRET_KEY` |   Yes    | Secret used to sign JWT access/refresh tokens.                              |
| `GROQ_API_KEY`   | For chat | Groq API key for the SSE assistant (`/api/mobile_chat`). Get one at <https://console.groq.com/keys>. |
| `PORT`           |    No    | Port gunicorn binds to in production (default `8080`; compose sets `8000`). |

Generate strong secrets with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

> **Never commit your real `.env`.** It is gitignored. Access tokens live for one week
> by default (see `config.py`).

---

## Database migrations

Migrations are managed with Flask-Migrate (Alembic). In Docker they run automatically via
`entrypoint.sh` before gunicorn starts.

```bash
export FLASK_APP=run.py

flask db upgrade                       # apply all pending migrations
flask db migrate -m "describe change"  # autogenerate a new migration after model edits
flask db downgrade -1                  # roll back the last migration
flask db history                       # view migration history
```

Migration scripts live in [`migrations/versions/`](migrations/versions/).

---

## API overview

All protected endpoints require an `Authorization: Bearer <access_token>` header.
Browser clients that cannot set headers (EventSource, browser WebSockets) may pass the
token as a `?token=<JWT>` query-string parameter instead.

| Method | Path                     | Auth | Description                                     |
| ------ | ------------------------ | :--: | ----------------------------------------------- |
| GET    | `/`                      |  —   | Health check.                                   |
| GET    | `/apidocs/`              |  —   | Swagger UI.                                      |
| POST   | `/auth/register`         |  —   | Create an account; returns tokens.              |
| POST   | `/auth/login`            |  —   | Log in; returns tokens.                         |
| GET    | `/auth/me`               |  ✔   | Current user profile.                           |
| POST   | `/auth/refresh`          |  ✔¹  | Issue a new access token.                       |
| POST   | `/auth/logout`           |  ✔¹  | Revoke the refresh token.                       |
| PUT    | `/users/me`              |  ✔   | Update username / password.                     |
| GET    | `/blacklist`             |  ✔   | List blacklisted IPs.                           |
| POST   | `/blacklist`             |  ✔   | Add an IP to the blacklist.                     |
| DELETE | `/blacklist/<id>`        |  ✔   | Remove one blacklist entry.                     |
| DELETE | `/blacklist`             |  ✔   | Clear the whole blacklist.                      |
| GET    | `/settings`              |  ✔   | Read detection settings.                        |
| PUT    | `/settings`              |  ✔   | Update detection settings.                      |
| POST   | `/hardware-metrics`      |  ✔   | Push a CPU/RAM/battery snapshot.                |
| GET    | `/hardware-metrics`      |  ✔   | Read telemetry history (date-filterable).       |
| POST   | `/firewall-logs`         |  ✔   | Create a single firewall log (REST).            |
| GET    | `/firewall-logs`         |  ✔   | List firewall logs (paginated, filterable).     |
| WS     | `/ws/logs?token=<JWT>`   |  ✔   | Real-time firewall-log batch ingestion.         |
| GET    | `/api/mobile_chat`       |  ✔   | Stream an AI assistant reply over SSE.          |

¹ Requires a **refresh** token, not an access token.

For request/response bodies, message protocols, and worked examples, see the
[**User & Integration Manual**](MANUAL.md).

---

## Project layout

```
Sentri-Backend/
├── app/
│   ├── __init__.py          # App factory: extensions, Swagger, blueprints
│   ├── models.py            # SQLAlchemy models (User, FirewallLog, ...)
│   ├── routes/              # Blueprints (auth, users, blacklist, settings,
│   │                        #   hardware_metrics, firewall_logs, chat)
│   └── utils/               # SSE helper, decorators
├── migrations/              # Alembic migration history
├── docs/                    # Schema + deployment references
├── config.py                # Environment-driven configuration
├── run.py                   # Dev entrypoint (Flask dev server, HTTPS)
├── gunicorn.conf.py         # Production server config (gevent)
├── entrypoint.sh            # Runs migrations, then starts gunicorn
├── Dockerfile               # Container image
├── docker-compose.yml       # App + PostgreSQL stack
├── Makefile                 # Compose helper targets
└── requirements.txt         # Python dependencies
```

---

## Deployment

Production runs the Docker stack on a Linux host behind an **nginx** reverse proxy that
terminates TLS with an auto-renewing **Let's Encrypt** certificate. gunicorn uses the
**gevent** worker class (required for the WebSocket endpoint) and binds to `$PORT`.

Full step-by-step HTTPS/SSL provisioning is documented in
[`docs/deployment-ssl.md`](docs/deployment-ssl.md).

---

## Further documentation

- [**MANUAL.md**](MANUAL.md) — end-to-end usage manual with request/response examples,
  the WebSocket & SSE protocols, and troubleshooting.
- [`docs/DATABASE_SCHEMA.md`](docs/DATABASE_SCHEMA.md) — firewall-log table & WebSocket
  wire contract.
- [`docs/deployment-ssl.md`](docs/deployment-ssl.md) — HTTPS / nginx / certbot setup.
- Swagger UI at `/apidocs/` — live, interactive API reference.
