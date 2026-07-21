# NOVA Dashboard

> Admin-facing Security Operations Center (SOC) dashboard for the **Sentri / NOVA** firewall ecosystem.

NOVA Dashboard is a Flask web application that gives administrators a single pane of glass over a fleet of Sentri firewall devices. It reads telemetry from a shared, remotely deployed PostgreSQL database, visualizes firewall logs and ML threat scores, renders a live 3D network topology, and uses a locally running **Ollama** LLM to provide AI-assisted security analysis and streaming chat.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Creating an Admin User](#creating-an-admin-user)
- [Running the App](#running-the-app)
- [API Reference](#api-reference)
- [Database Models](#database-models)
- [AI / Ollama Integration](#ai--ollama-integration)
- [Notes & Caveats](#notes--caveats)
- [License](#license)

---

## Features

- **Secure Admin Login** — JWT-based authentication (Flask-JWT-Extended + bcrypt). Only users with `is_admin = true` can access the dashboard.
- **System Dashboard** — Recent firewall logs, threat trend charts (Chart.js), and one-click AI log analysis.
- **User Access Profiles** — Per-user firewall logs, charts, hardware telemetry (CPU/RAM/battery), and a user-scoped AI chatbot.
- **3D Network Topology** — Interactive fleet visualization built with Three.js, driven by the latest hardware metrics and traffic data, with AI node analysis.
- **Unknown Events Triage** — Review ambiguous ML detections that fall between "warn" and "block", analyze them individually or in batches with AI, and blacklist IPs (per-user or globally).
- **Streaming AI Chatbots** — Server-Sent Events (SSE) chat powered by a local Ollama model via LangChain.
- **Health Check** — `GET /health` endpoint for uptime monitoring.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3, [Flask 3.1](https://flask.palletsprojects.com/) |
| Auth | Flask-JWT-Extended, bcrypt, DB-backed refresh-token revocation |
| ORM / DB | SQLAlchemy 2 + Flask-SQLAlchemy, PostgreSQL (`psycopg2-binary`) |
| Frontend | Server-rendered Jinja2 templates + vanilla JavaScript |
| Charts | Chart.js (CDN) |
| 3D Topology | Three.js + OrbitControls (CDN) |
| AI / LLM | Local Ollama via `langchain-ollama`, `langchain-core`, `langchain-community` |
| Config | `python-dotenv` |
| CORS | `flask-cors` |

> There is **no** Node build step — templates are rendered directly by Flask, and browser libraries are loaded via CDN.

---

## Architecture

```
┌─────────────────┐        ┌──────────────────────┐        ┌────────────────────┐
│  Admin Browser  │ <────> │   NOVA Dashboard      │ <────> │  Remote PostgreSQL │
│ (Jinja + JS UI) │  HTTP  │   (Flask, this repo)  │  SQL   │  (Linode, sentridb)│
└─────────────────┘        └──────────┬───────────┘        └────────────────────┘
                                       │
                                       │ HTTP (localhost:11434)
                                       ▼
                              ┌──────────────────┐
                              │  Local Ollama     │
                              │  (llama3.1:8b)    │
                              └──────────────────┘
```

- The **database schema is owned externally** (the Sentri backend that mobile clients write to). This app **mirrors** the schema in `app/models.py` and does **not** run migrations.
- The **Ollama** service runs locally on the operator's machine and is only required for AI endpoints.

---

## Project Structure

```
nova_dashboard/
├── app/                        # Flask application package
│   ├── __init__.py             # create_app() factory, blueprint registration, /health
│   ├── models.py               # SQLAlchemy models (mirror of remote schema)
│   ├── routes/                 # HTTP blueprints (pages, auth, dashboard API, chat/AI)
│   ├── services/               # Data/query layer (dashboard_data.py)
│   └── utils/                  # Decorators, LLM prompt templates, SSE helpers
├── templates/                  # Jinja2 pages & partials
│   ├── main_page/              # Dashboard tables, charts, chatbot
│   └── user_page/              # Per-user tables, charts, chatbot, hardware
├── static/js/                  # auth.js, config.js (client-side JWT/session helpers)
├── scripts/                    # Admin & DB utility scripts (create_admin, test_db, ...)
├── config.py                   # Runtime configuration (loads .env)
├── run.py                      # Application entry point
├── run_dashboard.bat           # Windows launcher
├── requirements.txt            # Python dependencies
├── .env.example                # Environment template (copy to .env)
└── .gitignore
```

---

## Prerequisites

- **Python 3.10+** and `pip`
- Access to the **remote PostgreSQL** database (a valid `DATABASE_URL`)
- *(Optional, for AI features)* [**Ollama**](https://ollama.com/) installed and running locally with a pulled model:

```bash
ollama pull llama3.1:8b
ollama serve
```

> If Ollama is not running, the app still works — but AI/chat endpoints will return a `503`.

---

## Installation

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd nova_dashboard

# 2. Create and activate a virtual environment
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your environment file
copy .env.example .env      # Windows
# cp .env.example .env       # macOS / Linux
```

---

## Configuration

Edit the `.env` file with your real values. **Never commit `.env`** — it is gitignored.

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret | *(required)* |
| `JWT_SECRET_KEY` | Secret used to sign JWTs | *(required)* |
| `DATABASE_URL` | PostgreSQL connection URL (`postgres://` is auto-normalized to `postgresql://`) | *(required)* |
| `OLLAMA_BASE_URL` | Base URL of the local Ollama server | `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | Ollama model name to use | `llama3.1:8b` |
| `PORT` | Port the dashboard listens on | `5000` |

Generate strong secrets with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Example `.env`:

```env
SECRET_KEY=your_generated_secret
JWT_SECRET_KEY=your_generated_jwt_secret
DATABASE_URL=postgresql://dbuser:YOUR_PASSWORD@YOUR_HOST:5432/sentridb
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.1:8b
PORT=5000
```

**JWT notes:** access tokens expire after **1 week** and are accepted via the `Authorization` header or a `?token=` query string (used for SSE chat streams).

---

## Creating an Admin User

The dashboard requires an account with `is_admin = true`. Use the bundled script:

```bash
python scripts/create_admin.py --email you@example.com --username admin --password yourpassword
```

On Windows you can also use the env-aware wrapper:

```bat
scripts\run_with_env.bat create-admin --email you@example.com --username admin --password yourpassword
```

Verify database connectivity at any time:

```bash
python scripts/test_db_connection.py
```

---

## Running the App

```bash
python run.py
```

Or, on Windows, double-click / run:

```bat
run_dashboard.bat
```

- Server binds to `0.0.0.0` on the configured `PORT` (default **5000**).
- Open [http://127.0.0.1:5000](http://127.0.0.1:5000) — you'll be redirected to `/login`.

> `run.py` enables `debug=True`. Disable debug mode before any production deployment.

---

## API Reference

### Page Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Redirects to `/login` |
| GET | `/login` | Login page |
| GET | `/dashboard` | System dashboard |
| GET | `/users` | User access profiles list |
| GET | `/user-profile/<user_id>` | Individual user profile |
| GET | `/topology` | 3D network topology |
| GET | `/unknown-events` | Unknown events triage |

### Authentication (`/auth`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create a user + default settings, returns tokens |
| POST | `/auth/login` | Authenticate, returns tokens + `is_admin` |
| GET | `/auth/me` | Current user (JWT required) |
| POST | `/auth/refresh` | Issue new access token (refresh JWT required) |
| POST | `/auth/logout` | Revoke refresh token |

### Dashboard API (`/dashboard/api`, admin + JWT)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard/api/logs` | Recent firewall logs |
| GET | `/dashboard/api/logs/user/<user_id>` | Logs for a user |
| GET | `/dashboard/api/chart-data` | Aggregated chart data |
| GET | `/dashboard/api/users-list` | List of users |
| GET | `/dashboard/api/hardware/<user_id>` | Hardware metrics for a user |
| GET | `/dashboard/api/fleet` | Fleet data for topology |
| GET | `/dashboard/api/unknown-events/users` | Users with unknown events |
| GET | `/dashboard/api/unknown-events/user/<user_id>` | Unknown events for a user |
| POST | `/dashboard/api/unknown-events/blacklist` | Blacklist an IP (user or global scope) |

### Chat / AI (admin + JWT)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/dashboard/api/nova/analyze` | Fleet node LLM insight |
| POST | `/api/analyze-log/<log_id>` | Analyze a dashboard log |
| POST | `/api/analyze_user_log/<log_id>` | Analyze a user log |
| GET | `/api/chat-bot` | SSE streaming chatbot |
| GET | `/api/chat-user/<user_id>` | SSE user-scoped chatbot |
| POST | `/api/analyze-unknown-event/<event_id>` | Analyze one unknown event |
| POST | `/dashboard/api/unknown-events/analyze/<user_id>` | Batch-analyze unknown events |

### Misc

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Returns `{"message": "NOVA Dashboard Running"}` |

---

## Database Models

Defined in `app/models.py` (mirror of the externally owned schema):

| Table | Model | Role |
|-------|-------|------|
| `users` | `User` | Accounts; `is_admin` gates dashboard access |
| `refresh_tokens` | `RefreshToken` | JWT refresh token JTIs + revocation |
| `blacklist_entries` | `BlacklistEntry` | Blocked IPs + optional model scores (JSONB) |
| `unknown_events` | `UnknownEvent` | Ambiguous threats between warn/block |
| `user_settings` | `UserSettings` | Thresholds, flood detection, model toggles |
| `hardware_metrics` | `HardwareMetric` | CPU / RAM / battery telemetry |
| `firewall_logs` | `FirewallLog` | Main traffic & threat logs |

Threat detection categories represented in settings/scores include brute force, DoS, Hulk, LOIC, and HOIC.

---

## AI / Ollama Integration

- AI features are powered by a **locally running Ollama** instance accessed through LangChain.
- Configure the endpoint and model with `OLLAMA_BASE_URL` and `OLLAMA_MODEL`.
- Prompt templates live in `app/utils/prompts.py`.
- Chatbots stream responses via **Server-Sent Events (SSE)**; because browsers can't set custom headers on `EventSource`, the JWT is passed as a `?token=` query parameter.
- If Ollama is unreachable, AI endpoints fail gracefully with a `503`.

---

## Notes & Caveats

- **No migrations here.** The database schema is owned by the separate Sentri backend. If tables change upstream, update `app/models.py` to match.
- **Admin-only UI.** Non-admin accounts are rejected at login (client- and server-side).
- **Debug mode is on** in `run.py` — turn it off and use a production WSGI server (e.g. Gunicorn/Waitress) before deploying.
- **Secrets:** keep `.env` out of version control; only `.env.example` should be committed.
- `run_dashboard.bat` may reference a machine-specific Python/Anaconda path — adjust it to your environment.

---

## License

This project was developed as a Final Year Project (FYP). Add your preferred license here (e.g. MIT) before publishing publicly.
