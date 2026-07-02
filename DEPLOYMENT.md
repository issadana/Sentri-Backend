# Deploying the Sentri Backend to DigitalOcean App Platform

Stack: Flask (app factory in `app/__init__.py`) + Postgres + Flask-Migrate +
Flask-Sock WebSockets, served by **gunicorn (gevent worker)**. App Platform
builds from GitHub, provides HTTPS automatically, and injects the database URL.

---

## 0. One-time local prep (already done in this repo)

- `requirements.txt` — cleaned to UTF-8, includes `gunicorn` + `gevent`.
- `gunicorn.conf.py` — binds `0.0.0.0:$PORT` (App Platform sets `$PORT`) with a
  `gevent` worker (required for the `/firewall-logs/ws` WebSocket).
- `config.py` — reads `DATABASE_URL` from the environment and normalizes a
  `postgres://` scheme to `postgresql://`.
- `.gitignore` — keeps `venv/`, `__pycache__/`, `.env` out of git.

**Rotate the secrets that were committed earlier** (the old `.env` is in git
history and is compromised). Generate new values:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # JWT_SECRET_KEY
```

Commit and push:

```bash
git add -A && git commit -m "Prep for DigitalOcean App Platform deploy"
git push
```

> Do NOT run `pip freeze > requirements.txt` — the committed venv is a Windows
> venv and `python`/`pip` aren't wired up locally. Use the curated
> `requirements.txt` in this repo as-is.

---

## 1. Create the App

1. DigitalOcean dashboard -> **Apps** -> **Create App** -> **GitHub**.
2. Authorize DO, pick the `Sentri-Backend` repo, branch `main`,
   **Autodeploy on push** = on.
3. DO detects Python automatically. It builds with `pip install -r requirements.txt`.

## 2. Set the Run Command

In the web service's settings, set the **Run Command** to:

```
gunicorn -c gunicorn.conf.py run:app
```

App Platform sets `$PORT` (default 8080); `gunicorn.conf.py` binds to it. HTTP
health checks hit `/`, which returns 200 — no extra health-check config needed.

## 3. Add the Database

- In the app, **Create/Attach Resource -> Database -> Postgres** (Dev DB is fine
  to start).
- DO auto-injects a `DATABASE_URL` env var. `config.py` reads it directly — no
  code change. The URL includes `sslmode=require`, which psycopg2 honors.

## 4. Environment Variables (App-level)

Mark the two secrets as **encrypted**:

| Key | Value |
| --- | --- |
| `SECRET_KEY` | your rotated secret |
| `JWT_SECRET_KEY` | your rotated JWT secret |
| `FLASK_APP` | `run.py`  (so the migration command below finds the app) |

`DATABASE_URL` is provided automatically by the attached database — do not set it
by hand.

## 5. Run Database Migrations

Add a **Pre-Deploy Job** (Components -> Create -> Job -> "Before every deploy")
in the same app, sharing the repo, with command:

```
flask db upgrade
```

Ensure the job also has `FLASK_APP=run.py` and access to `DATABASE_URL`
(app-level env vars are inherited). This runs the Alembic migrations against the
managed database before each deploy.

> Alternative: skip the job and run `flask db upgrade` once from the App
> Platform **Console** tab after the first deploy.

## 6. Deploy & Verify

Click **Deploy**. Once live at `https://<app-name>.ondigitalocean.app`:

```bash
curl https://<app-name>.ondigitalocean.app/          # {"message": "Neural Firewall Backend Running"}
# Swagger UI:   https://<app-name>.ondigitalocean.app/apidocs/
# WebSocket:    wss://<app-name>.ondigitalocean.app/firewall-logs/ws?token=<JWT>
```

---

## Updating after a code change

Just push to `main` — autodeploy rebuilds and (if the pre-deploy job is set up)
runs migrations. To roll back, use the **Deployments** tab.

## Notes / gotchas

- **Ephemeral filesystem:** App Platform containers have no persistent local
  disk. This app writes no local files, so nothing is lost on redeploy — keep it
  that way (store everything in Postgres).
- **gevent + psycopg2:** DB calls are blocking under gevent. Fine at low/medium
  load. If WebSockets stall under heavy DB load, add `psycogreen` and patch
  psycopg2, or move DB-heavy work off the request path.
- **CORS** is currently wide open (`CORS(app)` in `app/__init__.py`). Lock it to
  your frontend origin before going public.
- **`run.py` is dev-only** (`debug=True`, self-signed SSL). Production never runs
  it directly — App Platform runs `gunicorn ... run:app`, importing the `app`
  object without calling `app.run()`.
- Logs are in the App Platform **Runtime Logs** tab (gunicorn logs to stdout).
