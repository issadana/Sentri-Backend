#!/bin/sh
# Runs before the app starts: waits for Postgres, applies Alembic migrations,
# then hands control to the CMD (gunicorn). `exec` makes gunicorn PID 1 so it
# receives shutdown signals for a clean exit.
set -e

echo "[entrypoint] Applying database migrations (flask db upgrade)..."
flask db upgrade

echo "[entrypoint] Migrations complete. Starting gunicorn..."
exec "$@"
