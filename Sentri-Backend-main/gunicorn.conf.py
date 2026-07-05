# Gunicorn production config for the Sentri / Neural Firewall backend.
# Run with:  gunicorn -c gunicorn.conf.py run:app
#
# Flask-Sock WebSockets require an async worker; "gevent" is used so a single
# worker can hold many concurrent WebSocket connections without blocking.

import multiprocessing
import os

# Bind to the port the platform assigns. DigitalOcean App Platform sets $PORT
# (default 8080) and requires binding on 0.0.0.0. On a Droplet behind nginx
# this still works (nginx proxies to it; the firewall blocks the port publicly).
bind = "0.0.0.0:" + os.getenv("PORT", "8080")

# gevent is required for the /ws/logs WebSocket endpoint to work.
worker_class = "gevent"

# Each connection lives on one worker (no cross-worker shared state in the WS
# handler), so scaling workers horizontally is safe.
workers = multiprocessing.cpu_count() * 2 + 1

# Max simultaneous greenlets (connections) per worker.
worker_connections = 1000

# Recycle workers periodically to guard against slow memory leaks.
max_requests = 1000
max_requests_jitter = 100

# WebSockets can be idle for a long time; keep the worker from being killed.
timeout = 120
graceful_timeout = 30
keepalive = 5

# Log to stdout/stderr so systemd/journalctl captures everything.
accesslog = "-"
errorlog = "-"
loglevel = "info"
