# HTTPS & SSL Deployment — Sentri Backend

## Overview

The Sentri backend runs as a Dockerized Flask/gunicorn application listening on plain HTTP (`127.0.0.1:8000`). Public HTTPS access is provided by an **nginx reverse proxy installed on the Linode host**, which terminates TLS and forwards traffic to the container. SSL certificates are issued and renewed automatically by **Let's Encrypt via certbot**.

## Architecture

```
Client ──HTTPS/WSS :443──► nginx (Linode host, Let's Encrypt cert) ──HTTP :8000──► gunicorn (Docker container)
```

- **Domain:** `api.sentri-security.cloud`
- **Certificate Authority:** Let's Encrypt (free, auto-renewing)
- **Challenge method:** HTTP-01 (webroot at `/var/www/certbot`)
- **TLS:** TLS 1.2 / 1.3, HTTP/2, HSTS enabled
- **WebSocket:** proxy configured for `wss://` upgrades (`/firewall-logs/ws`)

## Deployment Procedure

The entire process was automated in a single idempotent provisioning script (`setup-ssl.sh`), run once as root on the Linode server after the application stack was up (`make up`). The script executed the following stages:

1. **Prerequisite validation** — confirmed root access, an apt-based OS, the app responding on `127.0.0.1:8000`, DNS resolution to the server, and that ports 80/443 were free.
2. **Package installation** — installed `nginx` and `certbot`.
3. **ACME preparation** — created the certbot webroot and an nginx WebSocket upgrade map.
4. **Temporary HTTP config** — deployed an HTTP-only nginx site to serve the ACME challenge and proxy the app.
5. **Certificate issuance** — obtained the Let's Encrypt certificate non-interactively via the webroot method.
6. **Full TLS config** — swapped in the production nginx configuration: HTTP→HTTPS 301 redirect, TLS termination on 443, HSTS, and WebSocket-aware proxying to the backend.
7. **End-to-end validation** — verified trusted HTTPS access, the HTTP→HTTPS redirect, and WebSocket routing.
8. **Auto-renewal** — enabled the certbot systemd timer plus an nginx reload hook so certificates renew and reload automatically.

## Infrastructure Notes (Linode)

- A DNS **A record** for `api.sentri-security.cloud` points to the Linode's public IP.
- The **Linode Cloud Firewall** allows inbound ports **80** (ACME challenge/redirect) and **443** (HTTPS).
- Certificate renewal is fully automatic; it can be tested with `sudo certbot renew --dry-run`.

## Result

| Endpoint     | URL                                                            |
| ------------ | -------------------------------------------------------------- |
| API root     | `https://api.sentri-security.cloud/`                           |
| Swagger docs | `https://api.sentri-security.cloud/apidocs/`                   |
| WebSocket    | `wss://api.sentri-security.cloud/firewall-logs/ws?token=<JWT>` |

The backend is served over HTTPS with a valid, auto-renewing certificate, and all HTTP traffic is redirected to HTTPS.
