#!/usr/bin/env bash
#
# setup-ssl.sh — Provision HTTPS for api.sentri-security.cloud in front of the
# dockerized Sentri backend (gunicorn on 127.0.0.1:8000).
#
# What it does, in order, validating each step before continuing:
#   0. Prerequisites: root, apt-based OS, DNS points here, ports 80/443 free,
#      and the app is actually answering on 127.0.0.1:8000.
#   1. Install nginx + certbot.
#   2. Create the ACME webroot.
#   3. Deploy an HTTP-only nginx config (serves the ACME challenge + proxies the app).
#   4. Obtain the Let's Encrypt certificate (webroot method, non-interactive).
#   5. Swap in the full config: HTTP→HTTPS redirect + TLS server block with
#      WebSocket-aware proxying.
#   6. End-to-end checks: HTTPS reaches the app, redirect works, cert is valid,
#      renewal path works.
#   7. Enable auto-renewal (systemd timer + reload-nginx deploy hook).
#
# Usage:
#   sudo ./setup-ssl.sh
#   sudo DOMAIN=api.sentri-security.cloud APP_PORT=8000 CERTBOT_EMAIL=you@x.com ./setup-ssl.sh
#
# Idempotent: safe to re-run; it skips issuance if a valid cert already exists.

set -Eeuo pipefail

# ─────────────────────────── Config (override via env) ────────────────────────
DOMAIN="${DOMAIN:-api.sentri-security.cloud}"
APP_PORT="${APP_PORT:-8000}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-admin@${DOMAIN}}"
WEBROOT="/var/www/certbot"
NGINX_SITE="/etc/nginx/sites-available/${DOMAIN}"
NGINX_ENABLED="/etc/nginx/sites-enabled/${DOMAIN}"
NGINX_DEFAULT="/etc/nginx/sites-enabled/default"
WS_MAP_CONF="/etc/nginx/conf.d/ws-upgrade.conf"
LIVE_DIR="/etc/letsencrypt/live/${DOMAIN}"
RENEW_HOOK="/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh"

# ─────────────────────────── Helpers ──────────────────────────────────────────
if [[ -t 1 ]]; then
    C_RED='\033[31m'; C_GRN='\033[32m'; C_YEL='\033[33m'; C_CYN='\033[36m'; C_RST='\033[0m'
else
    C_RED=''; C_GRN=''; C_YEL=''; C_CYN=''; C_RST=''
fi
log()  { printf "${C_YEL}▶ %s${C_RST}\n" "$*"; }
ok()   { printf "${C_GRN}✓ %s${C_RST}\n" "$*"; }
warn() { printf "${C_YEL}! %s${C_RST}\n" "$*" >&2; }
die()  { printf "${C_RED}✗ %s${C_RST}\n" "$*" >&2; exit 1; }
step() { printf "\n${C_CYN}━━ %s ━━${C_RST}\n" "$*"; }
# Run a command; abort with a message if it fails.
run() { "$@" || die "Command failed: $*"; }

# On any unexpected error, report where.
trap 'die "Aborted at line $LINENO."' ERR

# ─────────────────────────── Step 0: Prerequisites ────────────────────────────
step "Step 0 — Prerequisites"

[[ $EUID -eq 0 ]] || die "Must run as root (try: sudo $0)."

command -v apt-get >/dev/null \
    || die "This script targets Debian/Ubuntu (apt). OS not supported."

command -v curl >/dev/null || run apt-get update -y && run apt-get install -y curl ca-certificates

# 0a. The app must be answering on the configured port — otherwise the proxy
#     would point at nothing. This is the literal "points to our working port" check.
log "Checking app on 127.0.0.1:${APP_PORT} ..."
if curl -fsS --max-time 5 "http://127.0.0.1:${APP_PORT}/" >/dev/null 2>&1; then
    ok "App is responding on 127.0.0.1:${APP_PORT}."
else
    die "Nothing is answering on 127.0.0.1:${APP_PORT}. Start the stack first (e.g. 'make up') and re-run."
fi

# 0b. Ports 80/443 must be free for nginx (or already held by nginx).
log "Checking ports 80/443 ..."
command -v ss >/dev/null || run apt-get install -y iproute2
for port in 80 443; do
    holder="$(ss -ltnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p {print $NF; exit}')"
    if [[ -z "${holder}" ]]; then
        ok "Port ${port} is free."
    elif echo "${holder}" | grep -q nginx; then
        ok "Port ${port} held by nginx (expected on re-run)."
    else
        die "Port ${port} is held by '${holder}'. Stop that service or free the port before continuing."
    fi
done

ok "Prerequisites satisfied."

# ─────────────────────────── Step 1: Install nginx + certbot ──────────────────
step "Step 1 — Install nginx and certbot"
run apt-get update -y
run apt-get install -y nginx certbot
command -v nginx   >/dev/null || die "nginx install failed."
command -v certbot >/dev/null || die "certbot install failed."
ok "nginx $(nginx -v 2>&1 | cut -d/ -f2) and certbot installed."

# ─────────────────────────── Step 2: Webroot + WS map ─────────────────────────
step "Step 2 — Create ACME webroot and WebSocket upgrade map"
run mkdir -p "${WEBROOT}"

# The map must live in http{} context (outside any server block), so it goes in
# conf.d. Required for the /firewall-logs/ws endpoint to upgrade correctly.
run tee "${WS_MAP_CONF}" >/dev/null <<'EOF'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
EOF
run nginx -t
ok "Webroot and WebSocket map in place."

# ─────────────────────────── Step 3: HTTP-only nginx config ───────────────────
step "Step 3 — Deploy HTTP config (ACME challenge + app proxy)"
# Disable the default site so our server_name is authoritative for the domain.
[[ -L "${NGINX_DEFAULT}" ]] && run rm -f "${NGINX_DEFAULT}"

run tee "${NGINX_SITE}" >/dev/null <<EOF
# Provisional HTTP-only config: serves the ACME challenge and proxies the app.
# Replaced by the full TLS config in Step 5 once the cert exists.
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
    }

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
    }
}
EOF

run ln -sf "${NGINX_SITE}" "${NGINX_ENABLED}"
run nginx -t
run systemctl reload nginx
run systemctl is-active --quiet nginx || die "nginx is not active after reload."

# Validate HTTP reachability end-to-end (DNS -> nginx -> app).
if curl -fsS --max-time 10 "http://${DOMAIN}/" >/dev/null 2>&1; then
    ok "http://${DOMAIN}/ proxies to the app."
else
    die "http://${DOMAIN}/ did not return the app. Check firewall (ports 80/443) and DNS propagation."
fi

# ─────────────────────────── Step 4: Obtain certificate ───────────────────────
step "Step 4 — Obtain Let's Encrypt certificate"
if [[ -d "${LIVE_DIR}" && -f "${LIVE_DIR}/fullchain.pem" ]]; then
    warn "Existing cert found at ${LIVE_DIR}; skipping issuance (run 'certbot renew' to refresh)."
else
    log "Requesting cert for ${DOMAIN} (email: ${CERTBOT_EMAIL}) ..."
    run certbot certonly --webroot \
        -w "${WEBROOT}" -d "${DOMAIN}" \
        --email "${CERTBOT_EMAIL}" \
        --agree-tos --no-eff-email --non-interactive
fi

# Validate the cert files and that they cover the domain.
[[ -f "${LIVE_DIR}/fullchain.pem" && -f "${LIVE_DIR}/privkey.pem" ]] \
    || die "Cert files missing under ${LIVE_DIR}."
if openssl x509 -in "${LIVE_DIR}/fullchain.pem" -noout -text 2>/dev/null \
        | grep -q "${DOMAIN}"; then
    expiry="$(openssl x509 -in "${LIVE_DIR}/fullchain.pem" -noout -enddate | cut -d= -f2)"
    ok "Certificate valid for ${DOMAIN}; expires ${expiry}."
else
    die "Certificate does not cover ${DOMAIN}."
fi

# ─────────────────────────── Step 5: Full TLS config ──────────────────────────
step "Step 5 — Deploy full config (HTTP redirect + HTTPS + WebSocket proxy)"
run tee "${NGINX_SITE}" >/dev/null <<EOF
# api.sentri-security.cloud — TLS terminates here, proxied to the app on ${APP_PORT}.

# HTTP: serve ACME challenges (so renewals keep working), redirect all else to HTTPS.
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS: terminate TLS and proxy to gunicorn (WebSocket-aware).
server {
    # http2 on the listen line (not "http2 on;") so this works on nginx < 1.25.1 too.
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     ${LIVE_DIR}/fullchain.pem;
    ssl_certificate_key ${LIVE_DIR}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};

        proxy_http_version 1.1;
        proxy_set_header Upgrade           \$http_upgrade;
        proxy_set_header Connection        \$connection_upgrade;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Match gunicorn's 120s worker timeout so idle WebSockets aren't killed.
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
EOF

run nginx -t
run systemctl reload nginx
run systemctl is-active --quiet nginx || die "nginx is not active after reload."
ok "Full TLS config deployed and nginx reloaded."

# ─────────────────────────── Step 6: End-to-end validation ────────────────────
step "Step 6 — End-to-end validation"

log "HTTPS reachability (system CA must trust the cert) ..."
run curl -fsS --max-time 10 "https://${DOMAIN}/" >/dev/null
ok "https://${DOMAIN}/ returns the app with a trusted certificate."

log "HTTP -> HTTPS redirect ..."
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${DOMAIN}/")"
[[ "${code}" == "301" ]] \
    || die "Expected 301 redirect on http://${DOMAIN}/, got ${code}."
ok "http://${DOMAIN}/ redirects to HTTPS (301)."

log "WebSocket upgrade path reaches the app ..."
# We can't complete a WS handshake without a valid JWT, but we CAN confirm the
# upgrade request is proxied to gunicorn (it returns 401/422 for a bogus token,
# not a connection error or 5xx). Any of these codes proves routing works.
ws_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    "https://${DOMAIN}/firewall-logs/ws?token=bogus" || true)"
case "${ws_code}" in
    101|401|403|422) ok "WebSocket endpoint reachable via proxy (HTTP ${ws_code})." ;;
    "") warn "Could not probe the WebSocket endpoint (network/timeout). Verify manually." ;;
    *) warn "WebSocket probe returned HTTP ${ws_code} — review the proxy if WS misbehaves." ;;
esac

ok "End-to-end checks passed."

# ─────────────────────────── Step 7: Auto-renewal ─────────────────────────────
step "Step 7 — Enable automatic renewal"

# Reload nginx whenever a renewed cert is deployed.
run mkdir -p "$(dirname "${RENEW_HOOK}")"
run tee "${RENEW_HOOK}" >/dev/null <<'EOF'
#!/bin/sh
systemctl reload nginx
EOF
run chmod +x "${RENEW_HOOK}"
ok "Deploy hook installed: ${RENEW_HOOK}"

# Enable the certbot systemd timer if present (apt package usually adds it).
if systemctl list-unit-files 2>/dev/null | grep -q 'certbot.timer'; then
    run systemctl enable --now certbot.timer
    ok "certbot.timer enabled."
else
    warn "certbot.timer not found; add a cron entry: '0 3 * * * certbot renew --quiet'"
fi

log "Dry-run renewal to confirm the renewal path works ..."
run certbot renew --dry-run
ok "Renewal dry-run succeeded."

# ─────────────────────────── Summary ──────────────────────────────────────────
printf "\n${C_GRN}━━━ Done. ${DOMAIN} is live over HTTPS. ━━━${C_RST}\n"
cat <<EOF
  API root : https://${DOMAIN}/
  Swagger  : https://${DOMAIN}/apidocs/
  WebSocket: wss://${DOMAIN}/firewall-logs/ws?token=<JWT>
  Backend  : proxied to 127.0.0.1:${APP_PORT}

  Renewal  : automatic (certbot.timer). Test anytime with:
             sudo certbot renew --dry-run
  Logs     : sudo journalctl -u nginx -f
EOF
