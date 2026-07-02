# Deploying the Sentri Backend to a DigitalOcean Droplet

Stack: Flask (app factory in `app/__init__.py`) + Postgres + Flask-Migrate +
Flask-Sock WebSockets, served by **gunicorn (gevent worker)** behind **nginx**
with TLS from **Let's Encrypt**, managed by **systemd**.

---

## 0. Before you push code (local, one time)

1. **Rotate the secrets that were committed to git.** The old `.env`
   (`SECRET_KEY`, `JWT_SECRET_KEY`, DB password) is in git history and must be
   considered compromised. Generate new ones:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"   # SECRET_KEY
   python -c "import secrets; print(secrets.token_urlsafe(48))"   # JWT_SECRET_KEY
   ```
2. Commit the prep changes (new `.gitignore`, cleaned `requirements.txt`,
   `gunicorn.conf.py`, `deploy/`) and push to your GitHub repo.
   > Optional but recommended: scrub the old `.env` from history with
   > `git filter-repo` or the BFG, then force-push. Rotating the secrets (step 1)
   > is the essential part.

---

## 1. Create the Droplet

- Ubuntu 24.04 LTS, smallest tier is fine to start ($6–12/mo).
- Add your SSH key during creation.
- Optionally create a **Managed Postgres** database instead of running Postgres
  on the Droplet (more reliable, automatic backups). If you do, skip step 4 and
  use the connection string DO gives you as `DATABASE_URL`.

## 2. Point DNS

Create an `A` record for `api.yourdomain.com` -> the Droplet's public IP.

## 3. Server base setup (as root, then a non-root user)

```bash
ssh root@YOUR_DROPLET_IP
adduser sentri && usermod -aG sudo sentri
rsync --archive --chown=sentri:sentri ~/.ssh /home/sentri   # copy SSH access
apt update && apt upgrade -y
apt install -y python3-venv python3-pip nginx git ufw
ufw allow OpenSSH && ufw allow 'Nginx Full' && ufw --force enable
```

## 4. Install Postgres (skip if using Managed DB)

```bash
apt install -y postgresql
sudo -u postgres psql -c "CREATE DATABASE neural_firewalldb;"
sudo -u postgres psql -c "CREATE USER dbuser WITH PASSWORD 'STRONG_PASSWORD';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE neural_firewalldb TO dbuser;"
sudo -u postgres psql -d neural_firewalldb -c "GRANT ALL ON SCHEMA public TO dbuser;"
```

## 5. Deploy the app (as the `sentri` user)

```bash
su - sentri
git clone https://github.com/YOUR_ORG/Sentri-Backend.git
cd Sentri-Backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Create the production `.env` (NOT committed) with the rotated secrets:

```bash
cat > .env <<'EOF'
SECRET_KEY=<rotated-secret>
JWT_SECRET_KEY=<rotated-jwt-secret>
DATABASE_URL=postgresql://dbuser:STRONG_PASSWORD@localhost:5432/neural_firewalldb
EOF
chmod 600 .env
```

Run database migrations:

```bash
export FLASK_APP=run.py
flask db upgrade
```

Smoke-test gunicorn:

```bash
gunicorn -c gunicorn.conf.py run:app     # Ctrl-C after it says "Listening"
```

## 6. Run under systemd

```bash
sudo cp deploy/sentri.service /etc/systemd/system/sentri.service
sudo systemctl daemon-reload
sudo systemctl enable --now sentri
sudo systemctl status sentri            # should be active (running)
```

## 7. nginx reverse proxy + TLS

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/sentri
# edit the file: set server_name to api.yourdomain.com
sudo ln -s /etc/nginx/sites-available/sentri /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d api.yourdomain.com     # gets + installs the cert, enables HTTPS redirect
```

## 8. Verify

```bash
curl https://api.yourdomain.com/                 # {"message": "Neural Firewall Backend Running"}
# Swagger UI:   https://api.yourdomain.com/apidocs/
# WebSocket:    wss://api.yourdomain.com/firewall-logs/ws?token=<JWT>
```

---

## Updating after a code change

```bash
su - sentri && cd Sentri-Backend
git pull
source venv/bin/activate
pip install -r requirements.txt      # if deps changed
flask db upgrade                     # if new migrations
sudo systemctl restart sentri
```

## Notes / gotchas

- **`run.py` is dev-only** (`debug=True`, self-signed SSL). Production never runs
  it directly — gunicorn imports `run:app`, and nginx/certbot handle TLS.
- **gevent + psycopg2:** DB calls are blocking under gevent. Fine at low/medium
  load. If you see WebSocket stalls under heavy DB load, add `psycogreen` and
  patch psycopg2, or move DB-heavy work off the request path.
- **CORS** is currently wide open (`CORS(app)`). Lock it to your frontend origin
  before going public.
- Watch logs with: `sudo journalctl -u sentri -f`
