# Sentri / Neural Firewall backend
FROM python:3.12-slim

# Keep output unbuffered, skip writing .pyc files, speed up pip.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_APP=run.py \
    PORT=8000

WORKDIR /app

# Install dependencies first so this layer is cached when only code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application, migrations, and gunicorn config.
COPY . .

RUN chmod +x entrypoint.sh

# Gunicorn binds to 0.0.0.0:$PORT (see gunicorn.conf.py).
EXPOSE 8000

# entrypoint.sh runs `flask db upgrade` before handing off to the CMD.
ENTRYPOINT ["./entrypoint.sh"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "run:app"]
