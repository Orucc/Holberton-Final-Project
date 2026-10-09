# Kharibulbul SIEM - all-in-one demo image.
# Serves the dashboard + JSON API on port 8080 (override with the PORT env var)
# and seeds the SQLite store with the synthetic demo scenarios on every start -
# the host disk is ephemeral, so the data is reloaded each time the container boots.
FROM python:3.12-slim

# curl is used by the entrypoint to wait for /api/health before seeding.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first so this layer is cached independently of the source.
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e . \
    && chmod +x scripts/demo-entrypoint.sh

EXPOSE 8080

CMD ["bash", "scripts/demo-entrypoint.sh"]
