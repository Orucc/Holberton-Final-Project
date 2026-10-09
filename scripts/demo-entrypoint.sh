#!/usr/bin/env bash
# Demo entrypoint: start the Kharibulbul server, wait until the API answers,
# seed the store with the safe synthetic scenarios, then keep the server in the
# foreground. The container disk is ephemeral, so a fresh container has no
# data/kharibulbul.db and is seeded; a plain `docker restart` keeps the file
# and is not seeded twice.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PORT:-8080}"
BASE="http://127.0.0.1:${PORT}"

SEED=1
if [ -s data/kharibulbul.db ]; then
    SEED=0
fi

kharibulbul server -c config/server.yml &
SERVER_PID=$!

for _ in $(seq 1 60); do
    if curl -fsS "${BASE}/api/health" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "demo: kharibulbul server exited before becoming healthy" >&2
        wait "${SERVER_PID}" || true
        exit 1
    fi
    if [ "${_}" = "60" ]; then
        echo "demo: server did not answer /api/health within 60s" >&2
        kill "${SERVER_PID}" 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

if [ "${SEED}" = "1" ]; then
    echo "demo: server healthy - seeding synthetic scenarios (kharibulbul simulate all)"
    kharibulbul simulate all --server "${BASE}" \
        || echo "demo: WARNING - simulation seeding failed; dashboard will be empty" >&2
else
    echo "demo: existing database found - skipping seeding"
fi

wait "${SERVER_PID}"
