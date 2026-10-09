# Public demo deployment (Render)

The repo ships a root `Dockerfile` and `scripts/demo-entrypoint.sh`. The image
serves the dashboard + API on port **8080** (or `$PORT` when set) and seeds the
SQLite store with the 52 safe synthetic scenarios (`kharibulbul simulate all`)
on every cold start — the host disk is ephemeral, so the data is reloaded each
time the container boots.

## Render, click by click

1. Push these changes to GitHub (PR merged to `main` — see below).
2. <https://dashboard.render.com> → **New +** → **Web Service**.
3. **Source:** connect the GitHub repo (`Kharibulbul-SIEM`). Render detects the
   `Dockerfile` automatically — leave **Runtime: Docker**.
4. **Name:** e.g. `kharibulbul-siem-demo` → the URL becomes
   `https://kharibulbul-siem-demo.onrender.com`.
5. **Instance type:** **Free**.
6. **Environment variables** → add: `PORT` = `8080`.
7. Leave **Health Check Path** empty (default `/` is fine — it redirects to the
   dashboard) or set it to `/api/health`.
8. **Deploy Web Service.** First build takes a few minutes (pip install).
9. Open the public URL → Overview shows ~670 events and ~90 alerts.

## Notes for the live demo

- **Cold start:** the free plan sleeps after ~15 min idle. The first load after
  idle can take up to ~1 minute (container boot + health wait + seeding). Warm
  it up before the presentation.
- **No auth:** `KB_API_TOKEN` is intentionally empty — anyone with the URL can
  use every feature. Do not point real agents or real logs at it.
- **Ephemeral data:** alert status changes, custom rules and playbooks made in
  the UI live in `data/` and `custom/` inside the container and are wiped on
  every redeploy/restart-on-free-tier. Seeding runs again on each boot.
- Ports 5044 (agent TCP) and 5514 (syslog UDP) listen inside the container but
  are not exposed publicly; the dashboard works without them.

## Re-seeding

Render free-tier restarts wipe the filesystem, so `demo-entrypoint.sh` seeds
whenever `data/kharibulbul.db` is missing. To reseed without redeploying:
Render dashboard → the service → **⋯** → **Restart** is *not* enough on paid
persistent disks — use **Manual Deploy → Clear build cache & deploy** instead.

## Local check

```bash
docker build -t kharibulbul-demo .
docker run -d --name kb-demo -p 8080:8080 -e PORT=8080 kharibulbul-demo
# wait ~20 s, then open http://127.0.0.1:8080/
curl http://127.0.0.1:8080/api/health
```
