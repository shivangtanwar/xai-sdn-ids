# Live dashboard deployment (sds.shivang.me)

The always-on version of the testbed runs on `gr19-remote` and is shown at
**https://sds.shivang.me**. Anyone with the link can watch. Launching attacks, releasing
blocks and switching protection require the dashboard password.

## How it is wired

```
browser ──HTTPS──> nginx (sds.shivang.me, Let's Encrypt) ──> 127.0.0.1:8200 dashboard
                                                                 │  private Docker network
                                         ┌───────────────────────┴───────────────┐
                                  controller:8080 (Ryu REST)          mininet:9000 (testbed runner)
                                  Ryu + RF + SHAP + CGRE  <──OpenFlow──  Mininet/OVS, 8 hosts,
                                                                         always-on benign traffic
```

| Piece | Where |
|---|---|
| Code | `/srv/xai-sdn-ids` on gr19-remote (copied with rsync, not git) |
| Stack definition | `docker-compose.live.yml` (project name `xai-live`) |
| Secrets | `/srv/xai-sdn-ids/.env` (root-only): `DASHBOARD_PASSWORD`, `SESSION_SECRET` |
| nginx site | `/etc/nginx/sites-available/sds` (TLS block managed by certbot) |
| Certificate | `certbot certificates` → `sds.shivang.me`, renewed automatically by `certbot.timer` |

Only the dashboard is published, and only on 127.0.0.1. The Ryu REST API (which can
release blocks without auth) and the testbed runner are reachable only inside the Docker
network. Attack traffic never leaves Mininet's virtual network.

## Everyday operations (on gr19-remote)

```bash
cd /srv/xai-sdn-ids
docker compose -f docker-compose.live.yml ps                  # status
docker compose -f docker-compose.live.yml logs -f controller  # decisions (ALERT/RATE_LIMIT/BLOCK)
docker compose -f docker-compose.live.yml restart             # restart everything
docker compose -f docker-compose.live.yml down                # stop (frees ~1 CPU core)
docker compose -f docker-compose.live.yml up -d               # start again
grep DASHBOARD_PASSWORD .env                                  # show the password
```

Change the password: edit `DASHBOARD_PASSWORD` in `.env`, then
`docker compose -f docker-compose.live.yml up -d dashboard`. Changing `SESSION_SECRET`
signs everyone out.

## Updating the code (from a laptop with the repo)

```bash
rsync -az --exclude .git --exclude .env --exclude __pycache__ ./ gr19-remote:/srv/xai-sdn-ids/
ssh gr19-remote 'cd /srv/xai-sdn-ids && docker compose -f docker-compose.live.yml up -d --build'
```
Controller and runner code is mounted, so a `restart` is enough for `ids/`, `controller/`
and `traffic/` changes. The dashboard image must be rebuilt (`--build`) for `dashboard/` changes.

## Running the same stack locally

```bash
printf 'DASHBOARD_PASSWORD=localtest\nSESSION_SECRET=%s\nSECURE_COOKIE=0\n' "$(openssl rand -hex 32)" > .env
docker compose -f docker-compose.live.yml up -d --build      # http://127.0.0.1:8200
```
`SECURE_COOKIE=0` is needed only on plain-HTTP localhost.

## Presenting it

1. Open https://sds.shivang.me and click **Sign in**.
2. Click **Run guided demo**. It plays, 30 s each with 10 s gaps: a heavy *benign* transfer
   (should be ignored), then a SYN flood, port scan, UDP flood and ICMP flood (each should be
   detected, explained and mitigated).
3. Keep **Follow the latest alert** on. The pipeline panel jumps to each attacker and shows
   counters → features → Random Forest votes → SHAP → gates → decision.
4. To show why gating matters, switch **Automatic protection** off (monitor mode): attacks are
   still detected and explained, but nothing is blocked ("monitor mode (would BLOCK)").
5. **Launched episodes** shows the measured detection and mitigation time of each attack.
   The **Results** tab (or https://sds.shivang.me/#results) has the offline evaluation.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Banner "Ryu controller is not reachable" | `docker compose -f docker-compose.live.yml restart controller` (switches reconnect by themselves) |
| Banner "Mininet testbed is not reachable" | `docker compose -f docker-compose.live.yml restart mininet` |
| Page loads but stays on "Connecting…" | check `docker compose ... logs dashboard`; nginx must keep `proxy_buffering off` for `/api/stream` |
| "Too many attempts" at sign-in | 5 attempts per minute per IP; wait one minute |
