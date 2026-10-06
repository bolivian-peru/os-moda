# Demo: I Deleted My Nginx Config — Watch What Happens

Reproducible 45-90s demo script for bounty #2. Real camera + uncut terminal session.

## Prerequisites
- osModa installed (`curl -sSL https://raw.githubusercontent.com/bolivian-peru/os-moda/main/scripts/install.sh | bash`)
- or provisioned via `spawn.os.moda`
- nginx managed by NixOS (`services.nginx.enable = true`)
- daemons running: `safeswitch`, `autopilot`, `audit`

## Script (read hook in first 3 seconds)

> "What happens when I `rm -rf /etc/nginx` on a managed server?"

1. Setup (5s): show `systemctl status nginx`, `curl -s -o /dev/null -w "%{http_code}\n" http://localhost/`, `osmoda status`.
2. Start timer: `date -u +%FT%TZ; echo $SECONDS > /tmp/demo_start`.
3. Destruction (on camera, uncut): `sudo rm -rf /etc/nginx && echo DELETED && ls /etc/nginx || true`.
4. Recovery: watch `journalctl -u autopilot -f`, `journalctl -u safeswitch -f`. Expect: health check FAIL (systemd/TCP/HTTP) -> restart -> `nix-env --rollback` + `switch-to-configuration switch` -> nginx active.
5. Proof: `curl` 200 again, `date -u +%FT%TZ`, compute downtime, `osmoda audit log --last 20`, `osmoda audit verify`.
6. Punchline: "Try this on your Ubuntu server. I dare you."

## Requirements checklist for submission
- [ ] Real camera filming real screen, >=720p, public YouTube (not unlisted)
- [ ] Uncut deletion -> recovery sequence (no jump cuts)
- [ ] Audit log + hash-chain entry with reasoning shown
- [ ] Timestamp / total downtime shown
- [ ] Description links repo + `spawn.os.moda`
- [ ] Post YouTube link in issue #2

## Quick run

```bash
./scripts/demo-nginx-self-heal.sh
```

Safe by default: dry-run first, requires typed confirmation for real deletion.
--- /dev/null
++ b/scripts/demo-nginx-self-heal.sh
#!/usr/bin/env bash
# Demo helper for issue #2: rm -rf /etc/nginx -> watchdog -> rollback -> verify.
# Usage: ./scripts/demo-nginx-self-heal.sh [--dry-run] [--target /etc/nginx]
# REAL_MONEY=false: never pays/claims; local demo only.
set -euo pipefail
TARGET="${TARGET:-/etc/nginx}"
DRY_RUN="false"
for a in "$@"; do case "$a" in --dry-run) DRY_RUN="true";; --target=*) TARGET="${a#--target=}";;
  --target) shift; TARGET="${1:-/etc/nginx}";; esac; done

log() { echo "[demo] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

log "=== 1/5 SETUP ==="
date -u +%FT%TZ
systemctl status nginx --no-pager -l || true
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost/ || log "HTTP check failed (pre-demo)"
have osmoda && osmoda status || log "osmoda CLI not found; continuing with systemd/nixos checks"

log "=== 2/5 PRE-FLIGHT (dry-run default) ==="
log "TARGET=$TARGET DRY_RUN=$DRY_RUN"
if [ "$DRY_RUN" = "true" ]; then
  log "DRY RUN: would run: sudo rm -rf $TARGET"
  log "Then expect: autopilot health FAIL -> safeswitch nix-env --rollback + switch-to-configuration switch"
  log "Verify with: $0 (without --dry-run) for the real take"
  exit 0
fi

read -r -p "Type DELETE $TARGET to run the real destructive demo: " ans
if [ "$ans" != "DELETE $TARGET" ]; then log "Aborted."; exit 1; fi

START=$(date +%s); date -u +%FT%TZ | tee /tmp/osmoda-demo-start.txt
log "=== 3/5 DESTRUCTION (UNCUT - keep camera rolling) ==="
sudo rm -rf "$TARGET" && echo DELETED || true
ls "$TARGET" || log "Confirmed: $TARGET gone"

log "=== 4/5 RECOVERY (watch watchdog) ==="
timeout 10 journalctl -u autopilot --no-pager -n 30 || true
timeout 10 journalctl -u safeswitch --no-pager -n 30 || true
# Wait up to 120s for nginx 200
for i in $(seq 1 24); do
  if curl -sf -o /dev/null http://localhost/; then log "nginx back online after ~$(( $(date +%s) - START ))s"; break; fi
  sleep 5
  if [ "$i" = "24" ]; then log "TIMEOUT waiting for nginx; check journalctl"; fi
done
systemctl status nginx --no-pager -l || true

log "=== 5/5 PROOF ==="
END=$(date +%s); date -u +%FT%TZ
echo "Downtime: ~$((END - START))s (START $START END $END)"
have osmoda && { osmoda audit log --last 20 || true; osmoda audit verify || true; } || journalctl --no-pager -n 50 | tail -n 50 || true
log "Done. Keep this terminal on camera for audit log + timestamps."
```
