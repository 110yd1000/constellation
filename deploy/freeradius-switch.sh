#!/usr/bin/env bash
# Switch FreeRADIUS in LXC 102 from the phase 3 test setup to the portal. Run as root:
#     RADIUS_PORTAL_PASSWORD=<RADIUS_PASS from the portal's portal.env> bash freeradius-switch.sh
# Optional: PORTAL_URL (default http://10.20.0.31), RADDB (default /etc/freeradius/3.0),
#           SKIP_RESTART=1 (dry run: write the files and check the configuration only)
set -euo pipefail

: "${RADIUS_PORTAL_PASSWORD:?Set RADIUS_PORTAL_PASSWORD to the RADIUS_PASS value on LXC 103}"
PORTAL_URL="${PORTAL_URL:-http://10.20.0.31}"
RADDB="${RADDB:-/etc/freeradius/3.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -d "$RADDB" ] || { echo "No FreeRADIUS configuration at $RADDB" >&2; exit 1; }
case "$RADIUS_PORTAL_PASSWORD" in *[\'\"\\\&\|]*) echo "The password must not contain quotes, backslashes, & or |." >&2; exit 1;; esac

BACKUP="/root/freeradius-before-phase4-$(date +%Y%m%d-%H%M%S).tgz"
tar czf "$BACKUP" -C "$RADDB" .
echo "Backup of the old configuration: $BACKUP"

# Phase 3 test users go away: restore the original users file.
if [ -f "$RADDB/users.orig" ]; then
    mv "$RADDB/users.orig" "$RADDB/users"
    echo "Test users removed (users file restored)."
fi

# Without the stock default site, the eap module has no section to attach to and
# FreeRADIUS refuses to start, so it is switched off together with the two stock sites.
rm -f "$RADDB/sites-enabled/default" "$RADDB/sites-enabled/inner-tunnel" "$RADDB/mods-enabled/eap"

sed "s|http://10.20.0.31|$PORTAL_URL|; s|<RADIUS_PORTAL_PASSWORD>|$RADIUS_PORTAL_PASSWORD|g" \
    "$HERE/freeradius-rest" > "$RADDB/mods-available/rest"
ln -sf ../mods-available/rest "$RADDB/mods-enabled/rest"
cp "$HERE/freeradius-site-media" "$RADDB/sites-available/media"
ln -sf ../sites-available/media "$RADDB/sites-enabled/media"

if id freerad >/dev/null 2>&1; then
    chown root:freerad "$RADDB/mods-available/rest" "$RADDB/sites-available/media" "$RADDB/users"
fi
chmod 640 "$RADDB/mods-available/rest"

freeradius -C -d "$RADDB" >/dev/null 2>&1 || { freeradius -XC -d "$RADDB" 2>&1 | tail -15 || true; echo "Configuration check FAILED. Your old setup is in $BACKUP" >&2; exit 1; }
echo "Configuration check passed."

if [ -z "${SKIP_RESTART:-}" ]; then
    systemctl restart freeradius
    sleep 2
    systemctl is-active freeradius
fi
