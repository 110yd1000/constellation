#!/usr/bin/env bash
# Switch FreeRADIUS in LXC 102 from the phase 3 test setup to the portal. Run as root:
#     RADIUS_PORTAL_PASSWORD=<RADIUS_PASS from the portal's portal.env> bash freeradius-switch.sh
# Optional: PORTAL_URL (default http://10.20.0.31), RADDB (default /etc/freeradius/3.0),
#           SKIP_APT=1 (do not install freeradius-rest), SKIP_RESTART=1 (check only, change nothing live)
#
# The new configuration is built and checked in a scratch copy first. Your live configuration is
# touched only when that check passes, and it is restored from the backup if anything fails after.
set -euo pipefail

: "${RADIUS_PORTAL_PASSWORD:?Set RADIUS_PORTAL_PASSWORD to the RADIUS_PASS value on LXC 103}"
PORTAL_URL="${PORTAL_URL:-http://10.20.0.31}"
RADDB="${RADDB:-/etc/freeradius/3.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -d "$RADDB" ] || { echo "No FreeRADIUS configuration at $RADDB" >&2; exit 1; }
case "$RADIUS_PORTAL_PASSWORD" in *[\'\"\\\&\|]*) echo "The password must not contain quotes, backslashes, & or |." >&2; exit 1;; esac

# The rest module is a separate Debian package; without it the configuration cannot load.
if [ -z "${SKIP_APT:-}" ] && ! dpkg -s freeradius-rest >/dev/null 2>&1; then
    apt-get update -q && apt-get install -y -q freeradius-rest
fi
command -v freeradius >/dev/null || { echo "freeradius is not installed." >&2; exit 1; }

apply_to() {  # apply_to <config dir>
    local d="$1"
    if [ -f "$d/users.orig" ]; then  # phase 3 test users go away: restore the original users file
        mv "$d/users.orig" "$d/users"
    fi
    # Without the stock default site the eap module has no section to attach to, so it goes too.
    # (This switches off 802.1X; the portal handles Wi-Fi logins instead.)
    rm -f "$d/sites-enabled/default" "$d/sites-enabled/inner-tunnel" "$d/mods-enabled/eap"
    sed "s|http://10.20.0.31|$PORTAL_URL|; s|<RADIUS_PORTAL_PASSWORD>|$RADIUS_PORTAL_PASSWORD|g" \
        "$HERE/freeradius-rest" > "$d/mods-available/rest"
    ln -sf ../mods-available/rest "$d/mods-enabled/rest"
    cp "$HERE/freeradius-site-media" "$d/sites-available/media"
    ln -sf ../sites-available/media "$d/sites-enabled/media"
    chmod 640 "$d/mods-available/rest"
}

BACKUP="/root/freeradius-before-phase4-$(date +%Y%m%d-%H%M%S).tgz"
tar czf "$BACKUP" -C "$RADDB" .
echo "Backup of the old configuration: $BACKUP"

# 1. Build and check the new configuration in a scratch copy.
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
cp -a "$RADDB/." "$SCRATCH/"
apply_to "$SCRATCH"
if ! freeradius -C -d "$SCRATCH" >/dev/null 2>&1; then
    freeradius -XC -d "$SCRATCH" 2>&1 | tail -15 || true
    echo "Configuration check FAILED. Nothing live was changed." >&2
    exit 1
fi
echo "Configuration check passed (nothing live changed yet)."

if [ -n "${SKIP_RESTART:-}" ]; then
    echo "SKIP_RESTART set: stopping here. Run again without it to apply."
    exit 0
fi

# 2. Apply for real; undo from the backup if the service does not come up.
restore() {
    echo "Restoring the old configuration from $BACKUP" >&2
    find "$RADDB" -mindepth 1 -delete
    tar xzf "$BACKUP" -C "$RADDB"
    systemctl restart freeradius || true
}
apply_to "$RADDB"
if id freerad >/dev/null 2>&1; then
    chown root:freerad "$RADDB/mods-available/rest" "$RADDB/sites-available/media" "$RADDB/users"
fi
systemctl restart freeradius || { restore; exit 1; }
sleep 2
systemctl is-active --quiet freeradius || { restore; exit 1; }
echo "FreeRADIUS is running with the portal configuration."
