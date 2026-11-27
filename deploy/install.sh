#!/usr/bin/env bash
# Install the portal inside LXC 103. Run as root from the unpacked folder:
#     bash deploy/install.sh
# Safe to run again: it never overwrites an existing /etc/portal/portal.env.
# Test switches (used only for dry runs): DESTROOT=<dir> SKIP_APT=1 SKIP_USER=1 SKIP_SYSTEMD=1
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="${DESTROOT:-}"
APP="$ROOT/opt/portal"
ETC="$ROOT/etc/portal"
VAR="$ROOT/var/lib/portal"
UNIT="$ROOT/etc/systemd/system/portal.service"

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

if [ -z "${SKIP_APT:-}" ]; then
    apt-get update -q
    apt-get install -y -q python3 python3-venv openssl ca-certificates
fi

if [ -z "${SKIP_USER:-}" ] && ! id portal >/dev/null 2>&1; then
    useradd --system --home-dir /opt/portal --shell /usr/sbin/nologin portal
fi

install -d "$APP" "$ETC" "$VAR"
rm -rf "$APP/app"
cp -r "$SRC/app" "$APP/app"
find "$APP/app" -name __pycache__ -type d -prune -exec rm -rf {} +
cp "$SRC/requirements.txt" "$APP/requirements.txt"

if [ ! -x "$APP/venv/bin/pip" ]; then
    python3 -m venv "$APP/venv"
fi
"$APP/venv/bin/pip" install --quiet --upgrade pip
"$APP/venv/bin/pip" install --quiet -r "$APP/requirements.txt"
"$APP/venv/bin/pip" freeze > "$APP/requirements.lock"

ENVFILE="$ETC/portal.env"
if [ ! -f "$ENVFILE" ]; then
    cp "$SRC/deploy/portal.env.example" "$ENVFILE"
    SESSION="$(openssl rand -hex 32)"
    RADIUS="$(openssl rand -hex 24)"
    FERNET="$("$APP/venv/bin/python" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
    sed -i "s|^SESSION_SECRET=.*|SESSION_SECRET=$SESSION|; s|^FERNET_KEY=.*|FERNET_KEY=$FERNET|; s|^RADIUS_PASS=.*|RADIUS_PASS=$RADIUS|" "$ENVFILE"
    echo "Created $ENVFILE with new secrets."
else
    echo "Kept your existing $ENVFILE."
fi

if [ -z "${SKIP_USER:-}" ]; then
    chown -R root:portal "$ETC"
    chown portal:portal "$VAR"
    chown -R root:root "$APP"
fi
chmod 750 "$ETC" "$VAR"
chmod 640 "$ENVFILE"

if [ -z "${SKIP_SYSTEMD:-}" ]; then
    install -d "$(dirname "$UNIT")"
    cp "$SRC/deploy/portal.service" "$UNIT"
    systemctl daemon-reload
    systemctl enable portal >/dev/null 2>&1 || true
fi

echo
echo "Installed. Next:"
echo "  1. Edit $ENVFILE and set LDAP_BIND_PASSWORD (the LLDAP 'portal' account password)."
echo "  2. Copy the CA certificate to $ETC/ca.crt"
echo "  3. systemctl start portal && systemctl status portal"
echo
echo "The FreeRADIUS password for LXC 102 is this RADIUS_PASS value:"
grep '^RADIUS_PASS=' "$ENVFILE"
