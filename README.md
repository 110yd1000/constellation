# Media LAN captive portal

FastAPI service for LXC 103 (10.20.0.31). It serves the login, guest and sign-up pages,
decides every Wi-Fi login for FreeRADIUS, records usage from the router, and gives the
administrator pages to approve sign-ups, manage users and disconnect sessions.
The router keeps no user data; the portal and LLDAP hold all of it.

## Install (inside LXC 103, as root)

    tar xzf media-portal-phase4-v3.tgz && cd portal
    bash deploy/install.sh

Then, in this order:

1. Set `LDAP_BIND_PASSWORD`, copy the CA file to `/etc/portal/ca.crt`, start the service, check `/healthz`.
2. Follow `deploy/lldap-portal-account.md`.
3. On LXC 102 run `SKIP_RESTART=1 RADIUS_PORTAL_PASSWORD=... bash deploy/freeradius-switch.sh`
   (checks only), then run it again without `SKIP_RESTART` to apply.
4. Apply `deploy/mikrotik-hotspot.rsc` on the router and upload `hotspot-login.html`.
5. Test: one guest login, one sign-up and approval, one admin disconnect, then the offline test.

## What is in the package

| Path | Purpose |
| --- | --- |
| `app/main.py` | All routes: login, guest, sign-up, RADIUS callbacks, admin pages |
| `app/directory.py` | LLDAP access (LDAP bind, GraphQL) and the optional Navidrome call |
| `app/services.py` | Staged approval of sign-ups, hourly clean-up |
| `app/routeros.py` | Optional router REST call to disconnect a session |
| `app/db.py`, `security.py`, `config.py` | SQLite schema, validation and limits, settings |
| `app/templates/` | The pages (no external files, so they work before login) |
| `deploy/install.sh` | Installs the app, creates the settings file with new secrets |
| `deploy/portal.env.example` | Every setting, with the defaults from the design |
| `deploy/portal.service` | systemd unit (listens on port 80) |
| `deploy/freeradius-switch.sh` | Switches FreeRADIUS from test users to the portal |
| `deploy/freeradius-rest`, `freeradius-site-media` | FreeRADIUS module and site used by that script |
| `deploy/Caddyfile-portal.snippet` | HTTPS for the admin pages in Caddy |
| `deploy/mikrotik-hotspot.rsc`, `hotspot-login.html` | Router Hotspot settings (PAP login, user profiles, walled garden) and the redirect page |
| `deploy/lldap-portal-account.md` | Rights the portal account needs in LLDAP |
| `tests/` | 28 tests, no network needed |

## Admin access

Admin pages open only at **https://portal.media.lan/admin** (through Caddy). Requests sent
straight to `http://10.20.0.31/admin` are refused, and the admin session cookie is sent
only over HTTPS (`ADMIN_VIA_PROXY=1`, `COOKIE_SECURE=1` in `portal.env`).

Deleting a user or changing their internet access disconnects their live Wi-Fi sessions
once `ROUTER_URL` and `ROUTER_PASS` are set; until then the change applies at their next login.

## Run the tests

    python3 -m venv venv && venv/bin/pip install -r requirements-dev.txt
    PORTAL_TESTING=1 venv/bin/python -m pytest -q
