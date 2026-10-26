# Media LAN captive portal

FastAPI service for LXC 103 (10.20.0.31). It serves the login, guest and sign-up pages,
decides every Wi-Fi login for FreeRADIUS, records usage from the router, and gives the
administrator pages to approve sign-ups, manage users and disconnect sessions.
The router keeps no user data; the portal and LLDAP hold all of it.

## Install (inside LXC 103, as root)

    tar xzf portal-phase4.tgz && cd portal
    bash deploy/install.sh

Then follow the phase 4 runbook: set `LDAP_BIND_PASSWORD`, copy the CA file, start the
service, and run `deploy/freeradius-switch.sh` on LXC 102.

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
| `tests/` | 18 tests, no network needed |

## Run the tests

    python3 -m venv venv && venv/bin/pip install -r requirements-dev.txt
    PORTAL_TESTING=1 venv/bin/python -m pytest -q
