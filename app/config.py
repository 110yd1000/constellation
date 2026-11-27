"""Settings, read once from environment variables (systemd EnvironmentFile)."""
import ipaddress
import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass
class Settings:
    db_path: str = "/var/lib/portal/portal.db"
    session_secret: str = ""
    fernet_key: str = ""
    # LLDAP
    ldap_url: str = "ldap://10.20.0.21:3890"
    ldap_base: str = "dc=media,dc=lan"
    ldap_bind_user: str = "portal"
    ldap_bind_password: str = ""
    lldap_http: str = "http://10.20.0.21:17170"
    # FreeRADIUS -> portal
    radius_user: str = "radius"
    radius_pass: str = ""
    radius_ip: str = "10.20.0.21"
    # router and landing pages
    hotspot_login_url: str = "http://10.20.1.1/login"
    landing_member: str = "https://test.media.lan"
    landing_guest: str = "https://guest.media.lan"
    ca_file: str = "/etc/portal/ca.crt"
    admin_nets: list = field(default_factory=list)
    trusted_proxies: list = field(default_factory=lambda: ["10.20.0.11"])
    # admin pages only through Caddy (HTTPS); the session cookie is HTTPS-only
    admin_via_proxy: bool = True
    cookie_secure: bool = True
    router_url: str = ""
    router_user: str = "portal"
    router_pass: str = ""
    # optional Navidrome account sync
    navidrome_url: str = ""
    navidrome_admin: str = ""
    navidrome_pass: str = ""
    # tier limits (seconds)
    token_ttl: int = 60
    guest_seconds: int = 7200
    guest_idle: int = 900
    guest_per_day: int = 6
    member_seconds: int = 43200
    member_idle: int = 3600
    internet_rate: str = ""  # e.g. "2M/4M" (upload/download); empty = no limit


def load() -> Settings:
    nets = []
    for part in _env("ADMIN_NETS", "10.20.1.2/32").split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return Settings(
        db_path=_env("PORTAL_DB", "/var/lib/portal/portal.db"),
        session_secret=_env("SESSION_SECRET"),
        fernet_key=_env("FERNET_KEY"),
        ldap_url=_env("LDAP_URL", "ldap://10.20.0.21:3890"),
        ldap_base=_env("LDAP_BASE", "dc=media,dc=lan"),
        ldap_bind_user=_env("LDAP_BIND_USER", "portal"),
        ldap_bind_password=_env("LDAP_BIND_PASSWORD"),
        lldap_http=_env("LLDAP_HTTP", "http://10.20.0.21:17170"),
        radius_user=_env("RADIUS_USER", "radius"),
        radius_pass=_env("RADIUS_PASS"),
        radius_ip=_env("RADIUS_CLIENT_IP", "10.20.0.21"),
        hotspot_login_url=_env("HOTSPOT_LOGIN_URL", "http://10.20.1.1/login"),
        landing_member=_env("LANDING_MEMBER", "https://test.media.lan"),
        landing_guest=_env("LANDING_GUEST", "https://guest.media.lan"),
        ca_file=_env("CA_FILE", "/etc/portal/ca.crt"),
        admin_nets=nets,
        trusted_proxies=[p.strip() for p in _env("TRUSTED_PROXIES", "10.20.0.11").split(",") if p.strip()],
        admin_via_proxy=_env("ADMIN_VIA_PROXY", "1") != "0",
        cookie_secure=_env("COOKIE_SECURE", "1") != "0",
        router_url=_env("ROUTER_URL"),
        router_user=_env("ROUTER_USER", "portal"),
        router_pass=_env("ROUTER_PASS"),
        navidrome_url=_env("NAVIDROME_URL").rstrip("/"),
        navidrome_admin=_env("NAVIDROME_ADMIN"),
        navidrome_pass=_env("NAVIDROME_PASS"),
        token_ttl=_int("TOKEN_TTL", 60),
        guest_seconds=_int("GUEST_SECONDS", 7200),
        guest_idle=_int("GUEST_IDLE", 900),
        guest_per_day=_int("GUEST_PER_DAY", 6),
        member_seconds=_int("MEMBER_SECONDS", 43200),
        member_idle=_int("MEMBER_IDLE", 3600),
        internet_rate=_env("INTERNET_RATE"),
    )


S = load()


def require_secrets() -> None:
    missing = [n for n, v in {
        "SESSION_SECRET": S.session_secret, "FERNET_KEY": S.fernet_key,
        "LDAP_BIND_PASSWORD": S.ldap_bind_password, "RADIUS_PASS": S.radius_pass,
    }.items() if not v]
    if missing:
        raise RuntimeError("missing required settings: " + ", ".join(missing))
