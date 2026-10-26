"""Optional RouterOS REST calls. Used only to disconnect a live Hotspot session."""
import httpx

from . import config
from .security import norm_mac


class RouterError(Exception):
    pass


def kick(username: str, mac: str) -> int:
    """Remove the Hotspot active entry for this user and MAC. Returns how many were removed."""
    s = config.S
    if not s.router_url or not s.router_pass:
        raise RouterError("router access is not configured (ROUTER_URL and ROUTER_PASS)")
    removed = 0
    try:
        with httpx.Client(base_url=s.router_url, auth=(s.router_user, s.router_pass),
                          verify=False, timeout=5) as c:  # self-signed cert, server LAN only
            r = c.get("/rest/ip/hotspot/active")
            r.raise_for_status()
            for e in r.json():
                if e.get("user") == username and norm_mac(e.get("mac-address", "")) == norm_mac(mac):
                    c.delete(f"/rest/ip/hotspot/active/{e['.id']}").raise_for_status()
                    removed += 1
    except (httpx.HTTPError, ValueError, KeyError) as e:
        raise RouterError(f"router request failed: {e}") from e
    return removed
