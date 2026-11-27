"""LLDAP (LDAP bind + GraphQL), and the optional Navidrome account sync."""
import logging
import re

import httpx
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError, LDAPSocketReceiveError
from ldap3.utils.conv import escape_filter_chars

from . import config
from .security import valid_login_username

log = logging.getLogger("portal.directory")


class DirectoryError(Exception):
    """The directory (or an integration) is unreachable or rejected a request."""


def user_dn(username: str) -> str:
    return f"uid={username},ou=people,{config.S.ldap_base}"


def _server() -> Server:
    return Server(config.S.ldap_url, connect_timeout=3)


def _service() -> Connection:
    s = config.S
    c = Connection(_server(), user=user_dn(s.ldap_bind_user), password=s.ldap_bind_password,
                   receive_timeout=6)
    try:
        if not c.bind():
            raise DirectoryError("portal service account could not bind to LLDAP")
    except (LDAPSocketOpenError, LDAPSocketReceiveError) as e:
        raise DirectoryError(f"LLDAP unreachable: {e}") from e
    return c


def groups_of(username: str) -> set:
    c = _service()
    try:
        c.search(f"ou=people,{config.S.ldap_base}", f"(uid={escape_filter_chars(username)})",
                 attributes=["memberOf"])
        groups = set()
        for entry in c.entries:
            if "memberOf" in entry.entry_attributes:
                for dn in entry["memberOf"].values:
                    m = re.match(r"(?i)cn=([^,]+),", str(dn))
                    if m:
                        groups.add(m.group(1).lower())
        return groups
    finally:
        c.unbind()


def user_exists(username: str) -> bool:
    c = _service()
    try:
        c.search(f"ou=people,{config.S.ldap_base}", f"(uid={escape_filter_chars(username)})",
                 attributes=["uid"])
        return bool(c.entries)
    finally:
        c.unbind()


def authenticate(username: str, password: str):
    """Return the user's group set when the password is right, None when it is wrong."""
    if not valid_login_username(username) or not password or len(password) > 256:
        return None  # an empty password would be an anonymous bind, so never try it
    c = Connection(_server(), user=user_dn(username), password=password, receive_timeout=6)
    try:
        ok = c.bind()
    except (LDAPSocketOpenError, LDAPSocketReceiveError) as e:
        raise DirectoryError(f"LLDAP unreachable: {e}") from e
    except LDAPException:
        return None
    finally:
        try:
            c.unbind()
        except Exception:
            pass
    return groups_of(username) if ok else None


def tier_for(groups: set):
    if "media_admin" in groups:
        return "admin"
    if "media_internet" in groups:
        return "internet"
    if "media_members" in groups:
        return "member"
    return None


# ---- LLDAP GraphQL (user and group management) -------------------------------------

def _gql(query: str, variables: dict = None) -> dict:
    s = config.S
    try:
        r = httpx.post(f"{s.lldap_http}/auth/simple/login",
                       json={"username": s.ldap_bind_user, "password": s.ldap_bind_password}, timeout=5)
        r.raise_for_status()
        token = r.json()["token"]
        r = httpx.post(f"{s.lldap_http}/api/graphql", json={"query": query, "variables": variables or {}},
                       headers={"Authorization": f"Bearer {token}"}, timeout=8)
        r.raise_for_status()
    except (httpx.HTTPError, KeyError, ValueError) as e:
        raise DirectoryError(f"LLDAP request failed: {e}") from e
    data = r.json()
    if data.get("errors"):
        raise DirectoryError("LLDAP: " + str(data["errors"][0].get("message")))
    return data["data"]


def _group_id(name: str) -> int:
    for g in _gql("{ groups { id displayName } }")["groups"]:
        if g["displayName"].lower() == name.lower():
            return g["id"]
    raise DirectoryError(f"group {name} does not exist in LLDAP")


def create_user(username: str, email: str, display_name: str) -> None:
    _gql("mutation($u: CreateUserInput!){ createUser(user: $u){ id } }",
         {"u": {"id": username, "email": email, "displayName": display_name}})


def set_password(username: str, password: str) -> None:
    c = _service()
    try:
        ok = c.extend.standard.modify_password(user=user_dn(username), old_password=None,
                                               new_password=password)
        if not ok:
            raise DirectoryError(f"LLDAP refused the password change: {c.result.get('description')}")
    finally:
        c.unbind()


def add_to_group(username: str, group: str) -> None:
    _gql("mutation($u: String!, $g: Int!){ addUserToGroup(userId: $u, groupId: $g){ ok } }",
         {"u": username, "g": _group_id(group)})


def remove_from_group(username: str, group: str) -> None:
    _gql("mutation($u: String!, $g: Int!){ removeUserFromGroup(userId: $u, groupId: $g){ ok } }",
         {"u": username, "g": _group_id(group)})


def delete_user(username: str) -> None:
    _gql("mutation($u: String!){ deleteUser(userId: $u){ ok } }", {"u": username})


def list_users() -> list:
    data = _gql("{ users { id email displayName groups { displayName } } }")["users"]
    return [{"id": u["id"], "email": u["email"],
             "groups": sorted(g["displayName"] for g in u["groups"])} for u in data]


# ---- Navidrome (optional: skipped until NAVIDROME_URL is set in phase 5) --------------

def navidrome_create(username: str, password: str, email: str) -> None:
    s = config.S
    if not s.navidrome_url:
        return
    try:
        r = httpx.post(f"{s.navidrome_url}/auth/login",
                       json={"username": s.navidrome_admin, "password": s.navidrome_pass}, timeout=5)
        r.raise_for_status()
        token = r.json()["token"]
        r = httpx.post(f"{s.navidrome_url}/api/user", headers={"X-ND-Authorization": f"Bearer {token}"},
                       json={"userName": username, "name": username, "email": email,
                             "password": password, "isAdmin": False}, timeout=8)
    except (httpx.HTTPError, KeyError, ValueError) as e:
        raise DirectoryError(f"Navidrome request failed: {e}") from e
    if r.status_code >= 300 and "already" not in r.text.lower() and "unique" not in r.text.lower():
        raise DirectoryError(f"Navidrome refused the account ({r.status_code}): {r.text[:200]}")
