import base64
import os
import re
import tempfile

os.environ.update({
    "PORTAL_TESTING": "1",
    "PORTAL_DB": os.path.join(tempfile.mkdtemp(), "portal.db"),
    "SESSION_SECRET": "x" * 32,
    "FERNET_KEY": "Rk1jd1pQZ0R2c0VtS0xSM2dJQnBvVmxkNmJFV3hZQ0E=",
    "LDAP_BIND_PASSWORD": "pw",
    "RADIUS_PASS": "radiuspw",
    "ADMIN_NETS": "10.20.1.2/32",
    "CA_FILE": "/nonexistent",
})

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app import config, db, directory, main, routeros

config.S.fernet_key = Fernet.generate_key().decode()
REAL_IP_OF = main.ip_of
MAC = "AA:BB:CC:DD:EE:01"
BASIC = {"Authorization": "Basic " + base64.b64encode(b"radius:radiuspw").decode()}


@pytest.fixture()
def client(monkeypatch):
    with TestClient(main.app) as c:
        monkeypatch.setattr(main, "ip_of", lambda r: c.test_ip)
        c.test_ip = "10.20.1.50"
        db.init()
        with db.conn() as conn:
            for t in ("signups", "guest_vouchers", "login_tokens", "sessions", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
        main.sec.LIMITER.hits.clear()
        yield c


def fake_dir(monkeypatch, users=None):
    state = {"users": dict(users or {}), "groups": {}, "calls": []}

    def authenticate(u, p):
        rec = state["users"].get(u)
        return set(state["groups"].get(u, [])) if rec == p else None

    monkeypatch.setattr(directory, "authenticate", authenticate)
    monkeypatch.setattr(directory, "user_exists", lambda u: u in state["users"])
    monkeypatch.setattr(directory, "create_user", lambda u, e, d: state["calls"].append("create"))
    monkeypatch.setattr(directory, "set_password",
                        lambda u, p: (state["users"].__setitem__(u, p), state["calls"].append("pw")))
    monkeypatch.setattr(directory, "add_to_group",
                        lambda u, g: state["groups"].setdefault(u, []).append(g))
    monkeypatch.setattr(directory, "remove_from_group",
                        lambda u, g: state["groups"].get(u, []).remove(g))
    monkeypatch.setattr(directory, "delete_user", lambda u: state["users"].pop(u, None))
    monkeypatch.setattr(directory, "list_users",
                        lambda: [{"id": u, "email": "e@x.io", "groups": state["groups"].get(u, [])}
                                 for u in state["users"]])
    return state


def token_from(html):
    m = re.search(r'name="password" value="([^"]+)"', html)
    assert m, html
    return m.group(1)


def radius(client, user, token, mac=MAC, path="authorize", extra=None):
    body = {"User-Name": {"type": "string", "value": [user]},
            "User-Password": {"type": "string", "value": [token]},
            "Calling-Station-Id": {"type": "string", "value": [mac]}}
    body.update(extra or {})
    client.test_ip = "10.20.0.21"
    try:
        return client.post(f"/internal/radius/{path}", json=body, headers=BASIC)
    finally:
        client.test_ip = "10.20.1.50"


def test_login_to_radius_accept_once(client, monkeypatch):
    st = fake_dir(monkeypatch, {"lloyd": "correct horse 1"})
    st["groups"]["lloyd"] = ["media_members", "media_internet"]
    r = client.post("/login", data={"username": "Lloyd", "password": "correct horse 1", "mac": MAC})
    assert r.status_code == 200 and "10.20.1.1/login" in r.text
    tok = token_from(r.text)
    ok = radius(client, "lloyd", tok)
    assert ok.status_code == 200
    j = ok.json()
    assert j["reply:Mikrotik-Group"] == "internet" and j["control:Auth-Type"] == "Accept"
    assert j["reply:Session-Timeout"] == 43200
    assert radius(client, "lloyd", tok).status_code == 401  # single use


def test_token_bound_to_mac_and_user(client, monkeypatch):
    st = fake_dir(monkeypatch, {"a": "passwordaaa"})
    st["groups"]["a"] = ["media_members"]
    tok = token_from(client.post("/login", data={"username": "a", "password": "passwordaaa", "mac": MAC}).text)
    assert radius(client, "a", tok, mac="AA:BB:CC:DD:EE:99").status_code == 401
    assert radius(client, "b", tok).status_code == 401
    assert radius(client, "a", tok).status_code == 200  # wrong attempts did not burn it


def test_expired_token(client, monkeypatch):
    st = fake_dir(monkeypatch, {"a": "passwordaaa"})
    st["groups"]["a"] = ["media_members"]
    tok = token_from(client.post("/login", data={"username": "a", "password": "passwordaaa", "mac": MAC}).text)
    with db.conn() as c:
        c.execute("UPDATE login_tokens SET expires_at=?", (db.now() - 1,))
    assert radius(client, "a", tok).status_code == 401


def test_wrong_password_and_lockout(client, monkeypatch):
    st = fake_dir(monkeypatch, {"a": "passwordaaa"})
    st["groups"]["a"] = ["media_members"]
    for _ in range(5):
        assert client.post("/login", data={"username": "a", "password": "nope", "mac": MAC}).status_code == 401
    r = client.post("/login", data={"username": "a", "password": "passwordaaa", "mac": MAC})
    assert r.status_code == 429


def test_no_mac_no_login(client, monkeypatch):
    fake_dir(monkeypatch)
    assert client.post("/login", data={"username": "a", "password": "x", "mac": ""}).status_code == 400
    assert client.post("/guest", data={"mac": ""}).status_code == 400


def test_user_without_group_is_refused(client, monkeypatch):
    fake_dir(monkeypatch, {"a": "passwordaaa"})
    r = client.post("/login", data={"username": "a", "password": "passwordaaa", "mac": MAC})
    assert r.status_code == 403


def test_guest_flow_and_daily_limit(client, monkeypatch):
    fake_dir(monkeypatch)
    r = client.post("/guest", data={"mac": MAC})
    assert r.status_code == 200 and "https://guest.media.lan" in r.text
    tok = token_from(r.text)
    user = re.search(r'name="username" value="([^"]+)"', r.text).group(1)
    assert user.startswith("guest-")
    j = radius(client, user, tok).json()
    assert j["reply:Mikrotik-Group"] == "guest" and j["reply:Session-Timeout"] == 7200
    assert j["reply:Idle-Timeout"] == 900
    for _ in range(5):
        main.sec.LIMITER.hits.clear()
        assert client.post("/guest", data={"mac": MAC}).status_code == 200
    main.sec.LIMITER.hits.clear()
    assert client.post("/guest", data={"mac": MAC}).status_code == 429


def test_signup_approve_flow(client, monkeypatch):
    st = fake_dir(monkeypatch)
    form = {"username": "newbie", "email": "n@x.io", "phone": "+263 77 123 4567",
            "password": "a-long-password", "password2": "a-long-password"}
    r = client.post("/signup", data=form, follow_redirects=False)
    assert r.status_code == 303
    sid = r.headers["location"].rsplit("/", 1)[1]
    assert "waiting" in client.get(f"/signup/{sid}").text
    with db.conn() as c:  # the password is stored encrypted, never in clear
        raw = c.execute("SELECT password_enc FROM signups").fetchone()[0]
    assert b"a-long-password" not in raw
    # duplicate username is refused with the same generic message
    assert "not available" in client.post("/signup", data=form).text
    # admin must come from an admin device and log in
    assert client.get("/admin/signups").status_code == 403
    client.test_ip = "10.20.1.2"
    assert client.get("/admin/signups", follow_redirects=False).status_code == 303
    st["users"]["root1"] = "adminpassword1"
    st["groups"]["root1"] = ["media_admin", "media_members"]
    bad = client.post("/admin/login", data={"username": "newbie", "password": "x"})
    assert bad.status_code == 401
    ok = client.post("/admin/login", data={"username": "root1", "password": "adminpassword1"},
                     follow_redirects=False)
    assert ok.status_code == 303
    page = client.get("/admin/signups")
    assert "newbie" in page.text and "n@x.io" in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    # missing CSRF is refused
    assert client.post(f"/admin/signups/{sid}/approve", data={"internet": "1"}).status_code == 403
    r = client.post(f"/admin/signups/{sid}/approve", data={"csrf": csrf, "internet": "1"}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" not in r.headers["location"]
    assert st["calls"] == ["create", "pw"]
    assert st["groups"]["newbie"] == ["media_members", "media_internet"]
    with db.conn() as c:
        row = c.execute("SELECT status, password_enc FROM signups").fetchone()
    assert row["status"] == "approved" and row["password_enc"] is None
    assert "Approved" in client.get(f"/signup/{sid}").text
    # the new user can now get an internet-tier token
    client.test_ip = "10.20.1.50"
    r = client.post("/login", data={"username": "newbie", "password": "a-long-password", "mac": MAC})
    tok = token_from(r.text)
    assert radius(client, "newbie", tok).json()["reply:Mikrotik-Group"] == "internet"


def test_approval_resumes_after_failure(client, monkeypatch):
    st = fake_dir(monkeypatch)
    form = {"username": "retry", "email": "r@x.io", "phone": "0771234567",
            "password": "a-long-password", "password2": "a-long-password"}
    sid = client.post("/signup", data=form, follow_redirects=False).headers["location"].rsplit("/", 1)[1]
    boom = {"on": True}

    def flaky(u, g):
        if boom["on"]:
            raise directory.DirectoryError("group missing")
        st["groups"].setdefault(u, []).append(g)

    monkeypatch.setattr(directory, "add_to_group", flaky)
    from app import services
    assert "group missing" in services.approve(sid, "root1", False)
    with db.conn() as c:
        row = c.execute("SELECT status, stage, error FROM signups").fetchone()
    assert (row["status"], row["stage"]) == ("pending", 2) and "group missing" in row["error"]
    boom["on"] = False
    assert services.approve(sid, "root1", False) is None
    assert st["calls"] == ["create", "pw"]  # earlier steps were not repeated


def test_signup_validation(client, monkeypatch):
    fake_dir(monkeypatch)
    base = {"username": "ok-user", "email": "n@x.io", "phone": "0771234567",
            "password": "a-long-password", "password2": "a-long-password"}
    for bad in ({"username": "admin"}, {"username": "guest-abc"}, {"username": "9bad"},
                {"email": "nope"}, {"phone": "12"}, {"password": "short", "password2": "short"},
                {"password2": "different-pass"}):
        main.sec.LIMITER.hits.clear()
        r = client.post("/signup", data={**base, **bad})
        assert r.status_code == 400, bad
    main.sec.LIMITER.hits.clear()
    assert client.post("/signup", data=base, follow_redirects=False).status_code == 303


def test_radius_endpoints_are_protected(client):
    body = {"User-Name": "a", "User-Password": "b"}
    assert client.post("/internal/radius/authorize", json=body, headers=BASIC).status_code == 403  # wrong IP
    client.test_ip = "10.20.0.21"
    assert client.post("/internal/radius/authorize", json=body).status_code == 403  # no password
    wrong = {"Authorization": "Basic " + base64.b64encode(b"radius:bad").decode()}
    assert client.post("/internal/radius/authorize", json=body, headers=wrong).status_code == 403


def test_accounting_and_admin_ip_from_session(client, monkeypatch):
    st = fake_dir(monkeypatch, {"boss": "adminpassword1"})
    st["groups"]["boss"] = ["media_admin", "media_members"]
    tok = token_from(client.post("/login", data={"username": "boss", "password": "adminpassword1",
                                                 "mac": MAC}).text)
    j = radius(client, "boss", tok).json()
    assert j["reply:Mikrotik-Group"] == "admin" and "reply:Session-Timeout" not in j
    acct = {"Acct-Session-Id": "81700001", "Framed-IP-Address": "10.20.1.77",
            "Acct-Status-Type": {"type": "integer", "value": ["Start"]}}
    assert radius(client, "boss", "", path="accounting", extra=acct).status_code == 200
    # a device with a live admin session may open the admin pages
    client.test_ip = "10.20.1.77"
    assert client.get("/admin/login").status_code == 200
    client.test_ip = "10.20.1.78"
    assert client.get("/admin/login").status_code == 403
    interim = {**acct, "Acct-Status-Type": 3, "Acct-Input-Octets": 1000, "Acct-Output-Octets": 5000,
               "Acct-Output-Gigawords": 1}
    assert radius(client, "boss", "", path="accounting", extra=interim).status_code == 200
    with db.conn() as c:
        row = c.execute("SELECT * FROM sessions").fetchone()
    assert row["tier"] == "admin" and row["bytes_out"] == 5000 + (1 << 32) and row["stop_at"] is None
    stop = {**acct, "Acct-Status-Type": "Stop"}
    radius(client, "boss", "", path="accounting", extra=stop)
    client.test_ip = "10.20.1.77"
    assert client.get("/admin/login").status_code == 403  # session ended


def test_user_admin_actions(client, monkeypatch):
    st = fake_dir(monkeypatch, {"root1": "adminpassword1", "bob": "bobpassword12"})
    st["groups"].update({"root1": ["media_admin"], "bob": ["media_members"]})
    client.test_ip = "10.20.1.2"
    client.post("/admin/login", data={"username": "root1", "password": "adminpassword1"})
    page = client.get("/admin/users")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    client.post("/admin/users/bob/internet", data={"csrf": csrf, "on": "1"})
    assert "media_internet" in st["groups"]["bob"]
    client.post("/admin/users/bob/password", data={"csrf": csrf, "new_password": "brand-new-password"})
    assert st["users"]["bob"] == "brand-new-password"
    assert client.post("/admin/users/root1/delete", data={"csrf": csrf}).status_code == 403  # not yourself
    client.post("/admin/users/bob/delete", data={"csrf": csrf})
    assert "bob" not in st["users"]


def test_kick_session(client, monkeypatch):
    fake_dir(monkeypatch)
    monkeypatch.setattr(directory, "authenticate", lambda u, p: {"media_admin"})
    client.test_ip = "10.20.1.2"
    client.post("/admin/login", data={"username": "root1", "password": "x"})
    csrf = re.search(r'name="csrf" value="([^"]+)"', client.get("/admin/users").text)
    csrf = csrf.group(1) if csrf else main.sec.new_token()
    with db.conn() as c:
        c.execute("INSERT INTO sessions(acct_session_id,username,mac,ip,tier,start_at,updated_at) "
                  "VALUES('s1','bob','aabbccddee01','10.20.1.60','member',?,?)", (db.now(), db.now()))
    page = client.get("/admin/sessions")
    assert "bob" in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = client.post("/admin/sessions/kick", data={"csrf": csrf, "username": "bob", "mac": "aabbccddee01"},
                    follow_redirects=False)
    assert r.status_code == 303 and "not%20configured" in r.headers["location"]  # router not set up yet
    monkeypatch.setattr(routeros, "kick", lambda u, m: 1)
    r = client.post("/admin/sessions/kick", data={"csrf": csrf, "username": "bob", "mac": "aabbccddee01"},
                    follow_redirects=False)
    assert "Disconnected%201" in r.headers["location"]


def test_public_pages(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert "Log in" in client.get("/", params={"mac": MAC}).text
    assert "neverssl" in client.get("/").text
    assert client.get("/ca").status_code == 200
    assert client.get("/ca.crt").status_code == 404  # no CA file in the test setup
    assert client.get("/docs").status_code == 404


def test_purge_wipes_old_data(client):
    from app import services
    with db.conn() as c:
        c.execute("INSERT INTO signups(id,username,email,phone,password_enc,created_at) VALUES('x','old','a@b.cc','1234567',x'00',?)",
                  (db.now() - 40 * 86400,))
    services.purge()
    with db.conn() as c:
        row = c.execute("SELECT status, password_enc FROM signups WHERE id='x'").fetchone()
    assert row["status"] == "rejected" and row["password_enc"] is None


def test_pending_user_sees_waiting_message(client, monkeypatch):
    fake_dir(monkeypatch)
    form = {"username": "waiter", "email": "w@x.io", "phone": "0771234567",
            "password": "a-long-password", "password2": "a-long-password"}
    assert client.post("/signup", data=form, follow_redirects=False).status_code == 303
    r = client.post("/login", data={"username": "waiter", "password": "a-long-password", "mac": MAC})
    assert r.status_code == 403 and "waiting for an administrator" in r.text
    # a wrong password gets the normal message, so the pending state cannot be probed
    r = client.post("/login", data={"username": "waiter", "password": "guess-guess-1", "mac": MAC})
    assert r.status_code == 401 and "waiting" not in r.text
    # waiting messages do not count toward the lockout
    for _ in range(6):
        client.post("/login", data={"username": "waiter", "password": "a-long-password", "mac": MAC})
    assert client.post("/login", data={"username": "waiter", "password": "a-long-password",
                                       "mac": MAC}).status_code == 403


class _Req:
    def __init__(self, peer, xff=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff} if xff else {}


def test_client_address_behind_caddy():
    # direct connection: header is ignored, so it cannot be spoofed
    assert REAL_IP_OF(_Req("10.20.1.50", "10.20.1.2")) == "10.20.1.50"
    # from Caddy: use the last entry, which Caddy added itself
    assert REAL_IP_OF(_Req("10.20.0.11", "10.20.1.2, 10.20.1.60")) == "10.20.1.60"
    assert REAL_IP_OF(_Req("10.20.0.11")) == "10.20.0.11"
