"""Captive portal: login, guest, sign-up, RADIUS decisions, admin pages."""
import asyncio
import base64
import ipaddress
import logging
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import Body, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import config, db, directory, routeros, services
from . import security as sec

S = config.S
log = logging.getLogger("portal")
BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))


def _fmt_time(ts):
    import time
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""


def _fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


templates.env.filters["ftime"] = _fmt_time
templates.env.filters["fbytes"] = _fmt_bytes


async def _housekeeping():
    while True:
        await asyncio.sleep(3600)
        try:
            await asyncio.to_thread(services.purge)
        except Exception:
            log.exception("housekeeping failed")


@asynccontextmanager
async def lifespan(app):
    if not os.environ.get("PORTAL_TESTING"):
        config.require_secrets()
    db.init()
    await asyncio.to_thread(services.purge)
    task = asyncio.create_task(_housekeeping())
    yield
    task.cancel()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=config.S.session_secret or "unset",
                   same_site="lax", https_only=False, max_age=3600, session_cookie="portal_session")


# ---- helpers ---------------------------------------------------------------------------

def ip_of(request: Request) -> str:
    """The client's address. Behind Caddy (a trusted proxy) use the last X-Forwarded-For entry,
    which is the address Caddy itself saw; anything the client put before it is ignored."""
    peer = request.client.host if request.client else ""
    if peer in config.S.trusted_proxies:
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
        if forwarded:
            return forwarded
    return peer


def pending_hint(username: str, password: str) -> str:
    """Tell a user whose sign-up is still waiting that this is why login fails.
    Only shown when the password matches the one in the request, so names cannot be probed."""
    with db.conn() as c:
        r = c.execute("SELECT password_enc FROM signups WHERE username=? AND status='pending'",
                      (username,)).fetchone()
    if r and r["password_enc"]:
        try:
            if sec.eq(sec.decrypt(r["password_enc"]), password):
                return "Your sign-up is still waiting for an administrator to approve it."
        except Exception:
            return ""
    return ""


def render(request: Request, name: str, status: int = 200, **ctx):
    return templates.TemplateResponse(request, name, ctx, status_code=status)


def notice(request: Request, title: str, text: str, status: int = 200):
    return render(request, "notice.html", status, title=title, text=text)


def issue_token(username: str, tier: str, mac: str) -> str:
    token = sec.new_token()
    t = db.now()
    with db.conn() as c:
        c.execute("INSERT INTO login_tokens(token_hash, username, tier, mac, created_at, expires_at) "
                  "VALUES(?,?,?,?,?,?)", (sec.hash_token(token), username, tier, mac, t, t + S.token_ttl))
    return token


def handoff(request: Request, username: str, token: str, tier: str):
    landing = S.landing_guest if tier == "guest" else S.landing_member
    return render(request, "handoff.html", action=config.S.hotspot_login_url,
                  username=username, token=token, landing=landing)


def tier_attrs(tier: str) -> dict:
    s = config.S
    if tier == "guest":
        secs, idle = s.guest_seconds, s.guest_idle
    elif tier == "admin":
        secs, idle = 0, 0
    else:
        secs, idle = s.member_seconds, s.member_idle
    reply = {"control:Auth-Type": "Accept", "reply:Mikrotik-Group": tier}
    if secs:
        reply["reply:Session-Timeout"] = secs
    if idle:
        reply["reply:Idle-Timeout"] = idle
    if tier == "internet" and s.internet_rate:
        reply["reply:Mikrotik-Rate-Limit"] = s.internet_rate
    return reply


# ---- public pages ----------------------------------------------------------------------

@app.get("/healthz")
def healthz():
    with db.conn() as c:
        c.execute("SELECT 1").fetchone()
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request, mac: str = "", err: str = ""):
    return render(request, "index.html", mac=sec.norm_mac(mac), router_error=bool(err), error="")


@app.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form(""), mac: str = Form("")):
    ip, m, u = ip_of(request), sec.norm_mac(mac), username.strip().lower()
    if not m:
        return notice(request, "Open a website first",
                      "Disconnect and reconnect to the Wi-Fi, then open any http:// website "
                      "(for example neverssl.com) so the router can send you here.", 400)
    if not (sec.LIMITER.allow(f"login:ip:{ip}", 20, 60) and sec.LIMITER.allow(f"login:mac:{m}", 20, 60)):
        return notice(request, "Too many attempts", "Wait a minute, then try again.", 429)
    if sec.LIMITER.count(f"fail:{u}", 300) >= 5:
        return notice(request, "Account locked for a few minutes",
                      "Too many wrong passwords. Try again in 5 minutes.", 429)
    try:
        groups = directory.authenticate(u, password)
    except directory.DirectoryError:
        log.exception("directory error during login")
        return notice(request, "Login service unavailable", "Tell the administrator.", 503)
    if groups is None:
        hint = pending_hint(u, password)
        if hint:
            return render(request, "index.html", 403, mac=m, router_error=False, error=hint)
        sec.LIMITER.add(f"fail:{u}")
        with db.conn() as c:
            db.audit(c, ip, "login-failed", u)
        return render(request, "index.html", 401, mac=m, router_error=False,
                      error="Wrong username or password.")
    tier = directory.tier_for(groups)
    if tier is None:
        return render(request, "index.html", 403, mac=m, router_error=False,
                      error="This account is not active yet.")
    sec.LIMITER.reset(f"fail:{u}")
    token = issue_token(u, tier, m)
    with db.conn() as c:
        db.audit(c, ip, "login", u, tier)
    return handoff(request, u, token, tier)


@app.post("/guest")
def guest(request: Request, mac: str = Form("")):
    ip, m = ip_of(request), sec.norm_mac(mac)
    if not m:
        return notice(request, "Open a website first",
                      "Open any http:// website so the router can send you here.", 400)
    if not sec.LIMITER.allow(f"guest:ip:{ip}", 10, 60):
        return notice(request, "Too many attempts", "Wait a minute, then try again.", 429)
    t = db.now()
    username = "guest-" + secrets.token_hex(3)
    with db.conn() as c:
        n = c.execute("SELECT COUNT(*) FROM guest_vouchers WHERE mac=? AND created_at>?",
                      (m, t - 86400)).fetchone()[0]
        if n >= config.S.guest_per_day:
            return notice(request, "Guest limit reached",
                          "This device has used its guest sessions for today. Sign up for an account.", 429)
        c.execute("INSERT INTO guest_vouchers(username, mac, created_at, expires_at) VALUES(?,?,?,?)",
                  (username, m, t, t + config.S.guest_seconds))
        db.audit(c, ip, "guest", username, m)
    return handoff(request, username, issue_token(username, "guest", m), "guest")


@app.get("/signup", response_class=HTMLResponse)
def signup_form(request: Request):
    return render(request, "signup.html", errors=[], v={})


@app.post("/signup")
def signup_post(request: Request, username: str = Form(""), email: str = Form(""), phone: str = Form(""),
                password: str = Form(""), password2: str = Form("")):
    ip = ip_of(request)
    u, email, phone = username.strip().lower(), email.strip(), phone.strip()
    if not sec.LIMITER.allow(f"signup:ip:{ip}", 5, 3600):
        return notice(request, "Too many requests", "Try again later.", 429)
    errors = []
    if not sec.valid_signup_username(u):
        errors.append("Username: 3-24 characters, starting with a letter; use letters, digits, . _ - only.")
    if not sec.valid_email(email):
        errors.append("Enter a valid email address.")
    if not sec.valid_phone(phone):
        errors.append("Enter a valid phone number (7-15 digits).")
    if not (10 <= len(password) <= 128):
        errors.append("Password: at least 10 characters.")
    elif password.lower() == u:
        errors.append("The password cannot be your username.")
    if password != password2:
        errors.append("The two passwords do not match.")
    if not errors:
        try:
            taken = directory.user_exists(u)
        except directory.DirectoryError:
            return notice(request, "Sign-up unavailable", "Tell the administrator.", 503)
        sid = secrets.token_urlsafe(12)
        if not taken:
            try:
                with db.conn() as c:
                    c.execute("INSERT INTO signups(id, username, email, phone, password_enc, created_at) "
                              "VALUES(?,?,?,?,?,?)", (sid, u, email, phone, sec.encrypt(password), db.now()))
                    db.audit(c, ip, "signup", u)
            except sqlite3.IntegrityError:
                taken = True
        if taken:
            errors.append("That username is not available.")
        else:
            return RedirectResponse(f"/signup/{sid}", status_code=303)
    return render(request, "signup.html", 400, errors=errors, v={"username": u, "email": email, "phone": phone})


@app.get("/signup/{sid}", response_class=HTMLResponse)
def signup_status(request: Request, sid: str):
    with db.conn() as c:
        r = c.execute("SELECT username, status, reason FROM signups WHERE id=?", (sid[:40],)).fetchone()
    if not r:
        return notice(request, "Request not found", "It may have been removed.", 404)
    return render(request, "signup_status.html", r=r)


@app.get("/ca", response_class=HTMLResponse)
def ca_page(request: Request):
    return render(request, "ca.html")


@app.get("/ca.crt")
def ca_file():
    if not Path(config.S.ca_file).is_file():
        raise HTTPException(404, "CA certificate is not installed on the portal")
    return FileResponse(config.S.ca_file, media_type="application/x-x509-ca-cert", filename="media-lan-ca.crt")


# ---- FreeRADIUS callbacks (source address + password) ------------------------------------

def radius_guard(request: Request) -> None:
    s = config.S
    ok_ip = ip_of(request) == s.radius_ip
    ok_pw = False
    auth = request.headers.get("authorization", "")
    if auth.startswith("Basic "):
        try:
            user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            ok_pw = sec.eq(user, s.radius_user) and sec.eq(pw, s.radius_pass) and bool(s.radius_pass)
        except Exception:
            ok_pw = False
    if not (ok_ip and ok_pw):
        raise HTTPException(403, "forbidden")


def attr(body: dict, name: str, default=""):
    """FreeRADIUS sends {"Name": {"type": "...", "value": ["x"]}}; accept plain values too."""
    v = body.get(name)
    if isinstance(v, dict):
        v = v.get("value")
    if isinstance(v, list):
        v = v[0] if v else None
    return default if v is None else v


@app.post("/internal/radius/authorize")
def radius_authorize(body: dict = Body(...), _: None = Depends(radius_guard)):
    user = str(attr(body, "User-Name")).strip().lower()
    secret = str(attr(body, "User-Password"))
    mac = sec.norm_mac(str(attr(body, "Calling-Station-Id")))
    t = db.now()
    with db.conn() as c:
        row = c.execute("SELECT * FROM login_tokens WHERE token_hash=? AND username=?",
                        (sec.hash_token(secret), user)).fetchone()
        good = bool(row and not row["used_at"] and row["expires_at"] >= t and mac and row["mac"] == mac)
        if good:  # single use: only one request can flip used_at
            good = c.execute("UPDATE login_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL",
                             (t, row["token_hash"])).rowcount == 1
        db.audit(c, "radius", "accept" if good else "reject", user, mac)
    if not good:
        return JSONResponse({}, status_code=401)
    return tier_attrs(row["tier"])


STATUS = {1: "Start", 2: "Stop", 3: "Interim-Update"}


def _octets(body: dict, low: str, high: str) -> int:
    try:
        return int(attr(body, low, 0)) + (int(attr(body, high, 0)) << 32)
    except (TypeError, ValueError):
        return 0


@app.post("/internal/radius/accounting")
def radius_accounting(body: dict = Body(...), _: None = Depends(radius_guard)):
    status = attr(body, "Acct-Status-Type")
    status = STATUS.get(int(status), status) if str(status).isdigit() else status
    sid = str(attr(body, "Acct-Session-Id"))
    if status not in ("Start", "Stop", "Interim-Update") or not sid:
        return {}
    user = str(attr(body, "User-Name")).lower()
    mac = sec.norm_mac(str(attr(body, "Calling-Station-Id")))
    ip = str(attr(body, "Framed-IP-Address"))
    bin_, bout = _octets(body, "Acct-Input-Octets", "Acct-Input-Gigawords"), \
        _octets(body, "Acct-Output-Octets", "Acct-Output-Gigawords")
    t = db.now()
    with db.conn() as c:
        tier = c.execute("SELECT tier FROM login_tokens WHERE username=? AND used_at IS NOT NULL "
                         "ORDER BY used_at DESC LIMIT 1", (user,)).fetchone()
        c.execute(
            "INSERT INTO sessions(acct_session_id, username, mac, ip, tier, start_at, stop_at, bytes_in, "
            "bytes_out, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(acct_session_id) DO UPDATE SET bytes_in=excluded.bytes_in, "
            "bytes_out=excluded.bytes_out, updated_at=excluded.updated_at, ip=excluded.ip, "
            "stop_at=excluded.stop_at",
            (sid, user, mac, ip, tier["tier"] if tier else "", t, t if status == "Stop" else None,
             bin_, bout, t))
    return {}


# ---- admin pages -----------------------------------------------------------------------

def admin_ip_ok(request: Request) -> bool:
    try:
        addr = ipaddress.ip_address(ip_of(request))
    except ValueError:
        return False
    if any(addr in n for n in config.S.admin_nets):
        return True
    with db.conn() as c:
        return bool(c.execute("SELECT 1 FROM sessions WHERE ip=? AND tier='admin' AND stop_at IS NULL "
                              "AND updated_at>?", (str(addr), db.now() - 1800)).fetchone())


def admin_guard(request: Request, csrf=None):
    """Return (admin username, None) or (None, response to send instead)."""
    if not admin_ip_ok(request):
        return None, notice(request, "Not allowed", "Admin pages open only from an administrator device.", 403)
    user = request.session.get("admin")
    if not user:
        return None, RedirectResponse("/admin/login", status_code=303)
    if csrf is not None and not sec.eq(csrf, request.session.get("csrf", "")):
        return None, notice(request, "Page expired", "Go back, reload the page and try again.", 403)
    return user, None


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_form(request: Request):
    if not admin_ip_ok(request):
        return notice(request, "Not allowed", "Admin pages open only from an administrator device.", 403)
    return render(request, "admin_login.html", error="")


@app.post("/admin/login")
def admin_login(request: Request, username: str = Form(""), password: str = Form("")):
    if not admin_ip_ok(request):
        return notice(request, "Not allowed", "Admin pages open only from an administrator device.", 403)
    u = username.strip().lower()
    if not sec.LIMITER.allow(f"adminlogin:{ip_of(request)}", 10, 300) or sec.LIMITER.count(f"fail:{u}", 300) >= 5:
        return notice(request, "Too many attempts", "Wait 5 minutes.", 429)
    try:
        groups = directory.authenticate(u, password)
    except directory.DirectoryError:
        return notice(request, "Directory unavailable", "LLDAP did not answer.", 503)
    if groups is None or "media_admin" not in groups:
        sec.LIMITER.add(f"fail:{u}")
        with db.conn() as c:
            db.audit(c, ip_of(request), "admin-login-failed", u)
        return render(request, "admin_login.html", 401, error="Wrong username or password, or not an admin.")
    request.session.clear()
    request.session.update({"admin": u, "csrf": secrets.token_urlsafe(16)})
    with db.conn() as c:
        db.audit(c, u, "admin-login", "", ip_of(request))
    return RedirectResponse("/admin/signups", status_code=303)


@app.get("/admin/logout")
def admin_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/admin/signups", response_class=HTMLResponse)
def admin_signups(request: Request):
    user, resp = admin_guard(request)
    if resp:
        return resp
    with db.conn() as c:
        pending = c.execute("SELECT * FROM signups WHERE status='pending' ORDER BY created_at").fetchall()
        done = c.execute("SELECT * FROM signups WHERE status!='pending' ORDER BY decided_at DESC LIMIT 20").fetchall()
    return render(request, "admin_signups.html", admin=user, csrf=request.session["csrf"],
                  pending=pending, done=done, msg=request.query_params.get("msg", ""))


@app.post("/admin/signups/{sid}/approve")
def admin_approve(request: Request, sid: str, csrf: str = Form(""), internet: str = Form("")):
    user, resp = admin_guard(request, csrf)
    if resp:
        return resp
    err = services.approve(sid[:40], user, bool(internet))
    return RedirectResponse("/admin/signups" + (f"?msg={quote(err)}" if err else ""), status_code=303)


@app.post("/admin/signups/{sid}/reject")
def admin_reject(request: Request, sid: str, csrf: str = Form(""), reason: str = Form("")):
    user, resp = admin_guard(request, csrf)
    if resp:
        return resp
    err = services.reject(sid[:40], user, reason.strip() or "rejected")
    return RedirectResponse("/admin/signups" + (f"?msg={quote(err)}" if err else ""), status_code=303)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request):
    user, resp = admin_guard(request)
    if resp:
        return resp
    try:
        users, error = directory.list_users(), ""
    except directory.DirectoryError as e:
        users, error = [], str(e)
    with db.conn() as c:
        contacts = {r["username"]: r for r in c.execute("SELECT username, email, phone FROM signups "
                                                         "WHERE status='approved'")}
    return render(request, "admin_users.html", admin=user, csrf=request.session["csrf"], users=users,
                  contacts=contacts, error=error, msg=request.query_params.get("msg", ""))


def _user_action(request: Request, name: str, csrf: str, fn):
    user, resp = admin_guard(request, csrf)
    if resp:
        return resp
    if not sec.valid_login_username(name) or name == user or name in ("admin", config.S.ldap_bind_user):
        return notice(request, "Not allowed", "That account cannot be changed here.", 403)
    try:
        msg = fn(user, name) or "Done."
    except directory.DirectoryError as e:
        msg = f"Failed: {e}"
    return RedirectResponse(f"/admin/users?msg={quote(msg)}", status_code=303)


@app.post("/admin/users/{name}/internet")
def admin_internet(request: Request, name: str, csrf: str = Form(""), on: str = Form("0")):
    def run(admin, n):
        (directory.add_to_group if on == "1" else directory.remove_from_group)(n, "media_internet")
        with db.conn() as c:
            db.audit(c, admin, "internet-on" if on == "1" else "internet-off", n)
    return _user_action(request, name, csrf, run)


@app.post("/admin/users/{name}/password")
def admin_password(request: Request, name: str, csrf: str = Form(""), new_password: str = Form("")):
    def run(admin, n):
        if not 10 <= len(new_password) <= 128:
            return "Password must be 10-128 characters."
        directory.set_password(n, new_password)
        with db.conn() as c:
            db.audit(c, admin, "password-reset", n)
    return _user_action(request, name, csrf, run)


@app.post("/admin/users/{name}/delete")
def admin_delete(request: Request, name: str, csrf: str = Form("")):
    def run(admin, n):
        directory.delete_user(n)
        with db.conn() as c:
            c.execute("DELETE FROM signups WHERE username=?", (n,))
            db.audit(c, admin, "user-deleted", n)
        return "User deleted. Remove the Navidrome account by hand until phase 5 adds sync."
    return _user_action(request, name, csrf, run)


@app.get("/admin/sessions", response_class=HTMLResponse)
def admin_sessions(request: Request):
    user, resp = admin_guard(request)
    if resp:
        return resp
    with db.conn() as c:
        rows = c.execute("SELECT * FROM sessions WHERE stop_at IS NULL AND updated_at>? "
                         "ORDER BY start_at DESC", (db.now() - 1800,)).fetchall()
    return render(request, "admin_sessions.html", admin=user, csrf=request.session["csrf"], rows=rows,
                  msg=request.query_params.get("msg", ""))


@app.post("/admin/sessions/kick")
def admin_kick(request: Request, csrf: str = Form(""), username: str = Form(""), mac: str = Form("")):
    user, resp = admin_guard(request, csrf)
    if resp:
        return resp
    try:
        n = routeros.kick(username, mac)
        msg = f"Disconnected {n} session(s)."
        with db.conn() as c:
            db.audit(c, user, "kick", username, mac)
    except routeros.RouterError as e:
        msg = f"Failed: {e}"
    return RedirectResponse(f"/admin/sessions?msg={quote(msg)}", status_code=303)
