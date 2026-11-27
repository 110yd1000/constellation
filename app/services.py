"""Approval and rejection of sign-ups. Each step is saved, so a retry resumes where it stopped."""
import logging

from . import db, directory, security as sec

log = logging.getLogger("portal.services")


def _stage(sid: str, stage: int) -> int:
    with db.conn() as c:
        c.execute("UPDATE signups SET stage=? WHERE id=?", (stage, sid))
    return stage


def approve(sid: str, admin: str, internet: bool):
    """Return None on success, or an error message (the sign-up stays pending)."""
    with db.conn() as c:
        r = c.execute("SELECT * FROM signups WHERE id=?", (sid,)).fetchone()
    if not r or r["status"] != "pending" or not r["password_enc"]:
        return "That request is not pending."
    u = r["username"]
    try:
        password = sec.decrypt(r["password_enc"])
        stage = r["stage"]
        if stage < 1:
            if directory.user_exists(u):
                raise directory.DirectoryError(f"{u} already exists in LLDAP")
            directory.create_user(u, r["email"], u)
            stage = _stage(sid, 1)
        if stage < 2:
            directory.set_password(u, password)
            stage = _stage(sid, 2)
        if stage < 3:
            directory.add_to_group(u, "media_members")
            if internet:
                directory.add_to_group(u, "media_internet")
            stage = _stage(sid, 3)
        if stage < 4:
            directory.navidrome_create(u, password, r["email"])
            stage = _stage(sid, 4)
    except Exception as e:  # keep the request pending and show the reason to the admin
        log.exception("approval of %s failed", u)
        with db.conn() as c:
            c.execute("UPDATE signups SET error=? WHERE id=?", (str(e)[:300], sid))
            db.audit(c, admin, "approve-failed", u, str(e))
        return str(e)
    with db.conn() as c:
        c.execute(
            "UPDATE signups SET status='approved', password_enc=NULL, internet=?, error=NULL, "
            "decided_by=?, decided_at=? WHERE id=?", (1 if internet else 0, admin, db.now(), sid))
        db.audit(c, admin, "approve", u, "internet" if internet else "member")
    return None


def reject(sid: str, admin: str, reason: str):
    with db.conn() as c:
        r = c.execute("SELECT * FROM signups WHERE id=?", (sid,)).fetchone()
    if not r or r["status"] != "pending":
        return "That request is not pending."
    if r["stage"] >= 1:  # a half-finished approval left an LLDAP user behind
        try:
            directory.delete_user(r["username"])
        except directory.DirectoryError as e:
            return f"Could not remove the partly created user: {e}"
    with db.conn() as c:
        c.execute(
            "UPDATE signups SET status='rejected', password_enc=NULL, reason=?, error=NULL, "
            "decided_by=?, decided_at=? WHERE id=?", (reason[:200], admin, db.now(), sid))
        db.audit(c, admin, "reject", r["username"], reason)
    return None


def purge() -> None:
    """Hourly housekeeping: expired tokens, old records, stale sessions, memory counters."""
    t = db.now()
    with db.conn() as c:
        c.execute("DELETE FROM login_tokens WHERE created_at < ?", (t - 86400,))
        c.execute("DELETE FROM guest_vouchers WHERE created_at < ?", (t - 2 * 86400,))
        c.execute("UPDATE signups SET status='rejected', password_enc=NULL, reason='expired', "
                  "decided_by='system', decided_at=? WHERE status='pending' AND created_at < ?",
                  (t, t - 30 * 86400))
        c.execute("DELETE FROM signups WHERE status='rejected' AND COALESCE(decided_at, created_at) < ?",
                  (t - 7 * 86400,))
        c.execute("UPDATE sessions SET stop_at=updated_at WHERE stop_at IS NULL AND updated_at < ?",
                  (t - 3600,))
        c.execute("DELETE FROM sessions WHERE stop_at IS NOT NULL AND stop_at < ?", (t - 90 * 86400,))
        c.execute("DELETE FROM audit_log WHERE ts < ?", (t - 180 * 86400,))
    sec.LIMITER.purge()
