"""Validation, hashing, encryption and rate limiting helpers."""
import hashlib
import hmac
import re
import secrets
import time
from collections import defaultdict, deque

from cryptography.fernet import Fernet

from . import config

SIGNUP_USER_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,23}$")
LOGIN_USER_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
PHONE_RE = re.compile(r"^[0-9+()\-\s.]{7,25}$")
RESERVED = {
    "admin", "administrator", "root", "portal", "authelia", "jellyfin", "navidrome",
    "guest", "lldap", "radius", "system", "public", "media", "test",
}


def valid_signup_username(u: str) -> bool:
    return bool(SIGNUP_USER_RE.match(u or "")) and u not in RESERVED and not u.startswith("guest-")


def valid_login_username(u: str) -> bool:
    return bool(LOGIN_USER_RE.match(u or ""))


def valid_email(e: str) -> bool:
    return bool(EMAIL_RE.match(e or ""))


def valid_phone(p: str) -> bool:
    digits = re.sub(r"\D", "", p or "")
    return bool(PHONE_RE.match((p or "").strip())) and 7 <= len(digits) <= 15


def norm_mac(m: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", m or "").lower()
    return h if len(h) == 12 else ""


def hash_token(t: str) -> str:
    return hashlib.sha256((t or "").encode()).hexdigest()


def eq(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


def new_token() -> str:
    return secrets.token_urlsafe(24)


_fernet = None


def _f() -> Fernet:
    global _fernet
    if _fernet is None or getattr(_fernet, "_key_src", None) != config.S.fernet_key:
        _fernet = Fernet(config.S.fernet_key.encode())
        _fernet._key_src = config.S.fernet_key
    return _fernet


def encrypt(text: str) -> bytes:
    return _f().encrypt(text.encode())


def decrypt(blob: bytes) -> str:
    return _f().decrypt(blob).decode()


class Limiter:
    """In-memory sliding-window counters. Resets on restart, which is fine here."""

    def __init__(self) -> None:
        self.hits = defaultdict(deque)

    def count(self, key: str, window: float) -> int:
        q = self.hits[key]
        cutoff = time.monotonic() - window
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def add(self, key: str) -> None:
        self.hits[key].append(time.monotonic())

    def allow(self, key: str, limit: int, window: float) -> bool:
        if self.count(key, window) >= limit:
            return False
        self.add(key)
        return True

    def reset(self, key: str) -> None:
        self.hits.pop(key, None)

    def purge(self, window: float = 3700) -> None:
        for k in list(self.hits):
            if self.count(k, window) == 0:
                self.hits.pop(k, None)


LIMITER = Limiter()
