"""Cryptographic signing, password hashing, validation, and rate limiting for Imran Cloud Control Plane."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict


def hash_password(password: str, salt: str | None = None) -> str:
    salt_hex = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_hex.encode("utf-8"), 200_000)
    return f"pbkdf2_sha256${salt_hex}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, salt_hex, expected_hex = stored_hash.split("$", 2)
        if algo != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_hex.encode("utf-8"), 200_000).hex()
        return hmac.compare_digest(actual, expected_hex)
    except Exception:
        return False


def sign_payload(payload: dict, secret: str) -> str:
    """Create a tamper-proof HMAC-SHA256 signed token (base64url payload + signature)."""
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def verify_signed_payload(token: str, secret: str) -> dict | None:
    try:
        if not token or "." not in token:
            return None
        b64, sig = token.rsplit(".", 1)
        expected = hmac.new(secret.encode("utf-8"), b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        pad = "=" * (-len(b64) % 4)
        return json.loads(base64.urlsafe_b64decode(b64 + pad).decode("utf-8"))
    except Exception:
        return None


def compute_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_release_hash(version: str, sha256_hex: str, signing_secret: str) -> str:
    """Cryptographic release signature over version + sha256."""
    msg = f"IMRAN_RELEASE_V1:{version.strip()}:{sha256_hex.strip().lower()}".encode("utf-8")
    return hmac.new(signing_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_release_signature(version: str, sha256_hex: str, signature: str, signing_secret: str) -> bool:
    if not version or not sha256_hex or not signature:
        return False
    expected = sign_release_hash(version, sha256_hex, signing_secret)
    return hmac.compare_digest(expected.lower(), signature.strip().lower())


def generate_license_key(plan: str = "lifetime") -> str:
    p = (plan or "lifetime").lower()
    prefix = "VIP" if "life" in p else ("YR" if "year" in p else ("GIFT" if "gift" in p else "MTH"))
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    return f"ICS-{prefix}-{parts[0]}-{parts[1]}-{parts[2]}-{parts[3]}"


def sanitize_device_id(raw: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_\-]", "", (raw or "").strip())
    return clean[:64]


def sanitize_version(raw: str) -> str:
    clean = re.sub(r"[^0-9.]", "", (raw or "").strip())
    return clean[:32] or "2.0.0"


def compare_versions(v1: str, v2: str) -> int:
    """Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
    def _parts(v):
        return [int(x) for x in re.findall(r"\d+", str(v or "0"))] or [0]
    p1, p2 = _parts(v1), _parts(v2)
    m = max(len(p1), len(p2))
    p1 += [0] * (m - len(p1))
    p2 += [0] * (m - len(p2))
    return (p1 > p2) - (p1 < p2)


class RateLimiter:
    """Thread-safe sliding window per-IP rate limiter."""
    def __init__(self, max_requests: int = 120, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            q = [t for t in self._hits[key] if t > cutoff]
            if len(q) >= self.max_requests:
                self._hits[key] = q
                return False
            q.append(now)
            self._hits[key] = q
            return True
