#!/usr/bin/env python3
"""
Imran Creator Suite — Lightweight Cloud Control Plane & Private Owner Admin Dashboard.
Handles ONLY: 72-Hour Trials, Paid Licensing, Device Management, Signed Updates,
Remote Feature Flags/Config, Announcements, and Audit Logs.
(Zero video processing or downloading happens here — all media stays 100% local on users' PCs.)
"""
import functools
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix

from db import DBConn, get_all_config, init_db, log_event, set_config_values, utc_now_iso
from security import (
    RateLimiter,
    compare_versions,
    compute_sha256_file,
    generate_license_key,
    hash_password,
    sanitize_device_id,
    sanitize_version,
    sign_payload,
    sign_release_hash,
    verify_password,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RELEASES_DIR = os.path.join(BASE_DIR, "releases_store")
os.makedirs(RELEASES_DIR, exist_ok=True)

app = Flask(__name__, template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "imran-cloud-dev-secret-change-in-prod-2026"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=365)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["MAX_CONTENT_LENGTH"] = 250 * 1024 * 1024  # 250 MB max release upload

# Secrets (loaded from environment variables on Render/VPS; safe dev defaults for local testing)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "imran_admin")
_ADMIN_PW_PLAIN = os.environ.get("ADMIN_PASSWORD", "ImranAdmin@2026")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH") or hash_password(_ADMIN_PW_PLAIN)
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "dev-admin-publish-key-change-me")
SIGNING_SECRET = os.environ.get("UPDATE_SIGNING_SECRET", "imran-signing-secret-v1-change-in-prod")
PAYMENT_WEBHOOK_SECRET = os.environ.get("PAYMENT_WEBHOOK_SECRET", "")

client_limiter = RateLimiter(max_requests=120, window_seconds=60)
admin_login_limiter = RateLimiter(max_requests=15, window_seconds=300)


def _client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return (request.remote_addr or "0.0.0.0")[:64]


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _is_admin_authed() -> bool:
    if session.get("admin_ok") and session.get("admin_user") == ADMIN_USERNAME:
        return True
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:].strip(), ADMIN_API_KEY):
        return True
    api_key = request.headers.get("X-Admin-Key", "").strip()
    if api_key and secrets.compare_digest(api_key, ADMIN_API_KEY):
        return True
    tok = request.cookies.get("imran_admin_token", "").strip()
    if tok and secrets.compare_digest(tok, ADMIN_API_KEY):
        return True
    if _client_ip() in ("127.0.0.1", "::1", "localhost") and session.get("admin_ok"):
        return True
    return False


def require_admin(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _is_admin_authed():
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


def _evaluate_device_access(db: DBConn, device: dict, cfg: dict) -> dict:
    """Computes authoritative server-side access state: blocked, pro, trial, or expired."""
    now = datetime.now(timezone.utc)
    device_id = device["device_id"]

    if device.get("status") == "blocked":
        return {
            "status": "blocked",
            "has_premium": False,
            "plan": None,
            "license_key": None,
            "expires_at": None,
            "trial_started_at": device["trial_started_at"],
            "trial_expires_at": device["trial_expires_at"],
            "trial_remaining_seconds": 0,
            "message": "This device has been blocked by the administrator.",
        }

    # 1. Check active license activations for this device
    act = db.fetchone(
        """
        SELECT l.id AS license_id, l.license_key, l.plan, l.status AS lic_status,
               l.expires_at, l.max_devices, a.activated_at
        FROM license_activations a
        JOIN licenses l ON l.id = a.license_id
        WHERE a.device_id = ? AND a.active = 1
        ORDER BY a.id DESC LIMIT 1
        """,
        (device_id,),
    )
    if act:
        lic_status = act["lic_status"]
        exp_dt = _parse_iso(act["expires_at"])
        if lic_status == "revoked":
            return {
                "status": "revoked",
                "has_premium": False,
                "plan": act["plan"],
                "license_key": act["license_key"],
                "expires_at": act["expires_at"],
                "trial_started_at": device["trial_started_at"],
                "trial_expires_at": device["trial_expires_at"],
                "trial_remaining_seconds": 0,
                "message": "Your license key has been revoked. Please contact support.",
            }
        if exp_dt and now > exp_dt:
            if lic_status != "expired":
                db.execute("UPDATE licenses SET status = 'expired' WHERE id = ?", (act["license_id"],))
            return {
                "status": "license_expired",
                "has_premium": False,
                "plan": act["plan"],
                "license_key": act["license_key"],
                "expires_at": act["expires_at"],
                "trial_started_at": device["trial_started_at"],
                "trial_expires_at": device["trial_expires_at"],
                "trial_remaining_seconds": 0,
                "message": "Your license has expired. Please renew or activate a new key.",
            }
        if lic_status == "active":
            return {
                "status": "pro",
                "has_premium": True,
                "plan": act["plan"],
                "license_key": act["license_key"],
                "expires_at": act["expires_at"],
                "max_devices": act["max_devices"],
                "trial_started_at": device["trial_started_at"],
                "trial_expires_at": device["trial_expires_at"],
                "trial_remaining_seconds": 0,
                "message": f"Active {act['plan']} license.",
            }

    # 2. Check exact 72-hour server-side trial
    trial_exp = _parse_iso(device["trial_expires_at"])
    remaining = int((trial_exp - now).total_seconds()) if trial_exp else 0
    if remaining > 0:
        return {
            "status": "trial",
            "has_premium": True,
            "plan": "3-Day Free Trial",
            "license_key": None,
            "expires_at": device["trial_expires_at"],
            "trial_started_at": device["trial_started_at"],
            "trial_expires_at": device["trial_expires_at"],
            "trial_remaining_seconds": remaining,
            "message": "3-Day Free Trial active.",
        }

    return {
        "status": "expired",
        "has_premium": False,
        "plan": None,
        "license_key": None,
        "expires_at": None,
        "trial_started_at": device["trial_started_at"],
        "trial_expires_at": device["trial_expires_at"],
        "trial_remaining_seconds": 0,
        "message": "Your 3-Day Free Trial Has Expired! Purchase a license to continue using all features.",
    }


def _get_latest_release(db: DBConn) -> dict | None:
    rows = db.fetchall("SELECT * FROM releases WHERE is_active = 1")
    if not rows:
        return None
    rows.sort(key=lambda r: [int(x) for x in r["version"].split(".") if x.isdigit()] or [0], reverse=True)
    return rows[0]


# =====================================================================
# PUBLIC CLIENT API (v1)
# =====================================================================

@app.route("/api/v1/health", methods=["GET"])
def api_health():
    return jsonify({"ok": True, "service": "imran-cloud-control", "time": utc_now_iso()})


@app.route("/api/v1/client/bootstrap", methods=["POST"])
def api_client_bootstrap():
    ip = _client_ip()
    if not client_limiter.allow(f"boot:{ip}"):
        return jsonify({"ok": False, "error": "Rate limit exceeded"}), 429

    data = request.get_json(silent=True) or {}
    device_id = sanitize_device_id(data.get("device_id", ""))
    if len(device_id) < 6:
        return jsonify({"ok": False, "error": "Invalid device_id"}), 400

    hostname = str(data.get("hostname") or "")[:120]
    os_info = str(data.get("os_info") or "")[:120]
    app_version = sanitize_version(data.get("app_version") or "2.0.0")
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now_iso = now_dt.isoformat()

    with DBConn() as db:
        cfg = get_all_config(db)
        trial_hours = int(cfg.get("trial_hours") or 72)

        device = db.fetchone("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        if not device:
            trial_exp_iso = (now_dt + timedelta(hours=trial_hours)).isoformat()
            db.execute(
                """
                INSERT INTO devices
                (device_id, hostname, os_info, app_version, status, trial_started_at, trial_expires_at, first_ip, last_ip, last_seen_at, created_at)
                VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
                """,
                (device_id, hostname, os_info, app_version, now_iso, trial_exp_iso, ip, ip, now_iso, now_iso),
            )
            log_event(db, "TRIAL_STARTED", device_id, ip, f"New device registered ({trial_hours}h trial, v{app_version})")
            device = db.fetchone("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        else:
            db.execute(
                "UPDATE devices SET hostname = ?, os_info = ?, app_version = ?, last_ip = ?, last_seen_at = ? WHERE device_id = ?",
                (hostname or device["hostname"], os_info or device["os_info"], app_version, ip, now_iso, device_id),
            )
            device["app_version"] = app_version
            device["last_seen_at"] = now_iso

        access = _evaluate_device_access(db, device, cfg)

        # Build update info
        latest = _get_latest_release(db)
        min_ver = str(cfg.get("min_supported_version") or "2.0.0")
        if latest and compare_versions(latest.get("min_supported_version") or "2.0.0", min_ver) > 0:
            min_ver = latest["min_supported_version"]

        version_blocked = compare_versions(app_version, min_ver) < 0
        dl_url = latest["download_url"] if latest else ""
        if dl_url and "/api/v1/updates/download/" in dl_url:
            fname = dl_url.split("/api/v1/updates/download/")[-1]
            dl_url = f"{request.host_url.rstrip('/')}/api/v1/updates/download/{fname}"

        update_info = {
            "current_version": app_version,
            "latest_version": latest["version"] if latest else app_version,
            "min_supported_version": min_ver,
            "update_available": bool(latest and compare_versions(latest["version"], app_version) > 0),
            "version_blocked": version_blocked,
            "is_mandatory": bool(version_blocked or (latest and latest.get("is_mandatory"))),
            "download_url": dl_url,
            "sha256": latest["sha256"] if latest else "",
            "signature": latest["signature"] if latest else "",
            "release_notes": latest["release_notes"] if latest else "",
            "file_size": latest["file_size"] if latest else 0,
        }

        # Signed offline grace token (allows local processing during temporary internet drop)
        grace_hours = int(cfg.get("offline_grace_hours") or 24)
        grace_until = (now_dt + timedelta(hours=grace_hours)).isoformat()
        token_payload = {
            "device_id": device_id,
            "status": access["status"],
            "has_premium": access["has_premium"],
            "plan": access["plan"],
            "license_key": access["license_key"],
            "expires_at": access["expires_at"],
            "trial_started_at": access["trial_started_at"],
            "trial_expires_at": access["trial_expires_at"],
            "feature_flags": cfg.get("feature_flags", {}),
            "issued_at": now_iso,
            "grace_until": grace_until,
        }
        signed_token = sign_payload(token_payload, SIGNING_SECRET)

        return jsonify({
            "ok": True,
            "server_time": now_iso,
            "device_id": device_id,
            "access": access,
            "signed_token": signed_token,
            "config": {
                "feature_flags": cfg.get("feature_flags", {}),
                "trial_hours": trial_hours,
                "min_supported_version": min_ver,
                "maintenance_mode": bool(cfg.get("maintenance_mode")),
                "maintenance_message": str(cfg.get("maintenance_message") or ""),
                "announcement_banner": str(cfg.get("announcement_banner") or ""),
                "purchase_url": str(cfg.get("purchase_url") or ""),
                "plans": cfg.get("plans", []),
            },
            "update": update_info,
        })


@app.route("/api/v1/license/activate", methods=["POST"])
def api_license_activate():
    ip = _client_ip()
    if not client_limiter.allow(f"act:{ip}"):
        return jsonify({"ok": False, "error": "Too many attempts. Please wait a minute."}), 429

    data = request.get_json(silent=True) or {}
    device_id = sanitize_device_id(data.get("device_id", ""))
    key = (data.get("license_key") or data.get("key") or "").strip().upper()
    if len(device_id) < 6 or not key:
        return jsonify({"ok": False, "error": "Device ID and License Key are required."}), 400

    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now_iso = now_dt.isoformat()

    with DBConn() as db:
        cfg = get_all_config(db)
        device = db.fetchone("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        if not device:
            trial_exp_iso = (now_dt + timedelta(hours=int(cfg.get("trial_hours") or 72))).isoformat()
            db.execute(
                """
                INSERT INTO devices
                (device_id, hostname, os_info, app_version, status, trial_started_at, trial_expires_at, first_ip, last_ip, last_seen_at, created_at)
                VALUES (?, '', '', '2.0.0', 'active', ?, ?, ?, ?, ?, ?)
                """,
                (device_id, now_iso, trial_exp_iso, ip, ip, now_iso, now_iso),
            )
            device = db.fetchone("SELECT * FROM devices WHERE device_id = ?", (device_id,))

        if device["status"] == "blocked":
            log_event(db, "ACTIVATE_BLOCKED_DEVICE", device_id, ip, f"Key={key}")
            return jsonify({"ok": False, "error": "This device is blocked."}), 403

        lic = db.fetchone("SELECT * FROM licenses WHERE license_key = ?", (key,))
        if not lic:
            log_event(db, "ACTIVATE_INVALID_KEY", device_id, ip, f"Key={key}")
            return jsonify({"ok": False, "error": "Invalid license key."}), 400

        if lic["status"] == "revoked":
            log_event(db, "ACTIVATE_REVOKED_KEY", device_id, ip, f"Key={key}")
            return jsonify({"ok": False, "error": "This license key has been revoked."}), 403

        exp_dt = _parse_iso(lic["expires_at"])
        if exp_dt and now_dt > exp_dt:
            db.execute("UPDATE licenses SET status = 'expired' WHERE id = ?", (lic["id"],))
            log_event(db, "ACTIVATE_EXPIRED_KEY", device_id, ip, f"Key={key}")
            return jsonify({"ok": False, "error": "This license key has expired."}), 403

        if lic["status"] != "active":
            return jsonify({"ok": False, "error": f"License is not active (status: {lic['status']})."}), 403

        # Check if already active on this device
        already = db.fetchone(
            "SELECT * FROM license_activations WHERE license_id = ? AND device_id = ? AND active = 1",
            (lic["id"], device_id),
        )
        if not already:
            active_rows = db.fetchall(
                "SELECT * FROM license_activations WHERE license_id = ? AND active = 1",
                (lic["id"],),
            )
            if len(active_rows) >= int(lic["max_devices"]):
                log_event(db, "ACTIVATE_LIMIT_REACHED", device_id, ip, f"Key={key} max={lic['max_devices']}")
                return jsonify({
                    "ok": False,
                    "error": f"Device limit reached ({lic['max_devices']} device(s) max). Deactivate an old PC first.",
                }), 403

            # Deactivate any other old license on this device before binding new one
            db.execute(
                "UPDATE license_activations SET active = 0, deactivated_at = ? WHERE device_id = ? AND active = 1",
                (now_iso, device_id),
            )
            db.execute(
                "INSERT INTO license_activations (license_id, device_id, activated_at, active) VALUES (?, ?, ?, 1)",
                (lic["id"], device_id, now_iso),
            )
            log_event(db, "LICENSE_ACTIVATED", device_id, ip, f"Key={key} plan={lic['plan']}")

        access = _evaluate_device_access(db, device, cfg)
        grace_until = (now_dt + timedelta(hours=int(cfg.get("offline_grace_hours") or 24))).isoformat()
        signed_token = sign_payload({
            "device_id": device_id,
            "status": access["status"],
            "has_premium": access["has_premium"],
            "plan": access["plan"],
            "license_key": access["license_key"],
            "expires_at": access["expires_at"],
            "trial_started_at": access["trial_started_at"],
            "trial_expires_at": access["trial_expires_at"],
            "feature_flags": cfg.get("feature_flags", {}),
            "issued_at": now_iso,
            "grace_until": grace_until,
        }, SIGNING_SECRET)

        return jsonify({"ok": True, "access": access, "signed_token": signed_token, "message": f"Activated {lic['plan']}!"})


@app.route("/api/v1/license/deactivate", methods=["POST"])
def api_license_deactivate():
    ip = _client_ip()
    data = request.get_json(silent=True) or {}
    device_id = sanitize_device_id(data.get("device_id", ""))
    if len(device_id) < 6:
        return jsonify({"ok": False, "error": "Invalid device_id"}), 400

    now_iso = utc_now_iso()
    with DBConn() as db:
        act = db.fetchone("SELECT * FROM license_activations WHERE device_id = ? AND active = 1", (device_id,))
        if not act:
            return jsonify({"ok": False, "error": "No active license found on this device."}), 404
        db.execute("UPDATE license_activations SET active = 0, deactivated_at = ? WHERE id = ?", (now_iso, act["id"]))
        log_event(db, "LICENSE_DEACTIVATED", device_id, ip, f"activation_id={act['id']}")
        return jsonify({"ok": True, "message": "License deactivated on this device. You can now activate it on another PC."})


@app.route("/api/v1/updates/latest", methods=["GET"])
def api_updates_latest():
    with DBConn() as db:
        cfg = get_all_config(db)
        latest = _get_latest_release(db)
        if not latest:
            return jsonify({"ok": True, "release": None, "min_supported_version": cfg.get("min_supported_version", "2.0.0")})
        rel = dict(latest)
        dl_url = rel.get("download_url", "")
        if dl_url and "/api/v1/updates/download/" in dl_url:
            fname = dl_url.split("/api/v1/updates/download/")[-1]
            rel["download_url"] = f"{request.host_url.rstrip('/')}/api/v1/updates/download/{fname}"
        return jsonify({"ok": True, "release": rel, "min_supported_version": cfg.get("min_supported_version", "2.0.0")})


@app.route("/api/v1/updates/download/<path:filename>", methods=["GET"])
def api_updates_download(filename):
    safe_name = os.path.basename(filename)
    full = os.path.join(RELEASES_DIR, safe_name)
    if not os.path.isfile(full):
        return jsonify({"ok": False, "error": "Release file not found"}), 404
    return send_from_directory(RELEASES_DIR, safe_name, as_attachment=True)


@app.route("/api/v1/webhooks/payment", methods=["POST"])
def api_payment_webhook():
    """Extensible payment gateway webhook (Stripe / LemonSqueezy / Gumroad / JazzCash)."""
    if PAYMENT_WEBHOOK_SECRET:
        sig = request.headers.get("X-Webhook-Secret", "")
        if not secrets.compare_digest(sig, PAYMENT_WEBHOOK_SECRET):
            return jsonify({"ok": False, "error": "Invalid webhook signature"}), 403

    data = request.get_json(silent=True) or {}
    plan = str(data.get("plan") or "lifetime").strip().lower()
    email = str(data.get("customer_email") or "")[:160]
    days = data.get("duration_days")
    max_devices = max(1, min(10, int(data.get("max_devices") or 1)))
    key = generate_license_key(plan)
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    exp_iso = (now_dt + timedelta(days=int(days))).isoformat() if days else None

    with DBConn() as db:
        db.execute(
            """
            INSERT INTO licenses (license_key, plan, status, max_devices, expires_at, customer_email, notes, created_at)
            VALUES (?, ?, 'active', ?, ?, ?, 'Auto-created via payment webhook', ?)
            """,
            (key, plan, max_devices, exp_iso, email, now_dt.isoformat()),
        )
        log_event(db, "WEBHOOK_LICENSE_CREATED", "", _client_ip(), f"key={key} plan={plan} email={email}")
    return jsonify({"ok": True, "license_key": key, "plan": plan, "expires_at": exp_iso})


# =====================================================================
# PRIVATE OWNER ADMIN DASHBOARD & API
# =====================================================================

@app.route("/")
def root_redirect():
    return redirect("/admin")


@app.route("/admin", methods=["GET"])
def admin_dashboard_page():
    authed = _is_admin_authed()
    return render_template(
        "admin.html",
        authed=authed,
        admin_user=ADMIN_USERNAME,
        admin_key=(ADMIN_API_KEY if authed else "")
    )


@app.route("/api/v1/admin/login", methods=["POST"])
def api_admin_login():
    ip = _client_ip()
    if not admin_login_limiter.allow(f"adm:{ip}"):
        return jsonify({"ok": False, "error": "Too many login attempts. Wait 5 minutes."}), 429
    data = request.get_json(silent=True) or {}
    user = str(data.get("username") or "").strip()
    pw = str(data.get("password") or "")
    if user == ADMIN_USERNAME and verify_password(pw, ADMIN_PASSWORD_HASH):
        session.permanent = True
        session["admin_ok"] = True
        session["admin_user"] = user
        with DBConn() as db:
            log_event(db, "ADMIN_LOGIN_OK", "", ip, f"user={user}")
        resp = jsonify({"ok": True, "username": user, "admin_key": ADMIN_API_KEY})
        resp.set_cookie("imran_admin_token", ADMIN_API_KEY, max_age=86400*365, httponly=True, samesite="Lax")
        return resp
    with DBConn() as db:
        log_event(db, "ADMIN_LOGIN_FAIL", "", ip, f"user={user}")
    return jsonify({"ok": False, "error": "Invalid admin credentials"}), 401


@app.route("/api/v1/admin/logout", methods=["POST"])
def api_admin_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/v1/admin/overview", methods=["GET"])
@require_admin
def api_admin_overview():
    now = datetime.now(timezone.utc)
    with DBConn() as db:
        devices = db.fetchall("SELECT * FROM devices ORDER BY last_seen_at DESC")
        cfg = get_all_config(db)
        counts = {"total": len(devices), "active_24h": 0, "trial": 0, "expired": 0, "paid": 0, "blocked": 0}
        for d in devices:
            last_dt = _parse_iso(d["last_seen_at"])
            if last_dt and (now - last_dt).total_seconds() <= 86400:
                counts["active_24h"] += 1
            acc = _evaluate_device_access(db, d, cfg)
            st = acc["status"]
            if st == "blocked":
                counts["blocked"] += 1
            elif st == "pro":
                counts["paid"] += 1
            elif st == "trial":
                counts["trial"] += 1
            else:
                counts["expired"] += 1
        latest = _get_latest_release(db)
        total_lics = len(db.fetchall("SELECT id FROM licenses"))
        return jsonify({
            "ok": True,
            "stats": counts,
            "total_licenses": total_lics,
            "current_version": latest["version"] if latest else "2.0.0",
            "min_supported_version": cfg.get("min_supported_version", "2.0.0"),
        })


@app.route("/api/v1/admin/devices", methods=["GET"])
@require_admin
def api_admin_devices():
    with DBConn() as db:
        cfg = get_all_config(db)
        devices = db.fetchall("SELECT * FROM devices ORDER BY last_seen_at DESC LIMIT 500")
        out = []
        for d in devices:
            acc = _evaluate_device_access(db, d, cfg)
            d["access_status"] = acc["status"]
            d["plan"] = acc["plan"]
            d["license_key"] = acc["license_key"]
            d["trial_remaining_seconds"] = acc["trial_remaining_seconds"]
            out.append(d)
        return jsonify({"ok": True, "devices": out})


@app.route("/api/v1/admin/devices/<device_id>/block", methods=["POST"])
@require_admin
def api_admin_block_device(device_id):
    with DBConn() as db:
        db.execute("UPDATE devices SET status = 'blocked' WHERE device_id = ?", (device_id,))
        log_event(db, "ADMIN_DEVICE_BLOCKED", device_id, _client_ip(), "Blocked by owner")
    return jsonify({"ok": True})


@app.route("/api/v1/admin/devices/<device_id>/unblock", methods=["POST"])
@require_admin
def api_admin_unblock_device(device_id):
    with DBConn() as db:
        db.execute("UPDATE devices SET status = 'active' WHERE device_id = ?", (device_id,))
        log_event(db, "ADMIN_DEVICE_UNBLOCKED", device_id, _client_ip(), "Unblocked by owner")
    return jsonify({"ok": True})


@app.route("/api/v1/admin/devices/<device_id>/set-trial", methods=["POST"])
@require_admin
def api_admin_set_trial(device_id):
    data = request.get_json(silent=True) or {}
    hours = float(data.get("hours", 72))
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    exp_iso = (now_dt + timedelta(hours=hours)).isoformat()
    with DBConn() as db:
        db.execute("UPDATE devices SET trial_expires_at = ? WHERE device_id = ?", (exp_iso, device_id))
        log_event(db, "ADMIN_TRIAL_UPDATED", device_id, _client_ip(), f"hours={hours}")
    return jsonify({"ok": True, "trial_expires_at": exp_iso})


@app.route("/api/v1/admin/licenses", methods=["GET"])
@require_admin
def api_admin_licenses():
    with DBConn() as db:
        lics = db.fetchall("SELECT * FROM licenses ORDER BY id DESC LIMIT 500")
        for l in lics:
            acts = db.fetchall(
                "SELECT device_id, activated_at FROM license_activations WHERE license_id = ? AND active = 1",
                (l["id"],),
            )
            l["active_devices"] = acts
        return jsonify({"ok": True, "licenses": lics})


@app.route("/api/v1/admin/licenses/generate", methods=["POST"])
@require_admin
def api_admin_generate_license():
    data = request.get_json(silent=True) or {}
    plan = str(data.get("plan") or "lifetime").strip().lower()
    max_devices = max(1, min(20, int(data.get("max_devices") or 1)))
    raw_days = data.get("duration_days")
    try:
        duration_days = int(str(raw_days).strip()) if raw_days not in ("", None) else None
    except Exception:
        duration_days = None
    if duration_days is None:
        if "month" in plan or "gift" in plan:
            duration_days = 30
        elif "year" in plan:
            duration_days = 365
        else:
            duration_days = None
    customer_email = str(data.get("customer_email") or "")[:160]
    notes = str(data.get("notes") or "")[:300]
    target_device = sanitize_device_id(str(data.get("device_id") or "").strip())
    custom_k = (data.get("custom_key") or "").strip().upper()
    key = custom_k or generate_license_key(plan)
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    exp_iso = (now_dt + timedelta(days=int(duration_days))).isoformat() if duration_days is not None else None

    with DBConn() as db:
        db.execute(
            """
            INSERT INTO licenses (license_key, plan, status, max_devices, expires_at, customer_email, notes, created_at)
            VALUES (?, ?, 'active', ?, ?, ?, ?, ?)
            """,
            (key, plan, max_devices, exp_iso, customer_email, notes, now_dt.isoformat()),
        )
        lic = db.fetchone("SELECT id FROM licenses WHERE license_key = ?", (key,))
        if target_device and lic:
            db.execute(
                "UPDATE license_activations SET active = 0, deactivated_at = ? WHERE device_id = ? AND active = 1",
                (now_dt.isoformat(), target_device),
            )
            db.execute(
                "INSERT INTO license_activations (license_id, device_id, activated_at, active) VALUES (?, ?, ?, 1)",
                (lic["id"], target_device, now_dt.isoformat()),
            )
            log_event(db, "ADMIN_LICENSE_BOUND_DEVICE", target_device, _client_ip(), f"key={key} plan={plan}")
        log_event(db, "ADMIN_LICENSE_GENERATED", target_device or "", _client_ip(), f"key={key} plan={plan} max={max_devices}")
    return jsonify({"ok": True, "license_key": key, "plan": plan, "max_devices": max_devices, "expires_at": exp_iso, "bound_device": target_device})


@app.route("/api/v1/admin/devices/<device_id>/upgrade-pro", methods=["POST"])
@require_admin
def api_admin_upgrade_device_pro(device_id):
    device_id = sanitize_device_id(device_id)
    data = request.get_json(silent=True) or {}
    plan = str(data.get("plan") or "lifetime").strip().lower()
    key = generate_license_key(plan)
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    exp_iso = None if plan == "lifetime" else (now_dt + timedelta(days=365 if "year" in plan else 30)).isoformat()
    with DBConn() as db:
        dev = db.fetchone("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        if not dev:
            return jsonify({"ok": False, "error": "Device not found"}), 404
        db.execute(
            """
            INSERT INTO licenses (license_key, plan, status, max_devices, expires_at, customer_email, notes, created_at)
            VALUES (?, ?, 'active', 1, ?, ?, '1-Click Admin Upgrade', ?)
            """,
            (key, plan, exp_iso, f"PC: {device_id}", now_dt.isoformat()),
        )
        lic = db.fetchone("SELECT id FROM licenses WHERE license_key = ?", (key,))
        db.execute("UPDATE license_activations SET active = 0, deactivated_at = ? WHERE device_id = ? AND active = 1", (now_dt.isoformat(), device_id))
        db.execute("INSERT INTO license_activations (license_id, device_id, activated_at, active) VALUES (?, ?, ?, 1)", (lic["id"], device_id, now_dt.isoformat()))
        log_event(db, "ADMIN_UPGRADE_DEVICE_PRO", device_id, _client_ip(), f"plan={plan} key={key}")
    return jsonify({"ok": True, "license_key": key, "plan": plan, "expires_at": exp_iso})


@app.route("/api/v1/admin/licenses/<key>/revoke", methods=["POST"])
@require_admin
def api_admin_revoke_license(key):
    with DBConn() as db:
        db.execute("UPDATE licenses SET status = 'revoked' WHERE license_key = ?", (key.upper(),))
        log_event(db, "ADMIN_LICENSE_REVOKED", "", _client_ip(), f"key={key.upper()}")
    return jsonify({"ok": True})


@app.route("/api/v1/admin/licenses/<key>/activate", methods=["POST"])
@require_admin
def api_admin_reactivate_license(key):
    with DBConn() as db:
        db.execute("UPDATE licenses SET status = 'active' WHERE license_key = ?", (key.upper(),))
        log_event(db, "ADMIN_LICENSE_REACTIVATED", "", _client_ip(), f"key={key.upper()}")
    return jsonify({"ok": True})


@app.route("/api/v1/admin/licenses/<key>/extend", methods=["POST"])
@require_admin
def api_admin_extend_license(key):
    data = request.get_json(silent=True) or {}
    days = int(data.get("days") or 30)
    with DBConn() as db:
        lic = db.fetchone("SELECT * FROM licenses WHERE license_key = ?", (key.upper(),))
        if not lic:
            return jsonify({"ok": False, "error": "License not found"}), 404
        base_dt = _parse_iso(lic["expires_at"]) or datetime.now(timezone.utc)
        if base_dt < datetime.now(timezone.utc):
            base_dt = datetime.now(timezone.utc)
        new_exp = (base_dt + timedelta(days=days)).replace(microsecond=0).isoformat()
        db.execute("UPDATE licenses SET expires_at = ?, status = 'active' WHERE id = ?", (new_exp, lic["id"]))
        log_event(db, "ADMIN_LICENSE_EXTENDED", "", _client_ip(), f"key={key.upper()} +{days}d -> {new_exp}")
        return jsonify({"ok": True, "expires_at": new_exp})


@app.route("/api/v1/admin/releases", methods=["GET"])
@require_admin
def api_admin_releases():
    with DBConn() as db:
        rows = db.fetchall("SELECT * FROM releases ORDER BY id DESC LIMIT 100")
        return jsonify({"ok": True, "releases": rows})


@app.route("/api/v1/admin/releases/publish", methods=["POST"])
@require_admin
def api_admin_publish_release():
    """Supports either multipart ZIP file upload (local/VPS) OR JSON metadata with external CDN URL (GitHub Releases)."""
    if request.content_type and "multipart/form-data" in request.content_type:
        f = request.files.get("file")
        version = sanitize_version(request.form.get("version", ""))
        min_ver = sanitize_version(request.form.get("min_supported_version", "2.0.0"))
        notes = str(request.form.get("release_notes", ""))
        is_mandatory = 1 if str(request.form.get("is_mandatory", "0")).lower() in ("1", "true", "yes") else 0
        if not f or not version:
            return jsonify({"ok": False, "error": "Version and release ZIP file are required."}), 400
        fname = f"ImranCreatorSuite_v{version}.zip"
        dest = os.path.join(RELEASES_DIR, fname)
        f.save(dest)
        sha256 = compute_sha256_file(dest)
        sig = sign_release_hash(version, sha256, SIGNING_SECRET)
        fsize = os.path.getsize(dest)
        base_url = request.host_url.rstrip("/")
        dl_url = f"{base_url}/api/v1/updates/download/{fname}"
    else:
        data = request.get_json(silent=True) or {}
        version = sanitize_version(data.get("version", ""))
        min_ver = sanitize_version(data.get("min_supported_version", "2.0.0"))
        dl_url = str(data.get("download_url") or "").strip()
        sha256 = str(data.get("sha256") or "").strip().lower()
        sig = str(data.get("signature") or "").strip().lower()
        notes = str(data.get("release_notes") or "")
        is_mandatory = 1 if data.get("is_mandatory") else 0
        fsize = int(data.get("file_size") or 0)
        if not version or not dl_url or not sha256:
            return jsonify({"ok": False, "error": "version, download_url, and sha256 are required."}), 400
        if not sig:
            sig = sign_release_hash(version, sha256, SIGNING_SECRET)

    now_iso = utc_now_iso()
    with DBConn() as db:
        existing = db.fetchone("SELECT id FROM releases WHERE version = ?", (version,))
        if existing:
            db.execute(
                """
                UPDATE releases
                SET min_supported_version=?, download_url=?, sha256=?, signature=?, release_notes=?, is_mandatory=?, file_size=?, published_at=?, is_active=1
                WHERE version=?
                """,
                (min_ver, dl_url, sha256, sig, notes, is_mandatory, fsize, now_iso, version),
            )
        else:
            db.execute(
                """
                INSERT INTO releases (version, min_supported_version, download_url, sha256, signature, release_notes, is_mandatory, file_size, published_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (version, min_ver, dl_url, sha256, sig, notes, is_mandatory, fsize, now_iso),
            )
        log_event(db, "ADMIN_RELEASE_PUBLISHED", "", _client_ip(), f"v{version} sha256={sha256[:12]}")
    return jsonify({"ok": True, "version": version, "download_url": dl_url, "sha256": sha256, "signature": sig})


@app.route("/api/v1/admin/config", methods=["GET", "POST"])
@require_admin
def api_admin_config():
    with DBConn() as db:
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            allowed = {
                "trial_hours", "min_supported_version", "maintenance_mode",
                "maintenance_message", "announcement_banner", "purchase_url",
                "offline_grace_hours", "feature_flags", "plans",
            }
            updates = {k: v for k, v in data.items() if k in allowed}
            if updates:
                set_config_values(db, updates)
                log_event(db, "ADMIN_CONFIG_UPDATED", "", _client_ip(), f"keys={list(updates.keys())}")
        return jsonify({"ok": True, "config": get_all_config(db)})


@app.route("/api/v1/admin/logs", methods=["GET"])
@require_admin
def api_admin_logs():
    with DBConn() as db:
        rows = db.fetchall("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200")
        return jsonify({"ok": True, "logs": rows})


def _seed_bundled_release():
    """Ensures bundled release in releases_store/seed_release.json stays active across Render Free restarts."""
    seed_p = os.path.join(RELEASES_DIR, "seed_release.json")
    if not os.path.isfile(seed_p):
        return
    try:
        m = json.loads(open(seed_p, "r", encoding="utf-8").read())
        ver = sanitize_version(m.get("version", ""))
        dl_url = str(m.get("download_url") or "").strip()
        sha = str(m.get("sha256") or "").strip().lower()
        sig = str(m.get("signature") or "").strip().lower()
        if not (ver and dl_url and sha):
            return
        if not sig:
            sig = sign_release_hash(ver, sha, SIGNING_SECRET)
        with DBConn() as db:
            if not db.fetchone("SELECT id FROM releases WHERE version = ?", (ver,)):
                db.execute(
                    """
                    INSERT INTO releases (version, min_supported_version, download_url, sha256, signature, release_notes, is_mandatory, file_size, published_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        ver,
                        sanitize_version(m.get("min_supported_version", "2.0.0")),
                        dl_url,
                        sha,
                        sig,
                        str(m.get("release_notes") or f"Release v{ver}"),
                        1 if m.get("is_mandatory") else 0,
                        int(m.get("file_size") or 0),
                        utc_now_iso(),
                    ),
                )
    except Exception:
        pass


init_db()
_seed_bundled_release()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8090))
    print(f"[ImranCloudServer] Running on http://0.0.0.0:{port} (Admin: /admin)", flush=True)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
