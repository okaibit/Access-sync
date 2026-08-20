"""
dashboard.py

Local web dashboard for whitelist_sync.py. Runs entirely on your machine.
Start it with: python3 dashboard.py
Then open http://127.0.0.1:5051 in your browser.
"""

import csv
import glob
import json
import os
import re
import secrets
import subprocess
import sys
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, session,
)
from dotenv import load_dotenv
import discord

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Multi-tenant login
#
# This dashboard can trigger live role changes on a real Discord server, so
# every account is locked to only the server(s) it's allowed to touch --
# even if a client knows another client's server ID, the backend refuses to
# run a sync against it.
#
# Configure accounts with the DASHBOARD_CLIENTS env var as a JSON array:
#
#   [
#     {"username": "okai", "password": "...", "label": "Okai (admin)", "allowed_server_ids": ["*"]},
#     {"username": "acme", "password": "...", "label": "Acme Community", "allowed_server_ids": ["1538...24156"]}
#   ]
#
# "allowed_server_ids": ["*"] means unrestricted (use only for your own
# account). Everyone else should list the exact server ID(s) they're allowed
# to sync -- copy this from Discord (right-click the server icon -> Copy
# Server ID, with Developer Mode on).
#
# For backward compatibility, if DASHBOARD_CLIENTS isn't set, the older
# single-account DASHBOARD_USERNAME / DASHBOARD_PASSWORD pair still works as
# one unrestricted admin account.
#
# DASHBOARD_SECRET_KEY signs the session cookie. Set it as an env var too so
# logins survive a redeploy; if left unset, a random key is generated at
# startup, which just means everyone gets logged out on the next restart --
# safe, just slightly less convenient.
# ---------------------------------------------------------------------------
_IS_HOSTED = bool(os.getenv("RENDER") or os.getenv("VERCEL"))


def _load_clients():
    raw = os.getenv("DASHBOARD_CLIENTS")
    if raw:
        try:
            clients = json.loads(raw)
        except json.JSONDecodeError as e:
            sys.exit(f"DASHBOARD_CLIENTS is not valid JSON: {e}")
        by_username = {}
        for c in clients:
            if not c.get("username") or not c.get("password"):
                sys.exit("Every entry in DASHBOARD_CLIENTS needs a username and password.")
            by_username[c["username"]] = {
                "password": c["password"],
                "label": c.get("label", c["username"]),
                "allowed_server_ids": set(str(s) for s in c.get("allowed_server_ids", [])),
            }
        return by_username

    # Backward compatible single-account fallback.
    legacy_user = os.getenv("DASHBOARD_USERNAME")
    legacy_pass = os.getenv("DASHBOARD_PASSWORD")
    if legacy_user and legacy_pass:
        return {
            legacy_user: {
                "password": legacy_pass,
                "label": legacy_user,
                "allowed_server_ids": {"*"},
            }
        }
    return {}


CLIENTS = _load_clients()

if _IS_HOSTED and not CLIENTS:
    sys.exit(
        "No login configured. Set DASHBOARD_CLIENTS (preferred, supports "
        "multiple clients) or DASHBOARD_USERNAME/DASHBOARD_PASSWORD as "
        "environment variables in your Render dashboard, then redeploy."
    )
elif not CLIENTS:
    print(
        "WARNING: No DASHBOARD_CLIENTS or DASHBOARD_USERNAME/PASSWORD set. "
        "Running with no login -- fine for local dev, never deploy this way."
    )

app.secret_key = os.getenv("DASHBOARD_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_IS_HOSTED,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)


def check_auth(username, password):
    if not CLIENTS:
        return None  # local dev only, see warning above
    client = CLIENTS.get(username or "")
    if client and secrets.compare_digest(password or "", client["password"]):
        return client
    return None


def current_client():
    """The logged-in tenant's config, or an unrestricted stand-in for local dev."""
    if not CLIENTS:
        return {"username": "local", "label": "Local dev", "allowed_server_ids": {"*"}}
    return session.get("client")


def server_allowed(server_id: str) -> bool:
    client = current_client()
    if not client:
        return False
    allowed = client.get("allowed_server_ids", set())
    return "*" in allowed or str(server_id) in allowed


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if not CLIENTS:
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        client = check_auth(username, password)
        if client:
            session.clear()
            session["client"] = {
                "username": username,
                "label": client["label"],
                "allowed_server_ids": list(client["allowed_server_ids"]),
            }
            session.permanent = True
            return redirect(url_for("index"))
        error = "Incorrect username or password."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.before_request
def _global_auth_gate():
    if not CLIENTS:
        return  # local dev, no login configured

    if request.path in ("/login", "/logout") or request.path.startswith("/static"):
        return

    if session.get("client"):
        return

    if request.path == "/":
        return redirect(url_for("login_page"))

    return jsonify({"ok": False, "error": "Session expired. Please log in again."}), 401


# Ensure the reports directory exists whether we're started via
# `python3 dashboard.py` (local dev) or via gunicorn (production on Render,
# which never runs the __main__ block below).
os.makedirs(
    "/tmp/reports" if os.getenv("VERCEL") else os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports"),
    exist_ok=True,
)

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "whitelist_sync.py")
REPORTS_DIR = (
    "/tmp/reports"
    if os.getenv("VERCEL")
    else os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
)

LOG_LINE_RE = re.compile(r"^(?P<ts>[\d-]+ [\d:,]+)\s+\[(?P<level>\w+)\]\s+(?P<msg>.*)$")


def parse_log(log_text: str):
    """Turn raw script log output into structured audit events + permission checks."""
    events = []
    permissions = {
        "found_message": None,
        "role_hierarchy_ok": None,
        "logged_in": False,
    }

    for line in log_text.splitlines():
        m = LOG_LINE_RE.match(line)
        if not m:
            continue
        ts, level, msg = m.group("ts"), m.group("level"), m.group("msg")

        if "Logged in as" in msg:
            permissions["logged_in"] = True
            events.append({"ts": ts, "type": "info", "msg": "Connected to Discord"})
        elif msg.startswith("Found message"):
            permissions["found_message"] = True
            events.append({"ts": ts, "type": "info", "msg": "Located target message"})
        elif "Could not find message" in msg:
            permissions["found_message"] = False
            events.append({"ts": ts, "type": "error", "msg": msg})
        elif "highest role is not above" in msg:
            permissions["role_hierarchy_ok"] = False
            events.append({"ts": ts, "type": "error", "msg": msg})
        elif msg.startswith("Found") and "user(s) who reacted" in msg:
            permissions["role_hierarchy_ok"] = True if permissions["role_hierarchy_ok"] is None else permissions["role_hierarchy_ok"]
            events.append({"ts": ts, "type": "info", "msg": msg})
        elif msg.startswith("Protected roles"):
            events.append({"ts": ts, "type": "info", "msg": msg})
        elif msg.startswith("Progress:"):
            events.append({"ts": ts, "type": "progress", "msg": msg})
        elif msg.startswith("Done."):
            events.append({"ts": ts, "type": "done", "msg": msg})
        elif level == "ERROR":
            events.append({"ts": ts, "type": "error", "msg": msg})
        elif level == "WARNING" and "PyNaCl" not in msg and "davey" not in msg:
            events.append({"ts": ts, "type": "warn", "msg": msg})

    if permissions["role_hierarchy_ok"] is None:
        permissions["role_hierarchy_ok"] = True  # no error seen means it passed

    return events, permissions


@app.route("/")
def index():
    client = current_client()
    return render_template(
        "index.html",
        client_label=client["label"] if client else None,
        allowed_server_ids=list(client["allowed_server_ids"]) if client else [],
    )


@app.route("/server-info", methods=["POST"])
def server_info():
    """Resolve a Discord guild using the existing bot token."""
    data = request.get_json(silent=True) or {}
    server_id = str(data.get("server_id", "")).strip()

    if not server_id.isdigit():
        return jsonify({
            "ok": False,
            "error": "Enter a valid Discord Server ID."
        }), 400

    if not server_allowed(server_id):
        return jsonify({
            "ok": False,
            "error": "This account isn't authorized for that server."
        }), 403

    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token:
        return jsonify({
            "ok": False,
            "error": "DISCORD_BOT_TOKEN is not configured."
        }), 500

    async def resolve_guild():
        intents = discord.Intents.none()
        client = discord.Client(intents=intents)

        try:
            await client.login(token)
            guild = client.get_guild(int(server_id))

            if guild is None:
                try:
                    guild = await client.fetch_guild(int(server_id))
                except discord.NotFound:
                    return None, "Server not found or the bot is not connected to it."
                except discord.Forbidden:
                    return None, "The bot cannot access this server."

            return guild, None
        finally:
            await client.close()

    import asyncio

    try:
        guild, error = asyncio.run(resolve_guild())
    except Exception as exc:
        return jsonify({
            "ok": False,
            "error": f"Discord lookup failed: {exc}"
        }), 502

    if error:
        return jsonify({
            "ok": False,
            "error": error
        }), 404

    return jsonify({
        "ok": True,
        "server_id": str(guild.id),
        "server_name": guild.name,
        "server_icon": guild.icon.url if guild.icon else None,
    })


@app.route("/my-servers")
def my_servers():
    """
    Resolve display names for every server this logged-in account is
    scoped to. Used to power the server picker for accounts with more
    than one allowed server -- so they choose from real server names
    instead of pasting raw IDs.
    """
    client = current_client()
    allowed = list(client.get("allowed_server_ids", set())) if client else []

    if not allowed or "*" in allowed:
        return jsonify({"ok": True, "servers": []})

    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token:
        return jsonify({"ok": False, "error": "DISCORD_BOT_TOKEN is not configured."}), 500

    async def resolve_all():
        intents = discord.Intents.none()
        discord_client = discord.Client(intents=intents)
        results = []
        try:
            await discord_client.login(token)
            for sid in allowed:
                guild = discord_client.get_guild(int(sid))
                if guild is None:
                    try:
                        guild = await discord_client.fetch_guild(int(sid))
                    except (discord.NotFound, discord.Forbidden):
                        guild = None
                results.append({
                    "server_id": sid,
                    "server_name": guild.name if guild else f"Unknown server ({sid})",
                })
        finally:
            await discord_client.close()
        return results

    import asyncio

    try:
        servers = asyncio.run(resolve_all())
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Discord lookup failed: {exc}"}), 502

    return jsonify({"ok": True, "servers": servers})


@app.route("/run", methods=["POST"])
def run():
    data = request.get_json()

    server_id = str(data.get("server_id", "")).strip()
    message_id = str(data.get("message_id", "")).strip()
    role_id = str(data.get("role_id", "")).strip()
    action = str(data.get("action", "ADD")).strip().upper()
    dry_run = bool(data.get("dry_run", True))
    channel_id = str(data.get("channel_id", "")).strip()
    protected_roles = str(data.get("protected_roles", "")).strip()

    # No hardcoded default here anymore -- a prior version defaulted to two
    # specific role IDs from one server, which silently did nothing on any
    # other client's server instead of protecting their actual admin/mod
    # roles. Each client must enter their own protected role IDs explicitly.
    protected_roles_warning = None
    if not protected_roles:
        protected_roles_warning = (
            "No protected roles were entered. Admin/mod roles on this "
            "server will NOT be automatically protected from this sync -- "
            "double check the results before running live."
        )

    if not (server_id and message_id and role_id):
        return jsonify({"ok": False, "error": "Server ID, Message ID, and Role ID are all required."}), 400

    if not server_allowed(server_id):
        return jsonify({
            "ok": False,
            "error": "This account isn't authorized to run syncs against that server."
        }), 403

    cmd = [
        sys.executable, SCRIPT,
        "--server-id", server_id,
        "--message-id", message_id,
        "--role-id", role_id,
        "--action", action,
    ]
    if channel_id:
        cmd += ["--channel-id", channel_id]
    if protected_roles:
        cmd += ["--protected-roles", protected_roles]
    if dry_run:
        cmd.append("--dry-run")

    before_files = set(glob.glob(os.path.join(REPORTS_DIR, "*.csv")))

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(SCRIPT))

    after_files = set(glob.glob(os.path.join(REPORTS_DIR, "*.csv")))
    new_files = list(after_files - before_files)

    report_rows = []
    report_filename = None
    if new_files:
        report_filename = sorted(new_files)[-1]
        with open(report_filename, newline="") as f:
            reader = csv.DictReader(f)
            report_rows = list(reader)

        # Tag the report with which server it belongs to, so /history can
        # filter results per client and never show one client's activity to
        # another. whitelist_sync.py doesn't know about tenants, so this is
        # applied here, right after the run completes.
        tagged_name = report_filename.replace(
            "report_", f"report_srv{server_id}_", 1
        )
        try:
            os.rename(report_filename, tagged_name)
            report_filename = tagged_name
        except OSError:
            pass  # keep the untagged file rather than fail the whole run

    success = result.returncode == 0
    stdout = result.stdout or ""
    stderr = result.stderr or ""

    full_log = stdout
    if stderr:
        full_log += "\n\n--- ERROR OUTPUT ---\n" + stderr

    if not success:
        full_log += f"\n\n--- PROCESS EXIT CODE: {result.returncode} ---"

    events, permissions = parse_log(full_log)

    return jsonify({
        "ok": success,
        "dry_run": dry_run,
        "action": action,
        "log": full_log,
        "events": events,
        "permissions": permissions,
        "rows": report_rows,
        "report_file": os.path.basename(report_filename) if report_filename else None,
        "protected_roles_warning": protected_roles_warning,
    })


@app.route("/history")
def history():
    client = current_client()
    allowed = client.get("allowed_server_ids", set()) if client else set()

    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "*.csv")), reverse=True)
    runs = []
    for f in files:
        name = os.path.basename(f)

        # New format tags the server: report_srv<id>_add_20260101_120000.csv
        m = re.match(r"report_srv(\d+)_(add|remove)_(\d{8})_(\d{6})\.csv", name)
        if m:
            file_server_id, action, date_str, time_str = m.groups()
        else:
            # Older reports saved before server-tagging existed have no
            # recorded owner -- only the unrestricted admin account can see
            # these, since we can't verify which client they belong to.
            m = re.match(r"report_(add|remove)_(\d{8})_(\d{6})\.csv", name)
            if not m:
                continue
            action, date_str, time_str = m.groups()
            file_server_id = None

        if "*" not in allowed:
            if file_server_id is None or file_server_id not in allowed:
                continue

        if len(runs) >= 30:
            break

        try:
            dt = datetime.strptime(date_str + time_str, "%Y%m%d%H%M%S")
        except ValueError:
            dt = None

        counts = {"ADDED": 0, "REMOVED": 0, "SKIPPED": 0, "FAILED": 0, "DRY_RUN_ADD": 0, "DRY_RUN_REMOVE": 0}
        total = 0
        try:
            with open(f, newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    total += 1
                    r = row.get("result", "")
                    if r in counts:
                        counts[r] += 1
        except Exception:
            pass

        is_dry = counts["DRY_RUN_ADD"] > 0 or counts["DRY_RUN_REMOVE"] > 0

        runs.append({
            "file": name,
            "action": action.upper(),
            "mode": "DRY RUN" if is_dry else "LIVE",
            "time": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "unknown",
            "total": total,
            "counts": counts,
        })

    return jsonify({"runs": runs})


if __name__ == "__main__":
    # Local dev only. In production (Render), gunicorn imports `app` directly
    # and this block never runs -- gunicorn binds the host/port itself using
    # the $PORT Render provides.
    os.makedirs(REPORTS_DIR, exist_ok=True)
    port = int(os.getenv("PORT", 5051))
    print(f"Whitelist Sync Dashboard running at http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
