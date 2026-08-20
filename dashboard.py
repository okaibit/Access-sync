"""
dashboard.py

Local web dashboard for whitelist_sync.py. Runs entirely on your machine.
Start it with: python3 dashboard.py
Then open http://127.0.0.1:5051 in your browser.
"""

import csv
import glob
import os
import re
import secrets
import subprocess
import sys
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from dotenv import load_dotenv
import discord

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Basic auth gate
#
# This dashboard can trigger live role changes on a real Discord server, so
# it must never sit open on a public URL. Set DASHBOARD_USERNAME and
# DASHBOARD_PASSWORD as env vars (same place as DISCORD_BOT_TOKEN) to lock
# it down. If either is unset, the whole app refuses to start in production
# (VERCEL/RENDER) so it can't accidentally go live unprotected; locally it
# just logs a warning so you can still develop without setting them.
# ---------------------------------------------------------------------------
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD")
_IS_HOSTED = bool(os.getenv("RENDER") or os.getenv("VERCEL"))

if _IS_HOSTED and not (DASHBOARD_USERNAME and DASHBOARD_PASSWORD):
    sys.exit(
        "DASHBOARD_USERNAME and DASHBOARD_PASSWORD must both be set before "
        "this app can run on a public host. Add them as environment "
        "variables in your Render dashboard, then redeploy."
    )
elif not (DASHBOARD_USERNAME and DASHBOARD_PASSWORD):
    print(
        "WARNING: DASHBOARD_USERNAME/DASHBOARD_PASSWORD not set. "
        "Running with no login -- fine for local dev, never deploy this way."
    )


def check_auth(username, password):
    if not (DASHBOARD_USERNAME and DASHBOARD_PASSWORD):
        return True  # local dev only, see warning above
    return secrets.compare_digest(username or "", DASHBOARD_USERNAME) and \
        secrets.compare_digest(password or "", DASHBOARD_PASSWORD)


@app.before_request
def _global_auth_gate():
    auth = request.authorization
    if not auth or not check_auth(auth.username, auth.password):
        return Response(
            "Login required.", 401,
            {"WWW-Authenticate": 'Basic realm="Whitelist Sync"'},
        )

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
    return render_template("index.html")


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
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "*.csv")), reverse=True)
    runs = []
    for f in files[:30]:
        name = os.path.basename(f)
        m = re.match(r"report_(add|remove)_(\d{8})_(\d{6})\.csv", name)
        if not m:
            continue
        action, date_str, time_str = m.groups()
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
