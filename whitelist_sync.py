"""
whitelist_sync.py

A reusable, one-shot local script (NOT a persistent bot) that adds or removes
a Discord role from every user who reacted to a specific message. Built for
Web3/NFT communities running allowlist confirmations, mint reactions, raffle
entries, or emoji-reaction-based approvals.

Built to handle scale (hundreds to thousands of reactors):
  - Resumable: if it crashes or is interrupted, re-running the same job
    skips users already processed instead of redoing (or double-processing) them.
  - Retries transient Discord API failures automatically before giving up.
  - Processes multiple users concurrently (bounded, so it's still respectful
    of Discord's rate limits) instead of one at a time.
  - Logs progress periodically so a long run doesn't look frozen.

Two ways to run it:

  1) Config file (recommended for repeat use across clients):
     python whitelist_sync.py --config clients/acme_mint.json

  2) Command line flags (quick one-off runs):
     python whitelist_sync.py --server-id 123 --message-id 456 \
         --role-id 789 --action ADD

Add --dry-run to either mode to preview what WOULD happen without making
any changes. Always run --dry-run first on a live client server.

Every run writes a full CSV report (who was added/removed/skipped/failed)
in addition to the terminal log, so you can hand the client a clean file.
"""

import argparse
import asyncio
import csv
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Set, List, Dict

import discord
from dotenv import load_dotenv

load_dotenv()

if os.getenv("VERCEL"):
    LOG_FILE = "/tmp/whitelist_sync.log"
else:
    LOG_FILE = "whitelist_sync.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("whitelist_sync")

MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2
PROGRESS_LOG_EVERY = 25
CSV_FIELDS = ["username", "user_id", "result", "detail"]


# ---------------------------------------------------------------------------
# Config / args
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Add or remove a Discord role from everyone who reacted to a message."
    )
    parser.add_argument("--config", type=str, default=None, help="Path to a JSON config file")
    parser.add_argument("--server-id", type=int, default=None, help="Discord server (guild) ID")
    parser.add_argument("--message-id", type=int, default=None, help="Discord message ID")
    parser.add_argument("--role-id", type=int, default=None, help="Discord role ID to add/remove")
    parser.add_argument(
        "--action", type=str.upper, choices=["ADD", "REMOVE"], default=None,
        help="Whether to ADD or REMOVE the role",
    )
    parser.add_argument("--channel-id", type=int, default=None, help="Optional: limit search to one channel")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview changes without actually adding/removing any roles",
    )
    parser.add_argument(
        "--output-dir", type=str, default="reports",
        help="Directory to save the CSV report (default: ./reports)",
    )
    parser.add_argument(
        "--concurrency", type=int, default=5,
        help="How many users to process at once (default: 5). Higher is faster but more likely to hit rate limits.",
    )
    parser.add_argument(
        "--protected-roles", type=str, default=None,
        help="Comma-separated role IDs to never modify (e.g. admin/mod roles), even if they reacted.",
    )
    return parser.parse_args()


def load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def resolve_settings(args) -> dict:
    """Merge config file + CLI flags. CLI flags override config file values."""
    settings = {}
    if args.config:
        settings.update(load_config(args.config))

    overrides = {
        "server_id": args.server_id,
        "message_id": args.message_id,
        "role_id": args.role_id,
        "action": args.action,
        "channel_id": args.channel_id,
        "concurrency": args.concurrency,
    }
    for key, value in overrides.items():
        if value is not None:
            settings[key] = value

    if args.protected_roles is not None:
        settings["protected_role_ids"] = [
            int(x.strip()) for x in args.protected_roles.split(",") if x.strip()
        ]
    settings.setdefault("protected_role_ids", [])

    if args.dry_run:
        settings["dry_run"] = True
    settings.setdefault("dry_run", False)
    settings.setdefault("concurrency", 5)

    required = ["server_id", "message_id", "role_id", "action"]
    missing = [r for r in required if r not in settings or settings[r] is None]
    if missing:
        log.error(f"Missing required setting(s): {', '.join(missing)}. "
                   f"Provide via --config or CLI flags.")
        sys.exit(1)

    if settings["action"] not in ("ADD", "REMOVE"):
        log.error("action must be ADD or REMOVE")
        sys.exit(1)

    return settings


# ---------------------------------------------------------------------------
# Checkpointing (resumability)
# ---------------------------------------------------------------------------

def checkpoint_path(output_dir: str, action: str, message_id: int, role_id: int) -> str:
    return f"{output_dir}/.checkpoint_{action.lower()}_{message_id}_{role_id}.csv"


def load_checkpoint(path: str) -> Dict[str, dict]:
    """Return {user_id: row} for users already processed in a prior (interrupted) run."""
    if not os.path.exists(path):
        return {}
    done = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            done[row["user_id"]] = row
    return done


def init_checkpoint(path: str):
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=CSV_FIELDS).writeheader()


def append_checkpoint_row(path: str, row: dict):
    with open(path, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=CSV_FIELDS).writerow(row)


def finalize_report(output_dir: str, action: str, all_rows: List[dict], checkpoint_file: Optional[str]) -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/report_{action.lower()}_{timestamp}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(all_rows)
    if checkpoint_file and os.path.exists(checkpoint_file):
        os.remove(checkpoint_file)
    return filename


# ---------------------------------------------------------------------------
# Discord logic
# ---------------------------------------------------------------------------

async def find_message(guild: discord.Guild, message_id: int, channel_id: Optional[int]):
    channels = guild.text_channels
    if channel_id:
        channel = guild.get_channel(channel_id)
        if channel is None:
            log.error(f"Channel {channel_id} not found in guild {guild.id}")
            return None
        channels = [channel]

    for channel in channels:
        try:
            message = await channel.fetch_message(message_id)
            log.info(f"Found message {message_id} in #{channel.name}")
            return message
        except discord.NotFound:
            continue
        except discord.Forbidden:
            log.warning(f"No permission to read #{channel.name}, skipping")
            continue

    return None


async def collect_reacted_users(message: discord.Message) -> Set[discord.Member]:
    users: Set[discord.Member] = set()
    for reaction in message.reactions:
        async for user in reaction.users():
            if isinstance(user, discord.Member) and not user.bot:
                users.add(user)
    return users


async def process_one_member(
    member: discord.Member,
    role: discord.Role,
    action: str,
    dry_run: bool,
    semaphore: asyncio.Semaphore,
    checkpoint_file: Optional[str],
    file_lock: asyncio.Lock,
    counters: dict,
    counters_lock: asyncio.Lock,
    total: int,
    protected_role_ids: Set[int],
) -> dict:
    async with semaphore:
        row = {"username": str(member), "user_id": str(member.id), "result": "", "detail": ""}

        member_role_ids = {r.id for r in member.roles}
        if protected_role_ids and (member_role_ids & protected_role_ids):
            row.update(result="SKIPPED", detail="protected role - not modified")
            log.info(f"{row['result']:16s} {member} ({member.id}) {row['detail']}")
            if checkpoint_file:
                async with file_lock:
                    append_checkpoint_row(checkpoint_file, row)
            async with counters_lock:
                counters["done"] += 1
                if counters["done"] % PROGRESS_LOG_EVERY == 0 or counters["done"] == total:
                    log.info(f"Progress: {counters['done']}/{total} processed")
            return row

        has_role = role in member.roles

        attempt = 0
        while True:
            attempt += 1
            try:
                if action == "ADD":
                    if has_role:
                        row.update(result="SKIPPED", detail="already has role")
                    elif dry_run:
                        row.update(result="DRY_RUN_ADD", detail="would be added")
                    else:
                        await member.add_roles(role, reason="whitelist_sync.py: reacted to message")
                        row.update(result="ADDED", detail="")
                else:  # REMOVE
                    if not has_role:
                        row.update(result="SKIPPED", detail="did not have role")
                    elif dry_run:
                        row.update(result="DRY_RUN_REMOVE", detail="would be removed")
                    else:
                        await member.remove_roles(role, reason="whitelist_sync.py: reacted to message")
                        row.update(result="REMOVED", detail="")
                break  # success, exit retry loop

            except discord.Forbidden:
                # Permission errors won't fix themselves on retry
                row.update(result="FAILED", detail="missing permission")
                log.error(f"FAILED (missing permission) for {member} ({member.id})")
                break

            except discord.HTTPException as e:
                if attempt < MAX_RETRIES:
                    log.warning(f"Retry {attempt}/{MAX_RETRIES} for {member} after error: {e}")
                    await asyncio.sleep(RETRY_DELAY_SECONDS * attempt)
                    continue
                row.update(result="FAILED", detail=f"HTTP error after {MAX_RETRIES} attempts: {e}")
                log.error(f"FAILED (HTTP error, {MAX_RETRIES} attempts) for {member} ({member.id}): {e}")
                break

            except Exception as e:
                row.update(result="FAILED", detail=f"unexpected error: {e}")
                log.error(f"FAILED (unexpected) for {member} ({member.id}): {e}")
                break

        log.info(f"{row['result']:16s} {member} ({member.id}) {row['detail']}")

        if checkpoint_file:
            async with file_lock:
                append_checkpoint_row(checkpoint_file, row)

        async with counters_lock:
            counters["done"] += 1
            if counters["done"] % PROGRESS_LOG_EVERY == 0 or counters["done"] == total:
                log.info(f"Progress: {counters['done']}/{total} processed")

        return row


async def sync_role(client: discord.Client, settings: dict):
    guild = client.get_guild(settings["server_id"])
    if guild is None:
        log.error(f"Bot is not in a server with ID {settings['server_id']}, or server not cached yet.")
        return

    role = guild.get_role(settings["role_id"])
    if role is None:
        log.error(f"Role ID {settings['role_id']} not found in server {guild.name} ({guild.id}).")
        return

    if guild.me.top_role <= role:
        log.error(
            f"Bot's highest role is not above '{role.name}'. "
            "Move the bot's role higher in Server Settings > Roles and try again."
        )
        return

    message = await find_message(guild, settings["message_id"], settings.get("channel_id"))
    if message is None:
        log.error(f"Could not find message {settings['message_id']} in any channel the bot can read.")
        return

    reacted_users = await collect_reacted_users(message)
    total = len(reacted_users)
    log.info(f"Found {total} unique (non-bot) user(s) who reacted.")

    action = settings["action"]
    dry_run = settings["dry_run"]
    output_dir = settings.get("output_dir", "reports")
    concurrency = max(1, settings.get("concurrency", 5))

    if dry_run:
        log.info("DRY RUN MODE: no roles will actually be changed. (no checkpoint used)")

    protected_role_ids: Set[int] = set(settings.get("protected_role_ids", []))
    if protected_role_ids:
        protected_names = [
            guild.get_role(rid).name if guild.get_role(rid) else str(rid)
            for rid in protected_role_ids
        ]
        log.info(f"Protected roles (never modified): {', '.join(protected_names)}")

    # Only live runs use checkpointing -- a dry run makes no real changes,
    # so there's nothing to resume.
    ckpt_file = None
    already_done: Dict[str, dict] = {}
    if not dry_run:
        ckpt_file = checkpoint_path(output_dir, action, settings["message_id"], settings["role_id"])
        already_done = load_checkpoint(ckpt_file)
        init_checkpoint(ckpt_file)
        if already_done:
            log.info(f"Resuming previous run: {len(already_done)} user(s) already processed, skipping them.")

    to_process = [m for m in reacted_users if str(m.id) not in already_done]

    semaphore = asyncio.Semaphore(concurrency)
    file_lock = asyncio.Lock()
    counters_lock = asyncio.Lock()
    counters = {"done": len(already_done)}

    new_rows = []
    if to_process:
        tasks = [
            process_one_member(
                member, role, action, dry_run, semaphore,
                ckpt_file, file_lock, counters, counters_lock, total,
                protected_role_ids,
            )
            for member in to_process
        ]
        new_rows = await asyncio.gather(*tasks)

    all_rows = list(already_done.values()) + list(new_rows)

    if dry_run:
        report_path = finalize_report(output_dir, action, all_rows, checkpoint_file=None)
    else:
        report_path = finalize_report(output_dir, action, all_rows, checkpoint_file=ckpt_file)

    added = sum(1 for r in all_rows if r["result"] in ("ADDED", "DRY_RUN_ADD"))
    removed = sum(1 for r in all_rows if r["result"] in ("REMOVED", "DRY_RUN_REMOVE"))
    skipped = sum(1 for r in all_rows if r["result"] == "SKIPPED")
    failed = sum(1 for r in all_rows if r["result"] == "FAILED")

    summary = (
        f"Done. Added: {added}, Removed: {removed}, Skipped: {skipped}, Failed: {failed}. "
        f"{'(DRY RUN - no changes made) ' if dry_run else ''}"
        f"Report saved to {report_path}, full log in {LOG_FILE}"
    )
    log.info(summary)

    if failed and not dry_run:
        log.warning(
            f"{failed} user(s) failed. Re-run the exact same command to retry just those users "
            f"(already-processed users will be skipped automatically)."
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    settings = resolve_settings(args)
    settings.setdefault("output_dir", args.output_dir)

    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token:
        log.error("DISCORD_BOT_TOKEN not set. Copy .env.example to .env and fill it in.")
        sys.exit(1)

    intents = discord.Intents.default()
    intents.members = True
    intents.reactions = True
    intents.guilds = True

    client = discord.Client(intents=intents)

    @client.event
    async def on_ready():
        log.info(f"Logged in as {client.user}")
        try:
            await sync_role(client, settings)
        finally:
            await client.close()

    client.run(token, log_handler=None)


if __name__ == "__main__":
    main()
