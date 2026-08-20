# Whitelist Sync — Discord Role Sync for Web3 Communities

A one-shot local script that adds or removes a Discord role from every user
who reacted to a specific message — built for allowlist confirmations, mint
reactions, and raffle entries — anywhere someone reacts with an emoji to confirm or opt in.

Not a bot. You run it once, it does the job, then exits. No hosting required.

## Why this exists

Web3 projects constantly need to turn "everyone who reacted with a checkmark to
confirm they're on the allowlist" into an actual Discord role, or clean up
a role after a mint/event ends. Doing this by hand for hundreds of reactions
doesn't scale — this script does it in seconds and hands back a clean report.

## Features

- ADD or REMOVE a role based on emoji reactions on a message (reads regular reactions only — does NOT support Discord's native Poll feature, which uses a separate voting API)
- Dry-run mode — preview exactly who would be added/removed before touching anything live
- CSV report on every run — hand the client a clean file showing who was added, removed, skipped, or failed
- Config file support — reusable across multiple clients/servers without touching code
- Skips users who already have/don't have the role, no crashes
- Full log of every action in whitelist_sync.log

## Setup

### 1. Create a Discord bot (one-time, per client server)

1. Discord Developer Portal (discord.com/developers/applications) -> New Application
2. Bot tab -> Add Bot -> enable Server Members Intent
3. Copy the bot Token
4. OAuth2 -> URL Generator -> scope "bot", permissions Manage Roles, View Channels, Read Message History
5. Invite the bot to the server using the generated URL
6. In Server Settings -> Roles, drag the bot's role above the role it needs to manage

### 2. Install dependencies

pip install -r requirements.txt

### 3. Configure credentials

cp .env.example .env

Paste the bot token into .env:

DISCORD_BOT_TOKEN=your_actual_token_here

If you're running the web dashboard (dashboard.py) anywhere other than your
own machine (e.g. deployed on Render), also set:

DASHBOARD_USERNAME=your_choice
DASHBOARD_PASSWORD=your_choice

This locks the dashboard behind a login prompt. Without these set, the
dashboard refuses to start on a hosted platform (Render/Vercel) -- this is
intentional, since the dashboard can trigger live role changes and must
never sit open on a public URL with no login.

### 4. Get the IDs you need

Enable Developer Mode (User Settings -> Advanced -> Developer Mode), then
right-click to copy: Server ID, Message ID, Role ID.

## Usage

### Option A: Config file (recommended, reuse across clients)

cp config.example.json clients/acme_mint.json
python whitelist_sync.py --config clients/acme_mint.json --dry-run
python whitelist_sync.py --config clients/acme_mint.json

### Option B: One-off CLI flags

python whitelist_sync.py --server-id 123 --message-id 456 --role-id 789 --action ADD --dry-run
python whitelist_sync.py --server-id 123 --message-id 456 --role-id 789 --action ADD

Always run --dry-run first on a live client server. It shows exactly who
would be added/removed without changing anything, and still generates a
CSV report so you can review it before going live.

## Output

Every run produces:
- Terminal output + whitelist_sync.log — full activity log
- reports/report_ACTION_TIMESTAMP.csv — clean per-user results (username, user ID, result, detail) you can hand directly to a client

## Troubleshooting

- "Bot's highest role is not above X" -> Move the bot's role higher in Server Settings -> Roles
- "Could not find message" -> Check the message ID, or the bot may not have access to that channel, pass --channel-id to narrow the search
- "FAILED (missing permission)" for specific users -> That user likely has a role positioned higher than the bot's role, check role hierarchy
- Bot can't see server members -> Confirm "Server Members Intent" is enabled in the Developer Portal
