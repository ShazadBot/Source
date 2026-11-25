# Shblood Website Scanner

1. Python 3.10+.
2. Install dependencies: `pip install -r requirements.txt`
3. Set `TELEGRAM_BOT_TOKEN` as an environment variable.
4. Run: `python bot.py`

## Railway
Upload the project to GitHub, deploy it on Railway, add `TELEGRAM_BOT_TOKEN`
to Variables, and set the start command to `python bot.py`.

## Limits
- Only public same-origin resources; use only websites you own or are authorized to inspect.
- Does not bypass login, paywalls, access controls, or retrieve backend source, databases, or secrets.
- Heuristic code indicators are not antivirus scanning and cannot prove a site is safe.
- Up to 6 HTML pages, 60 files, 5 MB per file, 25 MB total.
- The visible 3+2+2 second sequence starts after collection; network collection may take longer.

ShbloodTeam
