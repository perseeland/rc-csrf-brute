# rc-csrf-brute

**CSRF-aware Roundcube login brute-forcer for CTF engagements.**

Roundcube protects its login form with a per-session CSRF token (`_token`)
bound to the `roundcube_sessid` cookie. Tools like ffuf and Hydra cannot
refresh this token between attempts, which makes them fail silently — every
request looks like a bad password even when the credentials are correct.

`rc-csrf-brute` solves this by opening a fresh session, scraping a new
`_token` from the login page, and submitting the POST **for every single
password guess**. Slow by design, reliable by necessity.

## Why this exists

- ffuf / wfuzz / Hydra don't do pre-flight GETs to harvest CSRF tokens.
- Roundcube returns `302/303` on success and `200` on failure — easy to
  misread if your token is stale.
- CTF boxes love Roundcube; this is the missing piece.

## Features

- Fresh `_token` + cookie per attempt (no false negatives from token reuse)
- Redirect-based success detection (`301/302/303`)
- CLI args or interactive prompts
- Wordlist loading, timeout control, stop-on-first-hit
- Pure Python 3 + `requests` — no other deps

## Usage

```bash
python3 rc_csrf_brute.py -u http://target/roundcube/ -U admin -w rockyou.txt
