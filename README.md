# Cudy WR3000 v2.0: fleet-wide MQTT compromise and root command injection

Independent security research on the **Cudy WR3000 v2.0** router (HiSilicon "luofu" v2
platform, Hi5671YV200 SoC, stock OpenWrt 22.03.6-based firmware, Linux 5.10.201).

Two linked vulnerabilities are published here as **CVE-2026-71960** and **CVE-2026-71961**,
together with a separate authenticated command injection in the LuCI system-time page that is
fixed in the 2.5.24 firmware line. All findings were reproduced on the author's own hardware,
with benign commands only.

## Findings

| ID | Class | One-line summary |
| --- | --- | --- |
| [CVE-2026-71960](writeups/cve-2026-71960-71961-mqtt-command-chain.md#cve-2026-71960-what-the-plugin-checks) | Broken authentication / hard-coded fleet key | The Mosquitto JWT authentication plugin (`auth_plugin_jwt.so`) accepts a forged HS256 token signed with the **fleet-wide `bdinfo` `secret`**. The secret is not per-unit, and a token's `exp` is only checked against a fixed floor, never against the current clock. |
| [CVE-2026-71961](writeups/cve-2026-71960-71961-mqtt-command-chain.md#cve-2026-71961-topic-and-command-contract) | Missing authorization / root command execution | A client holding the **satellite MQTT role** can publish a controller-addressed `router/command` message that the admin `cmagent` daemon executes as **root** via `io.popen`. Authorization is a string convention in the topic (`src_did`), not a cryptographic binding. No second physical mesh node is required. |
| (no CVE claimed) | Authenticated command injection | [LuCI system-time page](writeups/systime-command-injection.md): `date -s '%s'` is built from an unescaped form value; an authenticated admin gets root command execution. Verified on 2.4.15; fixed in 2.5.24. |

The two MQTT findings chain: CVE-2026-71960 supplies the credential (a forged satellite JWT),
and CVE-2026-71961 turns that credential into root command execution on the admin node. A
single leaked `bdinfo` `secret` therefore endangers every unit from the same firmware line.

## Affected firmware and versions

| Firmware build | CVE-2026-71960 | CVE-2026-71961 | System-time injection |
| --- | --- | --- | --- |
| **2.4.15-20251030-114751** (R116) | vulnerable (verified live) | vulnerable (verified live) | vulnerable (verified live) |
| **2.5.24-20260727-122111** | no fix found in the artifacts examined; treat as unfixed | no fix found in the artifacts examined; treat as unfixed | **fixed** (single quotes stripped before formatting) |

Device identification matters: the enclosure label may read "WR3000 v1" while the PCB is the
**luofu v2** design. The MediaTek MT7981-based WR3000 v1 is a different product and is not the
subject of this research. Confirm the platform from the board itself before assuming these
findings apply.

The live tests covered one retail 2.4.15 unit. The 2.5.24 assessment is from the official
rootfs image: the same `auth_plugin_jwt.so` and `cmagent` command path are present,
`systime.lua` carries the quoting fix. No evidence of a fixed release for the two MQTT
findings was found; treat them as unpatched until the vendor publishes an advisory.

## Disclosure status and timeline

This is independent research. It was **not** produced under a coordinated-disclosure
agreement, and no vendor security advisory or fixed release is known to the author for
CVE-2026-71960 or CVE-2026-71961 as of **2026-11-18**.

| Date | Event |
| --- | --- |
| 2026-09-30 | LuCI system-time command injection found and verified on the author's own 2.4.15 unit. |
| 2026-10-01 | GPLv2 source request sent to `support@cudy.com` — unrelated to these security findings; no reply or receipt is held. |
| 2026-11-08 | CVE-2026-71960 confirmed live against the unit's Mosquitto broker; CVE-2026-71961 proven live the same day. Tests used a benign `id` redirect only: no reboot, no Wi-Fi change, no cmagent role change. |
| 2026-11-18 | Curated writeups and sanitized proof-of-concept tools published in this repository. |

**Vendor contact attempts for these findings: none.** The gists this repository is curated from
record that the vendor had not been contacted about either finding. The only vendor contact in
the wider project is the GPL source request above, which concerns source-code availability, not
these vulnerabilities. There is no vendor security contact, CNA acknowledgement, advisory, or
fix coordinated with this work. If you are the vendor or an affected operator, please open an
issue on this repository.

The CVE identifiers are used as recorded for these findings in the author's private research
ledger. This repository does not host a CNA advisory record and makes no claim about CNA
assignment mechanics.

## Defensive guidance

The fixes are vendor-side, but operators can reduce exposure substantially:

1. **Do not expose the MQTT broker.** Port **1883/tcp** is plaintext MQTT with JWT auth; port
   **8883/tcp** is TLS with client certificates. On the tested unit the broker binds
   `0.0.0.0:1883` but the WAN firewall zone rejects input, so exposure was LAN-only. Block
   both ports at every boundary (WAN, guest networks, bridged mesh links). Check with
   `netstat -ltn | grep -E ':1883|:8883'` and inspect the firewall zone's `input` policy.
2. **Disable the mesh agent if you do not use it.** `cmagent` runs as root and executes the
   command topic; an unused mesh is pure attack surface. Verify whether it runs with `-a`
   (admin) and whether `/var/run/cmagent` contains non-controller IDs.
3. **Patch the web UI.** Upgrade past **2.5.24-20260727-122111**, which closes the system-time
   injection. Keep LuCI on the LAN, use a unique admin password, and do not port-forward
   80/443. Note that the 2.5.24 fix addresses the systime sink only, not the MQTT findings.
4. **Treat a `bdinfo` secret leak as fleet compromise.** The key is shared across units of the
   same firmware line. A single unit's `bdinfo` dump authenticates against every trusting
   unit. There is no user-level rotation; the vendor must issue per-device keys.
5. **Detect.** Watch for unexpected MQTT connections (`clients: ... connected` in the broker
   log), subscriptions outside normal role patterns, `shell cmd` lines in `logread` from
   `cmagent`, and `/var/run/cmagent` entries you did not create.
6. **If you suspect compromise:** reflash known-good firmware, change admin credentials, and
   assume the fleet secret is exposed. Isolating the unit does not rotate the key.

Internet-wide scanning for these devices is not endorsed or assisted by this repository.

## Verify on your own device

See [`writeups/verify-on-your-own-device.md`](writeups/verify-on-your-own-device.md). It is
written for a device you own and control, uses placeholder values and the tools' `--demo`
modes, and deliberately does not publish the fleet secret, forged tokens, per-unit identifiers,
or the unverified JSON-RPC login sink payload.

## Repository map

| Path | Contents |
| --- | --- |
| [`README.md`](README.md) | This index: findings, affected versions, disclosure status, mitigation. |
| [`writeups/cve-2026-71960-71961-mqtt-command-chain.md`](writeups/cve-2026-71960-71961-mqtt-command-chain.md) | Full writeup for both MQTT findings: broker config, plugin checks, key provenance, topic contract, exploit chain, impact. |
| [`writeups/systime-command-injection.md`](writeups/systime-command-injection.md) | Full writeup for the LuCI system-time command injection. |
| [`writeups/methodology.md`](writeups/methodology.md) | How the research was done, evidence discipline, limitations, and sinks deliberately not published as PoCs. |
| [`writeups/verify-on-your-own-device.md`](writeups/verify-on-your-own-device.md) | Safe, authorized verification procedure for your own unit. |
| [`tools/forge_jwt.py`](tools/forge_jwt.py) | Mint the JWT shape the plugin accepts. Demo mode uses a placeholder secret. |
| [`tools/mqtt_command_poc.py`](tools/mqtt_command_poc.py) | Authenticate with the forged JWT and exercise the mesh command path. Benign-command allowlist; no raw payload flag. |
| [`tools/systime_rce_poc.py`](tools/systime_rce_poc.py) | Dry-run-first proof of concept for the system-time injection. |
| [`NOTICE.md`](NOTICE.md) | Legal and provenance notice: no vendor binaries, no credentials, coordinated-disclosure status. |
| [`LICENSE-MIT`](LICENSE-MIT) | MIT license for the documentation and tools in this repository. |

## Responsible use and legal notice

This material is published for **defensive research, vendor accountability, and education**.
Use it only on hardware you own or have explicit written permission to test. Unauthorized access
to a computer system is a crime in most jurisdictions (for example, the U.S. Computer Fraud and
Abuse Act, the UK Computer Misuse Act, and similar laws elsewhere), and this repository does not
authorize or assist it.

The research was performed on the author's own hardware. No vendor firmware, rootfs dump,
kernel module, calibration data, vendor Lua bytecode, or per-unit secret is included here. No
warranty of any kind is provided; see [`NOTICE.md`](NOTICE.md).

Repository content is licensed **MIT** (see [`LICENSE-MIT`](LICENSE-MIT)).
