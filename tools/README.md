# Tools: sanitized proof-of-concept clients

> **Authorized research only.** These tools exist to verify the published findings on hardware
> you own or have explicit written permission to test. They contain no fleet secret, no forged
> token, no device-unique identifier, and no default network target.

| Tool | Purpose | Safe default |
| --- | --- | --- |
| [`forge_jwt.py`](forge_jwt.py) | Mint the JWT shape the WR3000 v2.0 Mosquitto plugin accepts (CVE-2026-71960). | `--demo` (placeholder secret); self-verifies locally. |
| [`mqtt_command_poc.py`](mqtt_command_poc.py) | Authenticate with the forged JWT and exercise the mesh command path (CVE-2026-71961). | `--demo` (no network); passive listen unless `--cmd`; benign-command allowlist. |
| [`systime_rce_poc.py`](systime_rce_poc.py) | Build/send the authenticated system-time injection request (2.4.15). | `--demo` (no network); dry run unless `--send`; benign payload. |

## Install

    python3 -m pip install -r requirements.txt

## Demo modes (no network, no secrets)

    python3 forge_jwt.py --demo
    python3 mqtt_command_poc.py --demo
    python3 systime_rce_poc.py --demo

## What is deliberately not here

- **The fleet `bdinfo` `secret`**, any forged token, MQTT password, cookie, MAC, serial, or
  other per-unit identifier.
- **The raw JSON-RPC `login` payload** kept in the private research ledger. That sink
  (`luci.controller.rpc` password handling) was never verified, may be neutralized by a
  hex-string guard, and could be pre-authentication; publishing it would be more dangerous than
  useful. See [`../writeups/methodology.md`](../writeups/methodology.md).
- **A `bdinfo` decryptor.** The writeup describes the vendor's constants and layout; the actual
  decryptor is not shipped. Use your own unit's data only.
- **A raw-payload escape hatch.** The private version of the MQTT client had a `--raw` flag for
  arbitrary pre-built payloads. It was removed for publication; the allowlist only permits
  `id`, `uname`, `echo`, `hostname`, and `true`.

## License

MIT. See [`../LICENSE-MIT`](../LICENSE-MIT).
