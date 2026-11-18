# NOTICE

## What this repository is

Independent security research on the **Cudy WR3000 v2.0** router. It is published for defensive
research, vendor accountability, and education. It is **not** affiliated with, sponsored by, or
endorsed by Cudy or any other vendor, and it is not a CNA advisory.

## What is included

Original writeups, a methodology note, safe verification guidance, and sanitized
proof-of-concept clients, all written by the author and licensed MIT (see `LICENSE-MIT`).

## What is deliberately excluded

- Vendor firmware images, rootfs or flash dumps, kernel modules, drivers, firmware blobs,
  calibration data, and decrypted/decompiled vendor Lua or other vendor bytecode.
- Credentials, keys, tokens, cookies, and the fleet `bdinfo` `secret`.
- Per-unit data: MAC addresses, serial numbers, bdinfo contents, device-specific topic IDs.
- Large local evidence artifacts. The full transcripts and dumps stay in a private archive; only
  the sanitized writeups and tools are published.

The writeups quote small descriptive details recovered from the vendor's own binaries — function
offsets, a plugin hash, the broker configuration, the topic/ACL grammar, and one static DES key
literal used by `libbdinfo.so` to decrypt the `bdinfo` partition. That DES literal is a
vendor-compiled constant, not a per-device credential; the per-fleet `secret` it unwraps is
**not** published, and recovering that secret still requires a `bdinfo` dump from a device you
already control. No vendor binary, object file, or rootfs image is redistributed here.

## Disclosure status

- The findings were made on the author's own hardware and published without a
  coordinated-disclosure agreement.
- **CVE-2026-71960** and **CVE-2026-71961** are the identifiers recorded for the two MQTT
  findings in the author's research ledger. This repository does not assert a CNA advisory
  record, an assignment by a specific CNA, or a vendor acknowledgement.
- No vendor security advisory or fixed release is known to the author for either MQTT finding as
  of 2026-11-18. The system-time command injection was fixed in firmware
  2.5.24-20260727-122111 (observed in the official image, not coordinated with this work).
- The vendor has **not** been contacted about these security findings. The only vendor contact in
  the wider project is a GPLv2 source request sent to `support@cudy.com` on 2026-10-01, which
  concerns source-code availability, not these vulnerabilities; no reply or receipt is held.
- If you are the vendor or an affected operator, please open an issue on this repository.

## Responsible use and legal notice

**Authorized research only.** Use this material only on devices you own or for which you hold
explicit written permission. Unauthorized access to computer systems is a criminal offence in
many jurisdictions, including under the U.S. Computer Fraud and Abuse Act, the UK Computer
Misuse Act, and equivalent laws elsewhere. The author does not authorize, encourage, or assist
any unauthorized use.

The tools are proof-of-concept clients for verification on your own hardware. They are
default-safe by design: demo modes send nothing, the MQTT client is passive unless a benign
command is explicitly requested, and the web PoC is dry-run unless `--send` is passed.

**No warranty.** This material is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness for a particular
purpose, and non-infringement. The author is not liable for any claim, damage, or other
liability arising from the use of this material. Running these tests may brick, expose, or
degrade a device; you accept that risk.

## License

Documentation and tools: **MIT** (see `LICENSE-MIT`). No GPL or vendor-derived code is
included; the writeups quote short factual details (offsets, constants, configuration strings)
under fair use for security research.