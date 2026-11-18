# Methodology note

This is a short, honest account of how the findings in this repository were produced, what the
evidence looks like, and where the limits are. It is not a step-by-step exploitation guide.

## Scope and rules of engagement

- One retail **Cudy WR3000 v2.0** unit, owned by the researcher, with physical access.
- Research was **host-only plus local-LAN verification**: no vendor infrastructure, no Cudy
  cloud, no third-party devices, no scanning of other people's equipment.
- Live tests used benign commands (`id` redirects) only. The unit was checked before and after,
  Wi-Fi state and calibration were not touched, no reboot was needed, and `cmagent` was never
  reconfigured during the final tests.
- The fleet `bdinfo` `secret`, tokens, cookies, and per-unit identifiers were handled in the
  private research ledger and are not part of this repository.

## Approach

1. **Offline firmware analysis.** The official 2.4.15 and 2.5.24 images were unpacked and
   diffed. The interesting components were the Mosquitto config/ACL, the JWT authentication
   plugin, the `cmagent` mesh daemon and its Lua handlers, `sync_command`, `libbdinfo.so`, and
   the LuCI controller/model bytecode.
2. **Static reverse engineering.** Compiled Lua 5.1 bytecode and ARM shared objects were
   disassembled to recover the authentication checks, the topic grammar, the `io.popen` sink,
   and the ACL-defer behaviour. Claims in the writeups carry function/offset references where
   they matter.
3. **Benign live verification on the unit.** Each finding was confirmed on the router with the
   smallest possible action: an authenticated form post that writes an `id` output file; an
   MQTT CONNECT plus a self-addressed `router/command` carrying a benign `id` redirect. No
   destructive command was used.
4. **State checks and cleanup.** The router's live binaries were hashed against the rootfs
   copies; process state, interfaces, and role settings were compared before and after; test
   files were removed and the results recorded. No reboot, flash, or persistent configuration
   change was required.

## Evidence discipline

- Every claim in the writeups is backed by a local artifact (transcript, disassembly excerpt,
  config/ACL capture, or final-health snapshot) in a private archive. That archive is not
  published because it contains device-unique data and local-only dumps.
- Where a claim is inferred rather than directly observed, it says so. Example: the exact
  trailing-NUL rule for the command payload was derived from the ARM disassembly and then
  confirmed by two live attempts (bare JSON fails, JSON plus NUL executes).
- The two CVE writeups describe live-verified behaviour; the sibling Latent sinks are labelled
  as unverified candidates.

## Sinks deliberately not published as working PoCs

- **JSON-RPC login password handling** (`/usr/lib/lua/luci/controller/rpc.lua` bytecode): the
  authentication path builds shell strings around the submitted password, including
  `echo -n '<password>' | crypt -ea` and `' | crypt -da`/`sha256sum` pipelines. This looks
  like a pre-authentication command-injection candidate, and an early raw JSON-RPC `login`
  payload was kept in the private ledger. It was **never verified**, a hex-string guard in the
  same routine may neutralize it, and the endpoint mapping was not established. Publishing an
  unverified, possibly-pre-auth payload would be more dangerous than useful, so this repository
  deliberately does not include it. If you are a defender, treat the `rpc.lua` password path as
  a sink worth auditing. If you are a vendor, this is a lead, not a proof.
- **LuCI terminal handler** (`terminal.lua`): raw
  `luci.util.exec(formvalue("cbid.syslog.1.cmd"))`, but the route returns 403 as shipped. It is
  described in the system-time writeup as a latent sink and no PoC is published.

## Limitations

- Findings are from a **single unit** and two firmware images. Fleet-wide impact is inferred
  from the firmware's design (one shared `bdinfo` key, one shared ACL) and from the fact that
  the 2.4.15 rootfs copies matched the live binaries, not from testing multiple devices.
- No second physical mesh node was available. The "no second node required" argument is proven
  for the admin-only case via its own wildcard subscription; a genuine satellite deployment was
  not exercised.
- The MQTT findings have **no known fixed release** as of publication. The 2.5.24 assessment is
  from the official image, not from a live 2.5.24 unit.
- The system-time finding is post-authentication only; no authentication bypass was found or
  chained.
- Offsets and hashes are for the named firmware build. Different builds may move code, though
  the design flaws are structural.
