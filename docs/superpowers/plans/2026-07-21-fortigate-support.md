# FortiGate SSL VPN Support — Plan

**Date:** 2026-07-21
**Status:** Draft, pending review
**End goal:** Add FortiGate SSL VPN as a third protocol alongside AnyConnect and
Checkpoint, reusing the existing TUN/routing/forwarding datapath.

## Why this is small

The engine is already protocol-agnostic at the forwarding layer. Any protocol
that (a) establishes a TLS stream, (b) yields a `SessionParams` (address, DNS,
MTU, routes), and (c) provides a `TunnelFramer` impl, plugs straight into
`run_pipeline()` (`client.rs:109-159`). AnyConnect and Checkpoint both do exactly
this. FortiGate needs only its own **auth + config-fetch + session upgrade +
framing** — the TUN device, routing guard, and `forward.rs` select-loop are
reused unchanged.

## Protocol summary (from openfortivpn / OpenConnect research)

- **Transport:** HTTPS on 443. Same TLS socket is upgraded to a packet tunnel by
  `GET /remote/sslvpn-tunnel`.
- **Flow:** auth → `SVPNCOOKIE` → config XML → tunnel GET → framed IP over TLS.
- **Auth:** POST `/remote/logincheck` form
  `username=&credential=&realm=&ajax=1` → `Set-Cookie: SVPNCOOKIE=`. 2FA: 200
  without cookie carries `tokeninfo/reqid/polid/grp/magic/portal/peer`; replay +
  `code=&code2=&magic=`. mTLS client-cert supported at TLS layer.
- **Config:** `GET /remote/fortisslvpn_xml` → `<assigned-addr ipv4>`, `<dns ip>`,
  `<dns domain>`, `<split-tunnel-info><addr ip mask>`. No `split-tunnel-info` ⇒
  full tunnel. No MTU in XML → default/clamp (~1400).
- **Framing (v1 & v2 identical outer header):** 6-byte header on TLS stream —
  `[BE u16 total = 6+payload][BE u16 magic 0x5050][BE u16 payload_len][payload]`.
  Reject if `magic != 0x5050` or `total-6 != payload_len`.
  - **v2 (FortiOS ≳5.6.6):** payload = **raw IP packet**. Maps 1:1 to our TUN
    datapath. **Primary target.**
  - **v1 (legacy):** payload = PPP frame; needs in-process LCP+IPCP + RFC1662
    HDLC. **Deferred** (fallback, phase F2).
- **Keepalive/DPD:** no dedicated tunnel DPD. Periodic `GET /remote/sslvpn` on
  auth channel + read-timeout → reconnect.
- **UA gotcha:** `User-Agent` containing `SV1` → HTTP 405. Use `Mozilla/5.0`.

## Scope

### F1 (MVP) — in scope
- FortiGate **v2 (raw-IP over TLS)** client, TLS-only.
- Username/password auth + `SVPNCOOKIE`; **2FA/OTP** (common in FortiGate
  deployments — should be F1, not deferred).
- Config XML parse → `SessionParams` + split-tunnel routes.
- `FortigateTunnelFramer` (0x5050 6-byte header, raw-IP payload).
- Session keepalive GET + read-timeout DPD (reuses existing supervision).
- Enum variants + config plumbing + frontend selector.
- Desktop (Win/mac/Linux) **and** Android — datapath is shared, TUN factory
  (Office-Mode post-handshake TUN) already fits the assigned-addr model.

### Deferred
- **F2:** v1 PPP fallback (LCP/IPCP + HDLC, ~200-400 LOC) for old gateways.
- **F3:** PPP-over-DTLS (UDP) transport optimization.
- mTLS client-cert auth (wire it only if a target deployment needs it).

### Open risk
v2 in-band behavior beyond "payload == raw IP" is **not** documented in open
source (OpenConnect notes v2 but hasn't implemented it). **Budget one
packet-capture session against a real FortiGate** before trusting "no v2 control
frames." This is the one unknown that can move the estimate.

## Work breakdown

### 1. Enum + config plumbing (mechanical, ~6 edit sites)
- `crates/vpn-engine/src/config.rs:20` — add `Protocol::FortiGate`.
- `crates/vpn-ipc/src/lib.rs:24` — add `WireProtocol::FortiGate`.
- `crates/vpn-helper/src/main.rs:40-43` — `config_from_wire()` match arm.
- `crates/vpn-engine/src/client.rs:96-104` — dispatch arm →
  `connect_fortigate(...)`.
- `src-tauri/src/lib.rs` (Android handler ~272) — wire→engine arm.
- `src/lib/vpn.ts:3` — `type Protocol = "AnyConnect" | "Checkpoint" | "FortiGate"`;
  `ProfileDialog.tsx` selector auto-renders new option.

### 2. New module `crates/vpn-engine/src/fortigate/`
Mirror the `checkpoint/` shape:
- `mod.rs` — re-exports.
- `http.rs` — raw HTTP-over-rustls helper (write request line+headers, read
  status/headers/body) on a persistent `TlsStream`. Manual `Set-Cookie` / body
  param parse. Do **not** pull in `reqwest` for the hijacked socket.
- `auth.rs` — `authenticate_fortigate()`: logincheck POST, SVPNCOOKIE extract,
  2FA second round. URL-encode creds. Never log cookie (T-03 pattern).
- `config.rs` — `GET /remote/fortisslvpn_xml`, XML parse →
  `assigned-addr/dns/split-tunnel`. Reuse an XML parser already in tree if any,
  else minimal hand-parse (attributes only).
- `session.rs` — allocation GETs (`/remote/index`, `/remote/fortisslvpn`), then
  `GET /remote/sslvpn-tunnel` upgrade; assemble `SessionParams`.
- `framing.rs` — `FortigateTunnelFramer` impl of `TunnelFramer`
  (`framer.rs:36-65`): `encode_data*` prepend 6-byte 0x5050 header;
  `try_decode` read 6-byte header, validate magic+len, emit `FrameEvent::Data`;
  `encode_keepalive`/`encode_shutdown` — likely no tunnel-level frame (None),
  keepalive handled on auth channel.

### 3. `connect_fortigate()` in client.rs (~40-60 LOC)
Parallel to `connect_checkpoint()` (`client.rs:189-243`):
1. TLS connect to `host:port` (reuse existing TLS+cert-pin setup).
2. `authenticate_fortigate()` → cookie.
3. Fetch config XML → address/DNS/MTU/routes.
4. `GET /remote/sslvpn-tunnel` upgrade on same stream.
5. `run_pipeline(stream, params, routes, Box::new(FortigateTunnelFramer), ...)`.
- Android: same, TUN built post-handshake via `ANDROID_TUN_FACTORY` with
  assigned-addr (`client.rs:132-140`) — already the right shape.

### 4. Keepalive / DPD
- Session keepalive: low-rate `GET /remote/sslvpn` on auth channel. Decide:
  reuse the tunnel TLS stream (can't — hijacked) → needs a **second short-lived
  TLS conn** or fold into `forward.rs` timer. Simplest F1: rely on read-timeout
  DPD in existing supervision + traffic; add session-refresh GET only if
  gateways idle us out in testing.

### 5. Tests (mirror `vpn-ipc` / engine test style)
- `framing.rs` unit tests: encode/decode round-trip, magic reject, split reads
  (header split across TLS reads — `try_decode` must handle partial `BytesMut`).
- XML parse tests: full-tunnel (no split-info), split-tunnel, multi-DNS, 2FA
  challenge body parse.
- `cargo test -p vpn-engine` / `-p vpn-ipc`.

## Estimate
- Enum/plumbing: trivial (~1h).
- Module (http/auth/config/session/framing): bulk, ~2-3 days incl. tests.
- Wire-up + desktop bringup against a real/staged FortiGate: ~1 day (gated on
  gateway access + the v2 packet-capture unknown).
- 2FA polish + Android bringup: ~1 day.

## Sequencing
1. Enum + plumbing (compiles, dispatch stubs `todo!()`).
2. `http.rs` + `auth.rs` (prove cookie against real gateway) — **earliest
   external validation**, do first.
3. `config.rs` parse.
4. `framing.rs` + tests (offline).
5. `session.rs` + `connect_fortigate()` — end-to-end desktop.
6. Packet-capture confirm v2 raw-IP; adjust framing if control frames exist.
7. 2FA + Android + frontend polish.
