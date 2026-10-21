# kudus Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add kudus (self-designed UDP reliable transport, full-random stealth) as a third agent↔server transport alongside WSS and QUIC, selected by `--server kudus://host:port`.

**Architecture:** New `src/common/kudus.rs` holds packet crypto/framing/SACK pure functions (XChaCha20-Poly1305, key=SHA256(token), 24B random nonce); new `src/server/kudus.rs` accepts UDP datagrams and reuses `on_register`/`spawn_egress_dial`/`spawn_link_relay`; new `src/agent/kudus_session.rs` dials kudus and reuses pump logic via a third `Sender`/`Tx` variant. WSS/QUIC paths untouched.

**Tech Stack:** chacha20poly1305 0.10 (xchacha), sha2 0.10 (already), rand 0.8/0.9, tokio 1 UDP sockets

## Global Constraints

- `make build` must pass with `RUSTFLAGS="-D warnings"` (zero warnings = hard error).
- `make test` (cargo test: unit + e2e) must be fully green before commit of each task.
- TDD: write failing test first, show RED caused by missing behavior (not typo), then GREEN with minimal impl.
- e2e uses real subprocesses + random ports + polling (max 40x200ms), never fixed long sleeps.
- WSS/QUIC behavior unchanged: `src/agent/session.rs`, `src/agent/quic_session.rs`, `src/server/tunnel.rs`, `src/server/quic.rs` are not modified except shared pure-function reuse and additive enum variants.
- Token-wrong packets are silently dropped (no reply, no warn log) — blackhole, never an oracle.
- MTU: single UDP datagram ≤ 1232B payload; proto_frame budget ≈ 1140B; oversize → error log, no chain break.

---

### Task 1: Common kudus packet crypto + framing + SACK pure functions

**Files:**
- Create: `src/common/kudus.rs`
- Modify: `src/common/mod.rs` (add `pub mod kudus;`)
- Modify: `Cargo.toml` (add `chacha20poly1305 = { version = "0.10", features = ["xchacha"] }`, `rand = "0.8"`)
- Modify: `src/common/quic.rs` (`Transport` enum add `Kudus { host: String, port: u16 }`, `parse_server_url` add `kudus://` branch)
- Test: `src/common/kudus.rs::tests`

**Interfaces:**
- Consumes: `ClientMsg/ServerMsg` serde from `src/common/proto.rs` (unchanged); `sha2::Sha256` (already a dep).
- Produces (exact signatures later tasks rely on):
  - `pub const KUDUS_MAX_UDP: usize = 1232;`
  - `pub const KUDUS_SACK_BITS: usize = 256;`
  - `pub fn derive_key(token: &str) -> [u8; 32]` — `SHA256(token)` bytes
  - `pub fn seal(key: &[u8; 32], nonce24: &[u8; 24], plain: &[u8]) -> Vec<u8>` — XChaCha20-Poly1305, returns ciphertext+16B tag
  - `pub fn open(key: &[u8; 32], nonce24: &[u8; 24], cipher_tag: &[u8]) -> Option<Vec<u8>>` — None on tag failure
  - `pub fn encode_packet(session: u32, nonce24: &[u8; 24], plain: &[u8]) -> Vec<u8>` — `[session 4B BE][nonce 24B][plain...]` (caller seals first)
  - `pub fn decode_packet(buf: &[u8]) -> Option<(u32, &[u8; 24], &[u8])>` — (session, nonce, cipher_tag); None if < 28B
  - `pub struct KudusHdr { pub ver: u8, pub flags: u8, pub seq: u32, pub ack: u32, pub sack: [u8; 32], pub ts_ms: u64 }` with `pub fn encode_hdr(h: &KudusHdr) -> [u8; 48]` / `pub fn decode_hdr(b: &[u8]) -> Option<(KudusHdr, &[u8])>`
  - `pub const FLAG_SYN: u8 = 0x01; FLAG_ACK: u8 = 0x02; FLAG_FIN: u8 = 0x04; FLAG_DATA: u8 = 0x08;`
  - `pub fn sack_mark(sack: &mut [u8; 32], base_ack: u32, seq: u32)` / `pub fn sack_missing(sack: &[u8; 32], base_ack: u32, window: u32) -> Vec<u32>` — SACK bitmap helpers
  - `pub fn fresh_nonce() -> [u8; 24]` — `rand::thread_rng().fill`
  - `pub fn now_ms() -> u64`

- [ ] **Step 1: Write the failing tests**

In `src/common/kudus.rs`, create the module with these tests (fail: module doesn't exist):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seal_open_roundtrip() {
        let k = derive_key("s3cret");
        let n = fresh_nonce();
        let c = seal(&k, &n, b"hello-kudus");
        let p = open(&k, &n, &c).unwrap();
        assert_eq!(p, b"hello-kudus");
    }
    #[test]
    fn wrong_token_is_blackhole() {
        let k1 = derive_key("right");
        let k2 = derive_key("wrong");
        let n = fresh_nonce();
        let c = seal(&k1, &n, b"secret");
        assert!(open(&k2, &n, &c).is_none()); // tag fails -> drop, no reply
    }
    #[test]
    fn tampered_nonce_fails() {
        let k = derive_key("t");
        let mut n = fresh_nonce();
        let c = seal(&k, &n, b"x");
        n[0] ^= 1;
        assert!(open(&k, &n, &c).is_none());
    }
    #[test]
    fn packet_hdr_roundtrip() {
        let k = derive_key("t");
        let n = fresh_nonce();
        let h = KudusHdr { ver: 1, flags: FLAG_DATA, seq: 101, ack: 99, sack: [0u8; 32], ts_ms: 12345 };
        let mut plain = encode_hdr(&h).to_vec();
        plain.extend_from_slice(b"payload");
        let pkt = encode_packet(0xdead_beef, &n, &seal(&k, &n, &plain));
        let (sess, nonce, ct) = decode_packet(&pkt).unwrap();
        assert_eq!(sess, 0xdead_beef);
        let opened = open(&k, nonce, ct).unwrap();
        let (h2, body) = decode_hdr(&opened).unwrap();
        assert_eq!((h2.seq, h2.ack), (101, 99));
        assert_eq!(body, b"payload");
        assert!(decode_packet(&pkt[..10]).is_none()); // short datagram
    }
    #[test]
    fn sack_marks_only_holes() {
        let mut sack = [0u8; 32];
        sack_mark(&mut sack, 100, 102);
        sack_mark(&mut sack, 100, 104);
        let missing = sack_missing(&sack, 100, 8);
        // 101,103,105..107 missing; 100 is acked base, 102/104 present
        assert!(missing.contains(&101) && missing.contains(&103));
        assert!(!missing.contains(&102) && !missing.contains(&104));
    }
    #[test]
    fn parse_kudus_scheme() {
        use crate::common::quic::{parse_server_url, Transport};
        assert!(matches!(parse_server_url("kudus://127.0.0.1:7445"), Transport::Kudus { .. }));
        assert!(matches!(parse_server_url("ws://127.0.0.1:7440/ws"), Transport::Ws(_)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bin neutrino kudus 2>&1 | tail -5`
Expected: FAIL — `can't find crate for kudus` / module doesn't exist (missing behavior, not typo).

- [ ] **Step 3: Write minimal implementation**

Create `src/common/kudus.rs` (~150 lines): constants, `derive_key` via `sha2::Sha256::digest(token.as_bytes())`, `seal`/`open` via `chacha20poly1305::{XChaCha20Poly1305, Key, XNonce}` + `AeadInPlace` (or `encrypt`/`decrypt` slice API), `encode_packet`/`decode_packet` (4+24 split, min len 28), `KudusHdr` 48B fixed layout (`ver,flags,seq BE,ack BE,sack 32B,ts_ms BE`), `sack_mark` (bit `seq-base_ack-1` in 256-bit LE bitmap), `sack_missing` (scan first `window` bits), `fresh_nonce` via `rand::RngCore::fill_bytes`, `now_ms` via `SystemTime::now().duration_since(UNIX_EPOCH)`.

In `src/common/mod.rs` add `pub mod kudus;`. In `src/common/quic.rs`: `Transport::Kudus { host: String, port: u16 }` + `kudus://` parse branch mirroring the `quic://` branch. In `Cargo.toml` add the two deps.

- [ ] **Step 4: Run tests to verify they pass**

Run: `RUSTFLAGS="-D warnings" cargo test --bin neutrino kudus 2>&1 | tail -3`
Expected: all new kudus tests PASS, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/common/kudus.rs src/common/mod.rs src/common/quic.rs Cargo.toml Cargo.lock
git commit -m "feat(kudus): packet crypto + framing + sack pure functions"
```

---

### Task 2: Server kudus listener + session semantics

**Files:**
- Create: `src/server/kudus.rs`
- Modify: `src/server/mod.rs` (add `pub mod kudus;`, wire `kudus_listen` spawn like `quic_listen`)
- Modify: `src/main.rs` (`Cmd::Server` add `kudus_listen: String` flag, pass to `server::run`)
- Test: `src/server/kudus.rs::tests` (replay/window pure logic)

**Interfaces:**
- Consumes: Task 1 (`derive_key/seal/open/encode_packet/decode_packet/KudusHdr/flags/sack_*`); `crate::server::tunnel::{on_register, spawn_egress_dial, spawn_link_relay}` (same as `server/quic.rs` does); `AgentHandle/AgentInfo/log_ev/save_state` from `super::state`.
- Produces: `pub async fn run_kudus(shared: S, token: Arc<String>, bind: &str) -> anyhow::Result<()>`; reuse of existing route tables (`agents/outbox/incoming/pending`) so WebUI sees kudus agents.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_seq_is_dropped() {
        let mut seen = SeqWindow::new(100);
        assert!(seen.check(101));
        assert!(!seen.check(101)); // replay
        assert!(!seen.check(50));  // below left edge
    }
    #[test]
    fn stale_ts_is_dropped() {
        assert!(!ts_fresh(crate::common::kudus::now_ms() - 120_000)); // 120s old
        assert!(ts_fresh(crate::common::kudus::now_ms()));
    }
    #[test]
    fn check_token_rejects_empty() {
        assert!(!check_token("", "s3cret"));
        assert!(!check_token("s3cret", ""));
        assert!(check_token("s3cret", "s3cret"));
    }
}
```

`SeqWindow`/`ts_fresh`/`check_token` don't exist yet → RED.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino server::kudus 2>&1 | tail -5`
Expected: FAIL — `unresolved import` / not found.

- [ ] **Step 3: Write minimal implementation**

`src/server/kudus.rs` (~450 lines, mirror `src/server/quic.rs::handle_conn` structure):
- `run_kudus`: `UdpSocket::bind`, loop `recv_from` → per-`session_id` task map (`Arc<RwLock<HashMap<u32, mpsc::Sender<(SocketAddr, Vec<u8>)>>>`); unknown session + `FLAG_SYN` → spawn `handle_conn`; known → forward; unknown non-SYN → drop.
- `handle_conn`: SYN decrypt → `Hello{token,hostname}` check (`check_token`, fail = silent return, no packet) → send SYN-ACK (`Welcome`) with 200/400/800ms ×5 retry → wait ACK (`Register`) → `AgentHandle` registration in same tables → `on_register` + `needs_config_push` reuse → control loop: decrypt each datagram → `ts_fresh` + `SeqWindow::check` → JSON control (`Register/Ping/Pong/Close`) or `[sid][payload]` data via `deliver` (same as quic.rs) → 15s Ping heartbeat → FIN → dual-close + `cleanup` (same totals/routes/save_state).
- Data plane: server→agent via `outbox` sender `(sid, chunk)` wrapped in kudus DATA packet to last-known peer addr; agent→server stream bytes via `deliver` + `pending` 64-cap (copy `quic.rs::deliver`/`drain_stream_into_incoming`).
- `main.rs`: `#[arg(long, default_value = "")] kudus_listen: String` + pass-through; `server/mod.rs::run(..., kudus_listen: &str)` + spawn block mirroring `quic_listen`, print `kudus : udp-k://{bind}`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `RUSTFLAGS="-D warnings" cargo test --bin neutrino 2>&1 | grep -E "test result|error"`
Expected: all unit tests PASS (67 + 3 new), zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/server/kudus.rs src/server/mod.rs src/main.rs
git commit -m "feat(kudus): server listener + session semantics over kudus"
```

---

### Task 3: Agent kudus session + transport routing

**Files:**
- Create: `src/agent/kudus_session.rs`
- Modify: `src/agent/mod.rs` (routing: `Transport::Kudus` → kudus session; third egress holder `kudus_egress_out`)
- Modify: `src/agent/stream.rs` (add `KudusSender` impl of `Sender`)
- Modify: `src/agent/egress.rs` (`DualOut` → third `kudus` field or `TripleOut`; keep constructor call-sites compiling)
- Modify: `src/agent/link.rs` (`Tx::Kudus` variant + `serve_link_kudus`-style branch)
- Modify: `src/agent/web.rs` (`validate_server_url` accept `kudus://` + test)
- Test: `src/agent/web.rs::tests` (kudus URL accepted)

**Interfaces:**
- Consumes: Task 1 crypto; `Upstream/AgentFileConfig/AgentStatus` (existing); `DualOut`/`Tx`/`Sender` extension points.
- Produces: `pub async fn session(up: Upstream, cfg: AgentFileConfig, status: Arc<RwLock<AgentStatus>>, out: KudusOutHolder) -> anyhow::Result<()>` mirroring `quic_session::session` signature.

- [ ] **Step 1: Write the failing test**

In `src/agent/web.rs::tests` add:

```rust
#[test]
fn validate_accepts_kudus() {
    assert!(validate_server_url("kudus://127.0.0.1:7445"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino validate_accepts_kudus 2>&1 | tail -3`
Expected: FAIL — `kudus://` returns false.

- [ ] **Step 3: Write minimal implementation**

- `web.rs`: one-line `|| s.starts_with("kudus://")`.
- `stream.rs`: `KudusSender(pub(crate) mpsc::UnboundedSender<Vec<u8>>)` — `send_data` wraps `encode_data(sid, chunk)` in kudus DATA seal via session's packetizer closure; simplest: sender holds `Arc<Packetizer>` with (key, session, seq counter, peer addr, socket handle) and emits ready-to-send datagrams. Keep `Sender` trait (data/ctrl/close) so `http_response_pump`/`stream_body_until_idle` are reused unchanged.
- `kudus_session.rs` (~400 lines, mirror `quic_session.rs`): UDP socket dial → SYN → SYN-ACK → Register → heartbeat 30s → Config hot-update (ConfigAck+Register) → dispatch loop (control JSON / `[sid][payload]` / dgram inner) → `open_stream`/`pump_tcp`/`open_udp_stream` with `KudusSender` → sliding-window sender (cwnd 16, rwnd 64, SACK补洞, RTO retransmit) + `SeqWindow` receiver + FIN fast-close.
- `mod.rs`: `Transport::Kudus{..}` → kudus task; `status.transport = "kudus"`; egress holder triple; `link.rs::Tx::Kudus` + serve branch (copy `serve_link_quic` pattern with kudus holder).

- [ ] **Step 4: Run tests to verify they pass**

Run: `RUSTFLAGS="-D warnings" cargo test --bin neutrino 2>&1 | grep -E "test result|error"`
Expected: PASS, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/agent/kudus_session.rs src/agent/mod.rs src/agent/stream.rs src/agent/egress.rs src/agent/link.rs src/agent/web.rs
git commit -m "feat(kudus): agent session + routing"
```

---

### Task 4: e2e + docs

**Files:**
- Modify: `tests/e2e.rs` (add `boot_kudus`, `kudus_http_udp_and_hot_config`, `kudus_bad_token_blackhole`)
- Modify: `README.md`, `docs/architecture.md` (kudus usage/frame notes)
- Test: the two new e2e tests

**Interfaces:**
- Consumes: Tasks 1–3 (working kudus path).
- Produces: green e2e proving kudus http/udp/hot-config + blackhole-on-wrong-token.

- [ ] **Step 1: Write the failing tests**

Copy `boot_quic` → `boot_kudus` (`--kudus-listen` + `kudus://` agent), then:

```rust
#[tokio::test]
async fn kudus_http_udp_and_hot_config() {
    // ... same shape as quic_http_udp_and_hot_config: http 200 "kudus-ok",
    // udp echo, hot-config clear -> 404 + udp timeout
}

#[tokio::test]
async fn kudus_bad_token_blackhole() {
    // wrong-token agent: agents table has no "bad", conns empty,
    // AND server sent zero UDP bytes back (blackhole, not even 401).
}
```

Blackhole assertion: bind a UDP probe socket, send a garbage datagram to the kudus port, assert `timeout(recv)` — server must not reply to undecryptable packets.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test e2e kudus 2>&1 | tail -5`
Expected: FAIL — `--kudus-listen` flag doesn't exist (before Task 2/3) or no convergence.

- [ ] **Step 3: Write minimal implementation**

Only test-body completion + docs edits (transport code already in Tasks 1–3): README protocol section add kudus bullet (`kudus://`, `key=SHA256(token)`, XChaCha full-random, SACK/AIMD); architecture.md one-line transport note.

- [ ] **Step 4: Run tests to verify they pass**

Run: `RUSTFLAGS="-D warnings" cargo test 2>&1 | grep -E "test result"`
Expected: unit + e2e fully green.

- [ ] **Step 5: Commit**

```bash
git add tests/e2e.rs README.md docs/architecture.md
git commit -m "test(kudus): e2e http/udp/hot-config/blackhole + docs"
```

---

## Self-Review

- Spec §1 (full-random packet) → Task 1 (seal/open/nonce/session, 1140B budget enforced by `KUDUS_MAX_UDP` check at send sites in Tasks 2–3).
- Spec §2 (2-round handshake, blackhole) → Tasks 2+3 handshake flows; blackhole covered by Task 1 `wrong_token_is_blackhole` + Task 4 probe test.
- Spec §3 (window+SACK+AIMD) → Task 3 sender; `sack_mark/sack_missing` in Task 1; Task 2 server side ACKs mirror quic heartbeat/data path.
- Spec §4 (ts ±60s + seq window) → Task 2 `ts_fresh`/`SeqWindow` + tests; `nonce→seq` map in Task 3.
- Spec §5 (2-step FIN) → Tasks 2+3 close paths (200ms ×3 retry, timeout-local-close).
- Spec §6 (integration slots) → exact files listed in Tasks 1–3; no WSS/QUIC semantic changes.
- Spec §7 (tests) → Task 1 unit + Task 4 e2e; QUIC's flaky link e2e stays deleted (no link-over-kudus e2e, unit-covered only).
- No placeholders: all signatures/commands/values concrete. Type check: `Transport::Kudus{host,port}` matches quic.rs enum style; `KudusSender` satisfies existing `Sender: Clone+Send+'static` bound.
