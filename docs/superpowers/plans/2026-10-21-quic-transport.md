# QUIC Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add QUIC as a second agent↔server transport alongside WSS, selected by `--server quic://` scheme.

**Architecture:** New `src/common/quic.rs` holds length-prefixed framing pure functions; new `src/server/quic.rs` accepts QUIC conns and reuses `resolve_proxies`/`needs_config_push`/route tables; new `src/agent/quic_session.rs` dials QUIC and reuses pump logic. WSS paths untouched.

**Tech Stack:** quinn 0.11, rustls 0.23, rcgen 0.13, tokio 1, axum 0.7 (unchanged)

## Global Constraints

- `make build` must pass with `RUSTFLAGS="-D warnings"` (zero warnings = hard error).
- `make test` (cargo test: unit + e2e) must be fully green before commit of each task.
- TDD: write failing test first, show RED caused by missing behavior (not typo), then GREEN with minimal impl.
- e2e uses real subprocesses + random ports + polling (max 40x200ms), never fixed long sleeps.
- WSS behavior unchanged: `ws://`/`wss://` paths in `src/agent/session.rs` and `src/server/tunnel.rs` are not modified except shared pure-function reuse.
- `ProxyConfig` field changes require `PartialEq` convergence check (`needs_config_push`) to still pass.

---

### Task 1: Common QUIC framing + URL parsing pure functions

**Files:**
- Create: `src/common/quic.rs`
- Modify: `src/common/mod.rs` (add `pub mod quic;`)
- Modify: `Cargo.toml` (add `quinn`, `rcgen`, `rustls`/`sha2` as needed)
- Test: `src/common/quic.rs::tests`

**Interfaces:**
- Consumes: `ClientMsg/ServerMsg` serde from `src/common/proto.rs` (unchanged).
- Produces:
  - `pub const CONTROL_MAX: usize = 1_048_576;`
  - `pub fn encode_ctrl(msg: &ClientMsg or ServerMsg) -> Vec<u8>` — actually generic: `pub fn encode_frame(json: &[u8]) -> Vec<u8>` = `[len u32BE][bytes]`
  - `pub fn decode_frames(buf: &[u8]) -> (Vec<Vec<u8>>, usize)` — returns complete frames + consumed bytes (handles sticky/half packets)
  - `pub fn encode_dgram(payload: &[u8]) -> Vec<u8>` = `[dlen u16BE][payload]`, `pub fn decode_dgram(buf: &[u8]) -> Option<(&[u8], usize)>`
  - `pub fn parse_server_url(url: &str) -> Transport` where `pub enum Transport { Ws(String), Quic { host: String, port: u16 } }`
  - `pub fn control_to_json<M: Serialize>(m: &M) -> Vec<u8>` helper

- [ ] **Step 1: Write the failing tests**

In `src/common/quic.rs`, create module with these tests (they fail: module doesn't exist):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_roundtrip_sticky_and_half() {
        let a = encode_frame(br#"{"t":"ping","ts":1}"#);
        let b = encode_frame(br#"{"t":"pong","ts":2}"#);
        let mut sticky = Vec::new(); sticky.extend_from_slice(&a); sticky.extend_from_slice(&b);
        let (frames, used) = decode_frames(&sticky);
        assert_eq!(frames.len(), 2);
        assert_eq!(used, sticky.len());
        // half packet: only len prefix + 1 byte -> no complete frame
        let (frames2, used2) = decode_frames(&a[..5]);
        assert!(frames2.is_empty() && used2 == 0);
    }
    #[test]
    fn frame_rejects_oversize() {
        let big = vec![0u8; CONTROL_MAX + 1];
        assert!(encode_frame_checked(&big).is_err());
        let mut hdr = (CONTROL_MAX as u32 + 1).to_be_bytes().to_vec();
        let (frames, _) = decode_frames(&hdr);
        assert!(frames.is_empty());
    }
    #[test]
    fn dgram_roundtrip_and_reject() {
        let p = encode_dgram(b"hello");
        let (body, used) = decode_dgram(&p).unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(used, p.len());
        assert!(decode_dgram(&[]).is_none());
        let big = vec![0u8; 65528];
        assert!(encode_dgram_checked(&big).is_err());
    }
    #[test]
    fn parse_transport_by_scheme() {
        assert!(matches!(parse_server_url("ws://127.0.0.1:7440/ws"), Transport::Ws(_)));
        assert!(matches!(parse_server_url("wss://tunnel.nat.kkito.cn:7443/ws"), Transport::Ws(_)));
        let Transport::Quic { host, port } = parse_server_url("quic://127.0.0.1:7444") else { panic!("quic") };
        assert_eq!((host.as_str(), port), ("127.0.0.1", 7444));
        assert!(matches!(parse_server_url("http://x/"), Transport::Invalid));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino common::quic 2>&1 | tail -5`
Expected: FAIL with `error[E0583]: file not found for module quic` / test not found.

- [ ] **Step 3: Write minimal implementation**

Create `src/common/quic.rs`:

```rust
//! QUIC transport framing: length-prefixed control frames + dgram-in-stream.
use std::fmt;
#[derive(Debug, Clone)]
pub enum Transport { Ws(String), Quic { host: String, port: u16 }, Invalid }
pub const CONTROL_MAX: usize = 1_048_576;
pub const DGRAM_MAX: usize = 65527;
#[derive(Debug)]
pub struct FrameError(pub String);
impl fmt::Display for FrameError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) } }
impl std::error::Error for FrameError {}
pub fn encode_frame(json: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + json.len());
    v.extend_from_slice(&(json.len() as u32).to_be_bytes());
    v.extend_from_slice(json);
    v
}
pub fn encode_frame_checked(json: &[u8]) -> Result<Vec<u8>, FrameError> {
    if json.len() > CONTROL_MAX { return Err(FrameError("control frame too large".into())); }
    Ok(encode_frame(json))
}
/// returns (complete payload frames, consumed bytes)
pub fn decode_frames(buf: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut out = Vec::new(); let mut off = 0;
    while buf.len() - off >= 4 {
        let len = u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]) as usize;
        if len > CONTROL_MAX { break; } // malicious: stop, caller closes conn
        if buf.len() - off - 4 < len { break; } // half packet
        out.push(buf[off+4..off+4+len].to_vec());
        off += 4 + len;
    }
    (out, off)
}
pub fn encode_dgram(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + payload.len());
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}
pub fn encode_dgram_checked(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > DGRAM_MAX { return Err(FrameError("dgram too large".into())); }
    Ok(encode_dgram(payload))
}
pub fn decode_dgram(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.len() < 2 { return None; }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() - 2 < len { return None; }
    Some((&buf[2..2+len], 2 + len))
}
pub fn parse_server_url(url: &str) -> Transport {
    if url.starts_with("ws://") || url.starts_with("wss://") { return Transport::Ws(url.to_string()); }
    if let Some(rest) = url.strip_prefix("quic://") {
        let rest = rest.trim_end_matches('/');
        if let Some((h, p)) = rest.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                if !h.is_empty() && port != 0 { return Transport::Quic { host: h.to_string(), port }; }
            }
        }
    }
    Transport::Invalid
}
```

Add to `src/common/mod.rs`: `pub mod quic;`. Add deps to `Cargo.toml`:

```toml
quinn = { version = "0.11", features = ["rustls-ring"] }
rcgen = "0.13"
sha2 = "0.10"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino common::quic 2>&1 | tail -5`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/common/quic.rs src/common/mod.rs Cargo.toml Cargo.lock
git commit -m "feat(quic): length-prefixed framing + transport url parse"
```

### Task 2: Server QUIC listener + Hello auth (up to Welcome/Close)

**Files:**
- Create: `src/server/quic.rs`
- Modify: `src/server/mod.rs` (add `pub mod quic;`, wire `--quic-listen`)
- Modify: `src/main.rs` (add `quic_listen` CLI flag to `Cmd::Server`)
- Test: `src/server/quic.rs::tests` (cert gen + token check pure fns)

**Interfaces:**
- Consumes: `Transport::Quic`, `encode_frame/decode_frames` from Task 1; `Shared/S` from `src/server/state.rs`.
- Produces:
  - `pub fn self_signed_cert() -> (rustls::Certificate pair...)` — actually `pub fn make_self_signed() -> anyhow::Result<(Vec<u8> cert_der, Vec<u8> key_der)>` via rcgen, plus `pub fn cert_fingerprint(cert_der: &[u8]) -> String` (sha256 hex first 16).
  - `pub async fn run_quic(s: S, token: Arc<String>, bind: String) -> anyhow::Result<()>` — binds UDP, accepts, spawns `handle_conn`.
  - `pub(crate) fn check_token(got: &str, want: &str) -> bool` (constant-time-ish compare, empty rejects).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_check_rejects_empty_and_mismatch() {
        assert!(check_token("s3cret", "s3cret"));
        assert!(!check_token("wrong", "s3cret"));
        assert!(!check_token("", "s3cret"));
        assert!(!check_token("", ""));
    }
    #[test]
    fn self_signed_cert_roundtrip() {
        let (cert, key) = make_self_signed().unwrap();
        assert!(!cert.is_empty() && !key.is_empty());
        let fp1 = cert_fingerprint(&cert);
        let fp2 = cert_fingerprint(&cert);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino server::quic 2>&1 | tail -5`
Expected: FAIL with `error[E0583]: file not found for module quic`.

- [ ] **Step 3: Write minimal implementation**

Create `src/server/quic.rs` with: rcgen self-signed gen (SAN `neutrino-quic`), persist handled by caller in `mod.rs`; quinn `ServerConfig` from single cert; accept loop; per-conn: `accept_bi` control stream → read len-prefixed Hello (15s timeout) → `check_token` → on fail `connection.close(401u32.into(), b"bad token")` + `log_ev`, on ok send `encode_frame(Welcome JSON)` → then `connection.closed().await` (full session comes in Task 3; this task ends after Welcome so e2e can assert handshake).

CLI in `src/main.rs` `Cmd::Server` add:

```rust
/// QUIC UDP listen (empty = disabled), e.g. 0.0.0.0:7444
#[arg(long, default_value = "")]
quic_listen: String,
```

and pass to `server::run(...)`. In `src/server/mod.rs` change signature to `pub async fn run(listen: &str, _http_in: &str, data: &str, token: &str, desired: &str, quic_listen: &str)` and after TCP bind, if `!quic_listen.is_empty()` spawn `quic::run_quic(shared.clone(), token.clone(), quic_listen.to_string())` + print fingerprint.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino server::quic 2>&1 | tail -5` → PASS; then `make build 2>&1 | tail -3` → zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/server/quic.rs src/server/mod.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "feat(quic): server quic listener + hello auth"
```

### Task 3: QUIC session semantics (Register/Config/heartbeat/pumps)

**Files:**
- Modify: `src/server/quic.rs` (extend `handle_conn` to full loop)
- Test: `src/server/quic.rs::tests` (reuse `needs_config_push`/`resolve_proxies`)

**Interfaces:**
- Consumes: `resolve_proxies`, `apply_proxies_for_agent`, `needs_config_push` from `src/server/tunnel.rs`/`state.rs`; `AgentHandle/AgentInfo` registration pattern copied from `ws_loop` (same `agents`/`outbox`/`incoming`/`pending` tables so WebUI/conns/traffic see QUIC agents identically).
- Produces: full control loop: `Register→on_register`, `Ping→Pong`, `Pong→rtt`, `Close→drop incoming`, `egress/link Open` spawn same `spawn_egress_dial`/`spawn_link_listen` equivalents (reuse via `pub(crate)` visibility change in `tunnel.rs` if needed).

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn quic_register_converges_without_extra_push() {
    // RED: QUIC handle_conn must call on_register with resolve_proxies semantics;
    // without impl, agent stays unregistered (proxies empty).
    let proxies = vec![crate::common::proto::ProxyConfig {
        name: "web".into(), ptype: "http".into(), local_ip: "127.0.0.1".into(),
        local_port: 80, domains: vec!["a.test".into()], remote_port: 0,
        set_x_forwarded_proto: None, basic_auth: None, enabled: true,
        link_agent: String::new(), link_host: String::new(), link_port: 0,
    }];
    assert!(!crate::server::tunnel::needs_config_push(&[], &proxies));
    assert!(!crate::server::tunnel::needs_config_push(&proxies, &proxies));
}
```

(Plus a comment noting RED proof: with Task-2-only server, a QUIC Register gets no `apply_proxies_for_agent`, so route table stays empty — the e2e in Task 5 captures it.)

- [ ] **Step 2: Run test to verify it fails/passes as appropriate**

Run: `cargo test --bin neutrino server::quic 2>&1 | tail -5`
Expected: PASS at unit level but behavior missing — RED is demonstrated by Task 5 e2e (do not fake GREEN here; proceed to implement loop).

- [ ] **Step 3: Write minimal implementation**

Extend `handle_conn` in `src/server/quic.rs`: after Welcome, register `AgentHandle` in `s.agents` (same fields as `ws_loop`: `ctl` channel, `incoming`, `pending`, restore totals), then loop `accept_bi` for control + `read_exact(4+len)` decode to `ClientMsg`; handle:
- `Register → on_register(&s, &agent_id, &hostname, proxies).await`
- `Ping → send_ctrl(Pong)`, `Pong → update rtt_ms`
- `Close{stream} → incoming/pending remove`
- `Open{egress/link} → same spawn fns` (change `spawn_egress_dial`/`spawn_link_relay` in `tunnel.rs` from `fn` to `pub(crate) fn` if needed)
- data streams: each `accept_bi` that is NOT control → first frame `Open`, then pump bytes into `incoming[sid]` / `outbox`, rx/tx accounting identical to Binary branch (single place, copy the 10-line accounting block).
- per-tunnel stream = one QUIC bidi stream; UDP payloads inside use `encode_dgram`/`decode_dgram` (Task 1) to preserve boundaries.

- [ ] **Step 4: Run test to verify it passes**

Run: `make build 2>&1 | tail -3` then `cargo test --bin neutrino 2>&1 | tail -3`
Expected: all green, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/server/quic.rs src/server/tunnel.rs
git commit -m "feat(quic): server session semantics over quic"
```

### Task 4: Agent QUIC session + `--server quic://` routing + WebUI transport

**Files:**
- Create: `src/agent/quic_session.rs`
- Modify: `src/agent/mod.rs` (transport match on `parse_server_url`; add `transport` to reconnection loop)
- Modify: `src/agent/web.rs` (add `transport: String` to `AgentStatus`, `validate_server_url` accepts `quic://`, status snapshot sets it)
- Test: `src/agent/web.rs::tests` + `src/agent/quic_session.rs::tests`

**Interfaces:**
- Consumes: `Transport::parse_server_url`, framing from Task 1; `Ctx` pattern from `src/agent/session.rs` (reuse same struct shape: `proxies/link_tasks/streams/pending/out` where `out` becomes an internal mpsc of bytes-to-control instead of tungstenite `Message`).
- Produces:
  - `pub(crate) async fn session(up: Upstream, cfg: AgentFileConfig, status: Arc<RwLock<AgentStatus>>, egress_out: OutHolder) -> anyhow::Result<()>`
  - `AgentStatus.transport: String` (`"quic"` or `"wss"`), set at session start.

- [ ] **Step 1: Write the failing tests**

In `src/agent/web.rs::tests` extend:

```rust
#[test]
fn server_url_accepts_quic_scheme() {
    assert!(validate_server_url("quic://127.0.0.1:7444"));
    assert!(!validate_server_url("quic://127.0.0.1")); // missing port
    assert!(!validate_server_url("quic://")); // empty
}
```

In `src/agent/quic_session.rs::tests`:

```rust
#[test]
fn quic_requires_port() {
    assert!(matches!(crate::common::quic::parse_server_url("quic://h:1"), crate::common::quic::Transport::Quic { .. }));
    assert!(matches!(crate::common::quic::parse_server_url("quic://h"), crate::common::quic::Transport::Invalid));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino agent:: 2>&1 | tail -8`
Expected: FAIL (`validate_server_url` rejects `quic://…`; `quic_session` module missing).

- [ ] **Step 3: Write minimal implementation**

`src/agent/quic_session.rs`: `quinn::Endpoint::client("0.0.0.0:0")`, custom `ServerCertVerifier` that skips chain verification (dangerous config, comment "self-signed: real auth is token"), `connect(host:port, "neutrino-quic")`, open control bidi stream, send `encode_frame(Hello JSON)`, 15s timeout read `Welcome`, send `Register`, spawn ping loop, reader loop over control frames mirroring `session.rs` match arms, per-`Open` spawn `open_stream` (copy `session.rs::open_stream` body, replacing `ctx.out.send(Message::Binary…)` with control-frame send + `quic SendStream::write_all`). UDP uses `encode_dgram`/`decode_dgram`. `AgentStatus.transport = "quic"`.

`src/agent/mod.rs` reconnection loop: `match parse_server_url(&up.server_url) { Transport::Ws(_) => session::session(…).await, Transport::Quic{..} => quic_session::session(…).await, Transport::Invalid => Err("bad --server scheme (ws://, wss://, quic://)") }`. Error string prefixed `quic:` on QUIC failures.

`src/agent/web.rs`: `validate_server_url` add `s.starts_with("quic://")` arm (keep case-sensitive lowercase-only rule); `AgentStatus` add `#[serde(default)] pub transport: String`; snapshot updates set it.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino agent:: 2>&1 | tail -5` → PASS; `make build 2>&1 | tail -3` → clean.

- [ ] **Step 5: Commit**

```bash
git add src/agent/quic_session.rs src/agent/mod.rs src/agent/web.rs
git commit -m "feat(quic): agent quic session + quic:// routing"
```

### Task 5: e2e (QUIC HTTP+UDP+hot-config, bad token) + docs

**Files:**
- Modify: `tests/e2e.rs` (add `boot_quic`, `quic_basic`, `quic_bad_token_closes`)
- Modify: `README.md`, `docs/architecture.md` (QUIC rows)
- Test: the two new e2e tests

**Interfaces:**
- Consumes: everything from Tasks 1–4; existing e2e helpers `free_port/wait_for/e2e_stdio/http_raw/login`.
- Produces: green `make test` including new e2e.

- [ ] **Step 1: Write the failing tests**

Append to `tests/e2e.rs`:

```rust
/// QUIC 传输 e2e：server 开 --quic-listen，agent 用 quic:// 建连，
/// HTTP 透隧道 + UDP 回声 + WebUI 热下发 Config 生效。
/// 旧代码复现：无 QUIC 实现时 agent 建连失败（quic:// scheme 被拒）。
async fn boot_quic(desired_toml: &str) -> (Env, u16) {
    let ws_port = free_port(); let quic_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-quic-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let cfg_path = dir.join("agent.toml");
    tokio::fs::write(&cfg_path, "hostname = \"e2eq\"\ntoken = \"s3cret\"\n").await.unwrap();
    let data = dir.join("data"); tokio::fs::create_dir_all(&data).await.unwrap();
    let desired_path = dir.join("desired.toml");
    tokio::fs::write(&desired_path, desired_toml).await.unwrap();
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio()).stderr(e2e_stdio())
        .args(["server", "--listen", &format!("127.0.0.1:{ws_port}"),
            "--quic-listen", &format!("127.0.0.1:{quic_port}"),
            "--data", data.to_str().unwrap(), "--desired", desired_path.to_str().unwrap(),
            "--token", "s3cret"])
        .kill_on_drop(true).spawn().unwrap();
    wait_for(&format!("127.0.0.1:{ws_port}")).await;
    // QUIC 是 UDP：等 control 面就绪（轮询 overview 出现 agent，40x200ms）
    let ag = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio()).stderr(e2e_stdio())
        .args(["agent", "--server", &format!("quic://127.0.0.1:{quic_port}"),
            "--config", cfg_path.to_str().unwrap()])
        .kill_on_drop(true).spawn().unwrap();
    (Env { http_port: ws_port, web_base: format!("http://127.0.0.1:{ws_port}"),
        data_dir: data, _srv: srv, _ag: ag }, quic_port)
}

#[tokio::test]
async fn quic_http_udp_and_hot_config() {
    let local_http = free_port(); let local_udp = free_port(); let pub_udp = free_port();
    // local http echo
    tokio::spawn(async move {
        let l = tokio::net::TcpListener::bind(format!("127.0.0.1:{local_http}")).await.unwrap();
        loop { let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut b = vec![0u8; 4096]; let n = s.read(&mut b).await.unwrap_or(0);
                let body = format!("quic-ok {}", String::from_utf8_lossy(&b[..n]).len());
                let resp = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", body.len(), body);
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    // local udp echo
    tokio::spawn(async move {
        let s = tokio::net::UdpSocket::bind(format!("127.0.0.1:{local_udp}")).await.unwrap();
        let mut b = vec![0u8; 65535];
        loop { if let Ok((n, p)) = s.recv_from(&mut b).await { let _ = s.send_to(&b[..n], p).await; } }
    });
    let desired = format!("[[agents.e2eq]]\nname = \"w\"\ntype = \"http\"\nlocal_ip = \"127.0.0.1\"\nlocal_port = {local_http}\ndomains = [\"q.test\"]\n\n[[agents.e2eq]]\nname = \"u\"\ntype = \"udp\"\nlocal_ip = \"127.0.0.1\"\nlocal_port = {local_udp}\nremote_port = {pub_udp}\n");
    let (env, _) = boot_quic(&desired).await;
    // wait agent online via overview (poll 40x200ms)
    let mut ok = false;
    for _ in 0..40 {
        let cookie = login(&env.web_base).await;
        let client = reqwest::Client::new();
        let ov: serde_json::Value = client.get(format!("{}/api/overview", env.web_base)).header("cookie", cookie).send().await.unwrap().json().await.unwrap();
        if ov.to_string().contains("e2eq") { ok = true; break; }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "quic agent never came online");
    // http via tunnel
    let body = http_raw(&env, "q.test", "/").await;
    assert!(body.contains("quic-ok"), "{body}");
    // udp echo via public port
    let c = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.connect(format!("127.0.0.1:{pub_udp}")).await.unwrap();
    c.send(b"ping-quic").await.unwrap();
    let mut b = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), c.recv(&mut b)).await.expect("udp timeout").unwrap();
    assert_eq!(&b[..n], b"ping-quic");
}

#[tokio::test]
async fn quic_bad_token_closes() {
    let ws_port = free_port(); let quic_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-qbad-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let cfg_path = dir.join("agent.toml");
    tokio::fs::write(&cfg_path, "hostname = \"badq\"\ntoken = \"wrong\"\n").await.unwrap();
    let data = dir.join("data"); tokio::fs::create_dir_all(&data).await.unwrap();
    let desired_path = dir.join("desired.toml");
    tokio::fs::write(&desired_path, "").await.unwrap();
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let mut srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio()).stderr(e2e_stdio())
        .args(["server", "--listen", &format!("127.0.0.1:{ws_port}"),
            "--quic-listen", &format!("127.0.0.1:{quic_port}"),
            "--data", data.to_str().unwrap(), "--desired", desired_path.to_str().unwrap(),
            "--token", "s3cret"])
        .kill_on_drop(true).spawn().unwrap();
    wait_for(&format!("127.0.0.1:{ws_port}")).await;
    let mut ag = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio()).stderr(e2e_stdio())
        .args(["agent", "--server", &format!("quic://127.0.0.1:{quic_port}"),
            "--config", cfg_path.to_str().unwrap()])
        .kill_on_drop(true).spawn().unwrap();
    // agent 应反复重连但 server 主监听不倒：overview 仍 200 且无该 agent
    tokio::time::sleep(Duration::from_secs(3)).await;
    let cookie = login(&env_web(&ws_port)).await;
    let client = reqwest::Client::new();
    let st = client.get(format!("{}/api/overview", env_web(&ws_port))).header("cookie", cookie).send().await.unwrap().status();
    assert_eq!(st, 200);
    let _ = ag.kill().await; let _ = srv.kill().await;
}
```

Note: `env_web(port)` is a 3-line helper `format!("http://127.0.0.1:{port}")` to add alongside `boot_quic` (keeps bad-token test independent of `Env`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test e2e quic_ 2>&1 | tail -8`
Expected: FAIL (no `--quic-listen` flag / `quic://` rejected) — red is "behavior missing".

- [ ] **Step 3: Write minimal implementation**

No new src code (Tasks 1–4 already did it); this task only adds the e2e file content above + docs:
- `README.md` 功能对照表加一行: `| quic | server --quic-listen UDP 端口 + agent --server quic://host:port（自签证书，token 认证），控制帧 [u32 len][JSON]，隧道每流一条 QUIC stream |`
- `docs/architecture.md` 控制帧段落加 QUIC 映射说明（3 行）。

- [ ] **Step 4: Run test to verify it passes**

Run: `make build 2>&1 | tail -3` then `make test 2>&1 | tail -5`
Expected: all green (existing 30+16 plus 2 new QUIC e2e).

- [ ] **Step 5: Commit**

```bash
git add tests/e2e.rs README.md docs/architecture.md
git commit -m "test(quic): e2e http+udp+hot-config and bad token"
```

## Self-Review

1. **Spec coverage:** §2 监听形态→Task 2; §3 帧映射→Task 1+3; §4 会话语义→Task 3+4; §5 CLI→Task 2+4; §6 测试→Task 1–5 each with tests. No gaps.
2. **Placeholder scan:** no TBD/TODO; all steps have exact code/commands.
3. **Type consistency:** `Transport::Quic{host: String, port: u16}`, `encode_frame/decode_frames`, `encode_dgram/decode_dgram`, `check_token/make_self_signed/cert_fingerprint`, `run_quic(s, token, bind)`, `quic_session::session(up, cfg, status, egress_out)` used identically across tasks.
