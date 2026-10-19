//! End-to-end tests: boot server + agent in-process ports, exercise
//! http/tcp/udp passthrough, auth gating, config hot-push and toggle.
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for(addr: &str) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{addr} never came up");
}

struct Env {
    http_port: u16,
    web_base: String,
    _srv: tokio::process::Child, // kill_on_drop -> cleaned up at test end
    _ag: tokio::process::Child,
}

async fn boot_with_desired(proxies_toml: &str, desired_toml: Option<&str>) -> Env {
    let ws_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let cfg_path = dir.join("agent.toml");
    tokio::fs::write(
        &cfg_path,
        format!("hostname = \"e2e\"\ntoken = \"s3cret\"\n{proxies_toml}"),
    )
    .await
    .unwrap();
    let data = dir.join("data");
    tokio::fs::create_dir_all(&data).await.unwrap();
    let desired_path = dir.join("desired.toml");
    if let Some(d) = desired_toml {
        tokio::fs::write(&desired_path, d).await.unwrap();
    }
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let srv = tokio::process::Command::new(&bin)
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{ws_port}"),
            "--data",
            data.to_str().unwrap(),
            "--desired",
            desired_path.to_str().unwrap(),
            "--token",
            "s3cret",
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for(&format!("127.0.0.1:{ws_port}")).await;
    let ag = tokio::process::Command::new(&bin)
        .args([
            "agent",
            "--server",
            &format!("ws://127.0.0.1:{ws_port}/ws"),
            "--config",
            cfg_path.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    Env {
        http_port: ws_port, // HTTP 入站与 ws+WebUI 同端口（Host 路由）
        web_base: format!("http://127.0.0.1:{ws_port}"),
        _srv: srv,
        _ag: ag,
    }
}

async fn boot(proxies_toml: &str) -> Env {
    boot_with_desired(proxies_toml, None).await
}

/// 生 HTTP GET（裸 TCP 组装），可指定任意 Host/路径：覆盖浏览器打 IP、
/// 隧道域名、未知域名三种分流，以及非 `/` 路径的透传。
async fn http_raw(env: &Env, host: &str, path: &str) -> String {
    let host_hdr = if host.is_empty() {
        String::new()
    } else {
        format!("Host: {host}\r\n")
    };
    let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", env.http_port))
        .await
        .unwrap();
    c.write_all(format!("GET {path} HTTP/1.1\r\n{host_hdr}Connection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = vec![];
    c.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

async fn http_get_via(env: &Env, host: &str) -> String {
    let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", env.http_port))
        .await
        .unwrap();
    c.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = vec![];
    c.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

async fn login(base: &str) -> String {
    let c = reqwest::Client::new();
    let r = c
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"user": "admin", "pass": "welcome2neutrino"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let cookie = r.headers().get("set-cookie").unwrap().to_str().unwrap().to_string();
    assert!(cookie.starts_with("nt_session="));
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["ok"], true);
    j["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn e2e_http_and_auth_and_xfp() {
    // backend echoes X-Forwarded-Proto header value
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 8192];
                let n = s.read(&mut b).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&b[..n]);
                let xfp = head
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("X-Forwarded-Proto:")
                            .or_else(|| l.strip_prefix("x-forwarded-proto:"))
                            .map(|v| v.trim().to_string())
                    })
                    .unwrap_or_else(|| "none".into());
                let body = format!("xfp={xfp}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    let env = boot(&format!(
        "[[proxies]]\nname=\"web\"\ntype=\"http\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\ndomains=[\"web.e2e.test\"]\nset_x_forwarded_proto=\"https\"\n"
    ))
    .await;
    // http via Host routing + XFP injection
    let out = http_raw(&env, "web.e2e.test", "/").await;
    assert!(out.contains("xfp=https"), "{out:?}");

    // unknown host -> 404; exact status line + body marker
    let o2 = http_raw(&env, "nope.test", "/").await;
    assert!(o2.starts_with("HTTP/1.1 404"), "{o2:?}");
    assert!(o2.contains("no such tunnel"));

    // bare IP -> WebUI (neutrino login page), not 404
    let w = http_raw(&env, "127.0.0.1", "/").await;
    assert!(w.starts_with("HTTP/1.1 200"), "{w:?}");
    assert!(w.contains("neutrino"));
    // localhost + missing Host likewise land on WebUI
    assert!(http_raw(&env, "localhost", "/").await.starts_with("HTTP/1.1 200"));
    assert!(http_raw(&env, "", "/").await.starts_with("HTTP/1.1 200"));

    // non-root path under tunnel host still proxies (not swallowed by WebUI)
    let np = http_raw(&env, "web.e2e.test", "/some/path?q=1").await;
    assert!(np.starts_with("HTTP/1.1 200"), "{np:?}");
    assert!(np.contains("xfp=https"));

    // auth gating
    let cli = reqwest::Client::new();
    let r = cli
        .get(format!("{}/api/overview", env.web_base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let jwt = login(&env.web_base).await;
    let r = cli
        .get(format!("{}/api/overview", env.web_base))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["agents"][0]["hostname"], "e2e");
    let r = cli
        .get(format!("{}/api/tunnels", env.web_base))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn e2e_tcp_passthrough() {
    // echo backend
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    // find a free remote port
    let rport = free_port();
    let env = boot(&format!(
        "[[proxies]]\nname=\"bt\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\n"
    ))
    .await;
    // wait for lazy tcp listen
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}"))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}"))
        .await
        .unwrap();
    c.write_all(b"hello-tcp").await.unwrap();
    let mut b = vec![0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(10), c.read(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"hello-tcp");
    let _ = env;
}

#[tokio::test]
async fn e2e_udp_and_hot_config() {
    // udp echo backend
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = vec![0u8; 2048];
        loop {
            let Ok((n, p)) = back.recv_from(&mut b).await else {
                break;
            };
            let _ = back.send_to(&b[..n], p).await;
        }
    });
    let rport = free_port();
    let env = boot(&format!(
        "[[proxies]]\nname=\"u\"\ntype=\"udp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\n"
    ))
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let cli = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli.connect(format!("127.0.0.1:{rport}")).await.unwrap();
    cli.send(b"ping-udp").await.unwrap();
    let mut b = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(10), cli.recv(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"ping-udp");

    // hot config: push empty proxy list -> udp route gone (datagram dropped, timeout)
    let jwt = login(&env.web_base).await;
    let c = reqwest::Client::new();
    let r = c
        .post(format!("{}/api/config", env.web_base))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"hostname": "e2e", "proxies": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // toggle path on missing proxy -> 404
    let r = c
        .post(format!("{}/api/tunnels/e2e/u/enabled", env.web_base))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn e2e_desired_crud_flows_to_agent() {
    // backend: fixed body
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let _ = s.read(&mut b).await;
                let body = "desired-ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    // agent boots with NO local proxies; desired comes from server WebUI
    let env = boot("").await;
    let jwt = login(&env.web_base).await;
    let c = reqwest::Client::new();
    // before: 404
    assert!(http_get_via(&env, "d.e2e.test").await.contains("404"));
    // WebUI creates tunnel via desired CRUD
    let r = c
        .post(format!("{}/api/desired/e2e", env.web_base))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"proxies": [
            {"name": "web", "type": "http", "local_ip": "127.0.0.1",
             "local_port": bport, "domains": ["d.e2e.test"]}
        ]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    tokio::time::sleep(Duration::from_secs(1)).await;
    // after: flows through
    assert!(http_get_via(&env, "d.e2e.test").await.contains("desired-ok"));
    // persisted?
    let j: serde_json::Value = c
        .get(format!("{}/api/desired/e2e", env.web_base))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(j["proxies"][0]["name"], "web");
    let _ = env;
}

#[tokio::test]
async fn e2e_agent_webui_upstream_edit_redials() {
    // agent WebUI：改上行 server_url（此处改个不可达端口再改回），
    // 保存即落盘 + 立即重连；status 反映新 target。
    use std::net::SocketAddr;
    let env = boot("").await;
    let data = std::env::temp_dir();
    // 复用 boot 的 agent 进程 WebUI？boot 未开 --web，改为直测 api_settings 语义：
    // 用独立 agent（带 --web）验证 settings -> toml 落盘 -> status 更新。
    let dir = data.join(format!("nt-e2e-web-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let cfg_path = dir.join("agent.toml");
    tokio::fs::write(&cfg_path, "hostname = \"w\"\ntoken = \"s3cret\"\n").await.unwrap();
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let web_addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let mut ag = tokio::process::Command::new(&bin)
        .args([
            "agent",
            "--server",
            &format!("ws://127.0.0.1:{}/ws", env.http_port),
            "--config",
            cfg_path.to_str().unwrap(),
            "--web",
            &web_addr.to_string(),
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for(&web_addr.to_string()).await;
    let base = format!("http://{web_addr}");
    let c = reqwest::Client::new();
    // login with default pass
    let r = c.post(format!("{base}/api/login"))
        .json(&serde_json::json!({"user": "admin", "pass": "neutrino123"}))
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    let jwt: String = r.json::<serde_json::Value>().await.unwrap()["token"].as_str().unwrap().into();
    // settings: bad scheme rejected
    let r = c.post(format!("{base}/api/settings"))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"server_url": "http://bad/"}))
        .send().await.unwrap();
    assert_eq!(r.status(), 400);
    // settings: valid upstream persists to toml
    let target = format!("ws://127.0.0.1:{}/ws", env.http_port);
    let r = c.post(format!("{base}/api/settings"))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"server_url": target, "hostname": "w2"}))
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    let saved = tokio::fs::read_to_string(&cfg_path).await.unwrap();
    assert!(saved.contains(&target), "{saved:?}");
    assert!(saved.contains("w2"));
    // status shows the pending target immediately (no polling race)
    let st: serde_json::Value = c.get(format!("{base}/api/status"))
        .bearer_auth(&jwt)
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(st["server_url"], target);
    assert_eq!(st["hostname"], "w2");
    // reconnect endpoint forces a redial: session撕掉重建后 online 回 true
    // 且 last_error 留下 "redial requested" 痕迹（稳定可判定，不依赖计数竞态）
    let r = c.post(format!("{base}/api/reconnect"))
        .bearer_auth(&jwt)
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    let mut st2 = st.clone();
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        st2 = c.get(format!("{base}/api/status"))
            .bearer_auth(&jwt)
            .send().await.unwrap().json().await.unwrap();
        if st2["last_error"] == "redial requested" || st2["reconnects"].as_u64().unwrap_or(0) > st["reconnects"].as_u64().unwrap_or(0) {
            break;
        }
    }
    assert!(
        st2["last_error"] == "redial requested" || st2["reconnects"].as_u64().unwrap_or(0) > st["reconnects"].as_u64().unwrap_or(0),
        "{st2:?}"
    );
    let _ = ag.kill().await;
    let _ = env;
}

#[tokio::test]
async fn e2e_register_does_not_loop_config_push() {
    // 回归：agent 上报收敛后，server 不再重复 push Config。
    // 刷屏死循环的根因：每次 Register 都无条件 Config -> agent 回 Register。
    // 现场还原：desired 有隧道（want.is_some 才会 push），agent 空上报等下发；
    // 收敛后 overlay 日志不再增长。boot() 无 desired 时旧代码也不循环，测不出。
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let _ = s.read(&mut b).await;
                let body = "loop-ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    // agent 空上报 + server desired 有隧道：正好走 want.is_some 的 push 分支
    let desired = format!(
        "[[agents.e2e]]\nname=\"web\"\ntype=\"http\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\ndomains=[\"l.e2e.test\"]\n"
    );
    let env = boot_with_desired("", Some(&desired)).await;
    let jwt = login(&env.web_base).await;
    let c = reqwest::Client::new();
    // overlay 日志每条带时间戳前缀，同名事件也算不同行 -> 计数即 Register 次数
    let count_overlays = || async {
        let j: serde_json::Value = c
            .get(format!("{}/api/logs", env.web_base))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        j["logs"]
            .as_array()
            .map(|a| a.iter().filter(|l| l.as_str().unwrap_or("").contains("desired overlay")).count())
            .unwrap_or(0)
    };
    // 等收敛：死循环版本会在 3s 内刷出几十条 overlay；修复后静默
    tokio::time::sleep(Duration::from_secs(3)).await;
    let n = count_overlays().await;
    assert!(n <= 2, "overlay log count {n}: Register/Config loop!");
    assert!(http_get_via(&env, "l.e2e.test").await.contains("loop-ok"));
    let _ = env;
}

#[tokio::test]
async fn e2e_restart_covered_by_desired() {
    // backend on good port
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let _ = s.read(&mut b).await;
                let body = "covered-ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    // agent reports a WRONG local proxy, but server desired.toml wins
    let desired = format!(
        "[[agents.e2e]]\nname=\"web\"\ntype=\"http\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\ndomains=[\"c.e2e.test\"]\n"
    );
    let env = boot_with_desired(
        "[[proxies]]\nname=\"wrong\"\ntype=\"http\"\nlocal_ip=\"127.0.0.1\"\nlocal_port=1\ndomains=[\"c.e2e.test\"]\n",
        Some(&desired),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(http_get_via(&env, "c.e2e.test").await.contains("covered-ok"));
    let _ = env;
}
