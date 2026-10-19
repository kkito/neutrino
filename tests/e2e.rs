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
    let http_port = free_port();
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
            "--http-in",
            &format!("127.0.0.1:{http_port}"),
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
        http_port,
        web_base: format!("http://127.0.0.1:{ws_port}"),
        _srv: srv,
        _ag: ag,
    }
}

async fn boot(proxies_toml: &str) -> Env {
    boot_with_desired(proxies_toml, None).await
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
        .json(&serde_json::json!({"user": "admin", "pass": "welcome2ll"}))
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
    let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", env.http_port))
        .await
        .unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: web.e2e.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = vec![];
    c.read_to_end(&mut out).await.unwrap();
    assert!(String::from_utf8_lossy(&out).contains("xfp=https"), "{out:?}");

    // unknown host -> 404
    let mut c2 = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", env.http_port))
        .await
        .unwrap();
    c2.write_all(b"GET / HTTP/1.1\r\nHost: nope.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut o2 = vec![];
    c2.read_to_end(&mut o2).await.unwrap();
    assert!(String::from_utf8_lossy(&o2).contains("404"));

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
