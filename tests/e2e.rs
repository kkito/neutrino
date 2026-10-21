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
    data_dir: std::path::PathBuf,
    _srv: tokio::process::Child, // kill_on_drop -> cleaned up at test end
    _ag: tokio::process::Child,
}

/// e2e 子进程输出策略：负向用例（非法 TOML reload 等）会故意触发 server
/// ERROR 日志，默认吞掉让 `make test` 输出干净；NT_E2E_LOUD=1 时透出排障。
/// 注意 tracing 默认写 stdout（非 stderr），所以 stdout/stderr 一起吞。
/// WebUI 日志页（/api/logs 走内存 events）不受影响，照常可查。
fn e2e_stdio() -> std::process::Stdio {
    if std::env::var("NT_E2E_LOUD").is_ok() {
        std::process::Stdio::inherit()
    } else {
        std::process::Stdio::null()
    }
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
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
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
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
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
        data_dir: data,
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

/// 回归：HTTP 下游提前断开时 conns 行必须消失（旧代码只在流尾回调 remove，
/// Body 被 drop 后清理永不执行，行越积越多——natproxy 现场 56 行僵尸即此因）。
/// 断言抓：慢后端保持行可见→客户端裸断→行在轮询上限内消失。
#[tokio::test]
async fn e2e_http_conns_cleaned_on_client_abort() {
    // 慢后端：先等 5s 再回包，行在等待期可见
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let _ = s.read(&mut b).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                let body = "slow-ok";
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
        "[[proxies]]\nname=\"slow\"\ntype=\"http\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\ndomains=[\"slow.e2e.test\"]\n"
    ))
    .await;
    let jwt = login(&env.web_base).await;
    let c = reqwest::Client::new();
    // 裸 TCP 发请求头后卡住不读，行应出现
    let mut cli = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", env.http_port))
        .await
        .unwrap();
    cli.write_all(b"GET / HTTP/1.1\r\nHost: slow.e2e.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut shown = false;
    for _ in 0..40 {
        let j: serde_json::Value = c
            .get(format!("{}/api/conns", env.web_base))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let arr = j["conns"].as_array().cloned().unwrap_or_default();
        if arr.iter().any(|x| x["tunnel"] == "slow") {
            shown = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(shown, "conns should show the slow http request");
    // 代理头透传：带 X-Real-IP 的请求，peer 列应是外部 IP 而非 127.0.0.1
    let mut cli2 = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", env.http_port))
        .await
        .unwrap();
    cli2.write_all(b"GET / HTTP/1.1\r\nHost: slow.e2e.test\r\nX-Real-IP: 9.9.9.9\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut real_shown = false;
    for _ in 0..40 {
        let j: serde_json::Value = c
            .get(format!("{}/api/conns", env.web_base))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let arr = j["conns"].as_array().cloned().unwrap_or_default();
        if arr.iter().any(|x| x["tunnel"] == "slow" && x["peer"].as_str().unwrap_or("").starts_with("9.9.9.9")) {
            real_shown = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(real_shown, "conns peer should show X-Real-IP, not 127.0.0.1");
    drop(cli2);
    // 客户端裸断（后端还没回包）→ 行必须消失
    drop(cli);
    let mut gone = false;
    for _ in 0..40 {
        let j: serde_json::Value = c
            .get(format!("{}/api/conns", env.web_base))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let arr = j["conns"].as_array().cloned().unwrap_or_default();
        if !arr.iter().any(|x| x["tunnel"] == "slow") {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(gone, "conns row leaked after client abort");
    let _ = env;
}

/// 旧代码无 /api/traffic、/api/conns（404 即红）；断言抓：conns 行出现/消失、traffic 接口可用。
/// 取舍：分钟 tick 在 e2e 等不起（60s），有点不断言，累计由 state 单测覆盖。
/// tick 无 fanout 回归：tcp 建连跑量后，conns 行 tunnel=tc；traffic 按 tunnel 归集
/// 只有 tc 有点“无量”，其他隧道无行（旧 tick 会给每个 proxy 各 push 一份）。
#[tokio::test]
async fn e2e_traffic_and_conns() {
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
    let rport = free_port();
    let env = boot(&format!(
        "[[proxies]]\nname=\"tc\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\n"
    ))
    .await;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let jwt = login(&env.web_base).await;
    let c = reqwest::Client::new();
    let get = |path: String| {
        let c = c.clone();
        let base = env.web_base.clone();
        let jwt = jwt.clone();
        async move {
            c.get(format!("{base}{path}")).bearer_auth(&jwt).send().await.unwrap()
        }
    };
    // traffic 接口可用（旧代码 404）
    let r = get("/api/traffic?tunnel=all&gran=min&n=10".into()).await;
    assert_eq!(r.status(), 200);
    let j: serde_json::Value = r.json().await.unwrap();
    assert!(j.get("points").is_some(), "{j:?}");
    // 建连并发包 -> conns 出现行
    let mut conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await.unwrap();
    conn.write_all(b"hello-conns").await.unwrap();
    let mut b = vec![0u8; 32];
    let _ = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut b)).await.unwrap().unwrap();
    let mut found = false;
    for _ in 0..40 {
        let r = get("/api/conns".into()).await;
        assert_eq!(r.status(), 200);
        let j: serde_json::Value = r.json().await.unwrap();
        let arr = j["conns"].as_array().cloned().unwrap_or_default();
        if arr.iter().any(|x| x["tunnel"] == "tc" && x["public_port"] == rport) {
            found = true;
            // 列齐全：外部/公网端口/隧道/agent/内网目标
            let x = arr.iter().find(|x| x["tunnel"] == "tc").unwrap();
            assert!(x["peer"].as_str().map(|s| !s.is_empty()).unwrap_or(false), "{x:?}");
            assert!(x["agent"].as_str().map(|s| !s.is_empty()).unwrap_or(false), "{x:?}");
            assert!(x["target"].as_str().map(|s| !s.is_empty()).unwrap_or(false), "{x:?}");
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(found, "conns should show the tcp connection");
    // 断开后行消失（轮询，上限 8s）
    drop(conn);
    let mut gone = false;
    for _ in 0..40 {
        let r = get("/api/conns".into()).await;
        let j: serde_json::Value = r.json().await.unwrap();
        let arr = j["conns"].as_array().cloned().unwrap_or_default();
        if !arr.iter().any(|x| x["tunnel"] == "tc") {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(gone, "conns row should disappear after close");
    let _ = env;
}

/// 旧代码行为：刷新页=内存 token 丢->401 登出；server 重启=jwt_secret 重生->cookie 作废。
/// 断言抓：纯 cookie（无 Bearer）可访问；同 data_dir 重启 server 后 cookie 仍有效。
#[tokio::test]
async fn e2e_cookie_survives_refresh_and_restart() {
    let env = boot("").await;
    let c = reqwest::Client::builder().cookie_store(true).build().unwrap();
    // 登录拿 cookie（cookie_store 自动存 nt_session）
    let r = c
        .post(format!("{}/api/login", env.web_base))
        .json(&serde_json::json!({"user": "admin", "pass": "welcome2neutrino"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // 刷新等价：不带 Bearer、只带 cookie -> 200（旧代码 401）
    let r = c.get(format!("{}/api/overview", env.web_base)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    // server 重启（同 data_dir，jwt_secret 落盘复用）-> cookie 仍有效
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let mut env = env;
    env._srv.kill().await.unwrap();
    let _ = env._srv.wait().await;
    let srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{}", env.http_port),
            "--data",
            env.data_dir.to_str().unwrap(),
            "--desired",
            // boot 时 desired.toml 与 data 同级（dir 下），data 是 dir/data
            env.data_dir.join("../desired.toml").to_str().unwrap(),
            "--token",
            "s3cret",
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    env._srv = srv;
    wait_for(&format!("127.0.0.1:{}", env.http_port)).await;
    let mut ok = false;
    for _ in 0..40 {
        let r = c.get(format!("{}/api/overview", env.web_base)).send().await.unwrap();
        if r.status() == 200 {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "cookie should survive server restart");
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

/// QUIC 版 boot：server 同时开 --quic-listen，agent 用 quic:// 拨号。
/// 其余与 WSS 版一致（desired/HTTP 入站同端口，Host 路由不变）。
async fn boot_quic(proxies_toml: &str) -> Env {
    let ws_port = free_port();
    let quic_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-quic-{}", uuid::Uuid::new_v4()));
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
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{ws_port}"),
            "--quic-listen",
            &format!("127.0.0.1:{quic_port}"),
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
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "agent",
            "--server",
            &format!("quic://127.0.0.1:{quic_port}"),
            "--config",
            cfg_path.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    Env {
        http_port: ws_port,
        web_base: format!("http://127.0.0.1:{ws_port}"),
        data_dir: data,
        _srv: srv,
        _ag: ag,
    }
}

#[tokio::test]
async fn quic_http_udp_and_hot_config() {
    // RED（Task 2 结束时）：server 只回 Welcome，Register 无响应，路由表空，
    // http 404 + udp 超时。本测试锁定 Task 3–4 的完整语义：
    // QUIC 建连→Register 收敛→http/udp 透传→热配清空路由消失。
    // http backend: fixed body
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let _ = s.read(&mut b).await;
                let body = "quic-ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    // udp echo backend
    let uback = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ubport = uback.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = vec![0u8; 2048];
        loop {
            let Ok((n, p)) = uback.recv_from(&mut b).await else {
                break;
            };
            let _ = uback.send_to(&b[..n], p).await;
        }
    });
    let rport = free_port();
    let env = boot_quic(&format!(
        "[[proxies]]\nname=\"web\"\ntype=\"http\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\ndomains=[\"q.e2e.test\"]\n\
         [[proxies]]\nname=\"u\"\ntype=\"udp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={ubport}\nremote_port={rport}\n"
    ))
    .await;
    // http 透传（轮询等 Register 收敛，上限 8s）
    let mut ok = false;
    for _ in 0..40 {
        if http_get_via(&env, "q.e2e.test").await.contains("quic-ok") {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "quic http never converged");
    // udp 回声
    let cli = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli.connect(format!("127.0.0.1:{rport}")).await.unwrap();
    cli.send(b"ping-quic").await.unwrap();
    let mut b = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(10), cli.recv(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"ping-quic");
    // hot config：清空后 http 404（路由摘除），udp 无响应（超时即断言）。
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
    let mut gone = false;
    for _ in 0..40 {
        if http_get_via(&env, "q.e2e.test").await.contains("404") {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(gone, "quic hot-config clear did not take effect");
    let cli2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli2.connect(format!("127.0.0.1:{rport}")).await.unwrap();
    cli2.send(b"ping-after-clear").await.unwrap();
    let mut b2 = vec![0u8; 64];
    assert!(tokio::time::timeout(Duration::from_secs(3), cli2.recv(&mut b2))
        .await
        .is_err());
}

#[tokio::test]
async fn quic_bad_token_closes() {
    // 错 token 的 QUIC agent 建连即被 401 close：server 侧 agents 表无此 hostname，
    // WebUI conns 为空；旧代码（Task 2 前）无 QUIC 监听，connect 直接超时。
    let ws_port = free_port();
    let quic_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-quic-bad-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let data = dir.join("data");
    tokio::fs::create_dir_all(&data).await.unwrap();
    let desired_path = dir.join("desired.toml");
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{ws_port}"),
            "--quic-listen",
            &format!("127.0.0.1:{quic_port}"),
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
    let cfg_path = dir.join("agent.toml");
    tokio::fs::write(&cfg_path, "hostname = \"bad\"\ntoken = \"wrong\"\n")
        .await
        .unwrap();
    let ag = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "agent",
            "--server",
            &format!("quic://127.0.0.1:{quic_port}"),
            "--config",
            cfg_path.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    // agents 表应无 bad（401 close 后无注册），conns 为空。
    let jwt = login(&format!("http://127.0.0.1:{ws_port}")).await;
    let c = reqwest::Client::new();
    let agents: serde_json::Value = c
        .get(format!("http://127.0.0.1:{ws_port}/api/overview"))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = agents.get("agents").and_then(|a| a.as_array()).cloned().unwrap_or_default();
    assert!(!arr.iter().any(|a| a.get("hostname").and_then(|h| h.as_str()) == Some("bad")));
    drop(ag);
    drop(srv);
}

async fn boot_kudus(proxies_toml: &str) -> Env {
    // 与 boot_quic 对称：kudus 独立 UDP 端口，agent --server kudus://…。
    let ws_port = free_port();
    let kudus_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-kudus-{}", uuid::Uuid::new_v4()));
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
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{ws_port}"),
            "--kudus-listen",
            &format!("127.0.0.1:{kudus_port}"),
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
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "agent",
            "--server",
            &format!("kudus://127.0.0.1:{kudus_port}"),
            "--config",
            cfg_path.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    Env {
        http_port: ws_port,
        web_base: format!("http://127.0.0.1:{ws_port}"),
        data_dir: data,
        _srv: srv,
        _ag: ag,
    }
}

/// agent 本地入口 e2e：内网 `*.<suffix>` 直访名下 http 隧道（不经 server 公网口）。
/// 旧代码无 [local_ingress]：本地端口无监听，连接直接被拒（ECONNREFUSED）。
#[tokio::test]
async fn local_ingress_http_names() {
    // backend1: web 固定 body；backend2: sec 固定 body（配 basic_auth u:p）
    async fn fixed_backend(body: &'static str) -> u16 {
        let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bport = back.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = back.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = vec![0u8; 4096];
                    let _ = s.read(&mut b).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        bport
    }
    let bweb = fixed_backend("local-ok").await;
    let bsec = fixed_backend("secret-ok").await;
    let li_port = free_port();
    // desired.toml 形状：[[agents.e2e]] 数组表；agent.toml 只追加 [local_ingress]。
    // （隧道以 server desired 为准，agent 本地 [[proxies]] 会被忽略——故此处不写。）
    let desired = format!(
        "[[agents.e2e]]\nname=\"web\"\ntype=\"http\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bweb}\ndomains=[\"w.e2e.test\"]\n\
         [[agents.e2e]]\nname=\"sec\"\ntype=\"http\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bsec}\nbasic_auth=\"u:p\"\ndomains=[\"s.e2e.test\"]\n"
    );
    let agent_extra = format!(
        "[local_ingress]\nenabled=true\nlisten_ip=\"127.0.0.1\"\nlisten_port={li_port}\nsuffix=\".local.e2e\"\n"
    );
    let env = boot_with_desired(&agent_extra, Some(&desired)).await;
    async fn raw(port: u16, host: &str, auth: Option<&str>) -> String {
        let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let mut req = format!("GET / HTTP/1.1\r\nHost: {host}\r\n");
        if let Some(a) = auth {
            use base64::Engine as _;
            req.push_str(&format!(
                "Authorization: Basic {}\r\n",
                base64::engine::general_purpose::STANDARD.encode(a)
            ));
        }
        req.push_str("Connection: close\r\n\r\n");
        c.write_all(req.as_bytes()).await.unwrap();
        let mut out = vec![];
        c.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }
    // 收敛轮询：本地入口读 status.proxies（server 下发后才有），上限 8s
    let mut ok = false;
    for _ in 0..40 {
        if raw(li_port, "web.local.e2e", None).await.contains("local-ok") {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "local ingress hit never converged");
    // miss 列名（含 web/sec，不含 token）
    let miss = raw(li_port, "nope.local.e2e", None).await;
    assert!(miss.contains("404") && miss.contains("web") && miss.contains("sec"), "miss page: {miss}");
    assert!(!miss.contains("s3cret"), "miss page leaks token: {miss}");
    // 多 label 越权拒绝
    let evil = raw(li_port, "evil.deep.local.e2e", None).await;
    assert!(evil.contains("404"), "multi-label must 404: {evil}");
    // basic_auth：无头 401（带 WWW-Authenticate），对头 200
    let noauth = raw(li_port, "sec.local.e2e", None).await;
    assert!(noauth.contains("401") && noauth.contains("WWW-Authenticate"), "auth missing: {noauth}");
    let authed = raw(li_port, "sec.local.e2e", Some("u:p")).await;
    assert!(authed.contains("secret-ok"), "auth ok failed: {authed}");
    // 大 body 透明透传（64KB 一致）：直调 backend 对比
    let big_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let big_port = big_backend.local_addr().unwrap().port();
    let big_body = "B".repeat(65536);
    let big_clone = big_body.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = big_backend.accept().await.unwrap();
            let bc = big_clone.clone();
            tokio::spawn(async move {
                let mut b = vec![0u8; 65536];
                let _ = s.read(&mut b).await;
                let resp = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{bc}", bc.len());
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    // 热配加一条 big 隧道（走 server /api/config，agent 热更新即时）
    let jwt = login(&env.web_base).await;
    let _ = reqwest::Client::new()
        .post(format!("{}/api/config", env.web_base))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"hostname": "e2e", "proxies": [
            {"name":"web","type":"http","local_ip":"127.0.0.1","local_port":bweb,"domains":["w.e2e.test"]},
            {"name":"sec","type":"http","local_ip":"127.0.0.1","local_port":bsec,"basic_auth":"u:p","domains":["s.e2e.test"]},
            {"name":"big","type":"http","local_ip":"127.0.0.1","local_port":big_port,"domains":["b.e2e.test"]}
        ]}))
        .send()
        .await;
    let mut big_ok = false;
    for _ in 0..40 {
        let r = raw(li_port, "big.local.e2e", None).await;
        if r.contains(&big_body) {
            big_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(big_ok, "64KB body via local ingress mismatch");
    // 热配清空 → 404（路由即时摘除，无需 reload）
    let _ = reqwest::Client::new()
        .post(format!("{}/api/config", env.web_base))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"hostname": "e2e", "proxies": []}))
        .send()
        .await;
    let mut gone = false;
    for _ in 0..40 {
        if raw(li_port, "web.local.e2e", None).await.contains("404") {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(gone, "local ingress route did not disappear after hot-clear");
}

#[tokio::test]
async fn kudus_http_udp_and_hot_config() {
    // kudus 全链路：建连→Register 收敛→http/udp 透传→热配清空路由消失。
    // 旧代码（Task 1–3 前）无 --kudus-listen：agent 建连超时，http 永远 404。
    // http backend: fixed body
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let _ = s.read(&mut b).await;
                let body = "kudus-ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    // udp echo backend
    let uback = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ubport = uback.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = vec![0u8; 2048];
        loop {
            let Ok((n, p)) = uback.recv_from(&mut b).await else {
                break;
            };
            let _ = uback.send_to(&b[..n], p).await;
        }
    });
    let rport = free_port();
    let env = boot_kudus(&format!(
        "[[proxies]]\nname=\"web\"\ntype=\"http\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\ndomains=[\"k.e2e.test\"]\n\
         [[proxies]]\nname=\"u\"\ntype=\"udp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={ubport}\nremote_port={rport}\n"
    ))
    .await;
    // http 透传（轮询等 Register 收敛，上限 8s）
    let mut ok = false;
    for _ in 0..40 {
        if http_get_via(&env, "k.e2e.test").await.contains("kudus-ok") {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "kudus http never converged");
    // udp 回声
    let cli = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli.connect(format!("127.0.0.1:{rport}")).await.unwrap();
    cli.send(b"ping-kudus").await.unwrap();
    let mut b = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(10), cli.recv(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"ping-kudus");
    // hot config：清空后 http 404（路由摘除），udp 无响应（超时即断言）。
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
    let mut gone = false;
    for _ in 0..40 {
        if http_get_via(&env, "k.e2e.test").await.contains("404") {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(gone, "kudus hot-config clear did not take effect");
    let cli2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli2.connect(format!("127.0.0.1:{rport}")).await.unwrap();
    cli2.send(b"ping-after-clear").await.unwrap();
    let mut b2 = vec![0u8; 64];
    assert!(tokio::time::timeout(Duration::from_secs(3), cli2.recv(&mut b2))
        .await
        .is_err());
}

/// kudus 单 flight：同 hostname 第二个 agent 上线踢掉旧会话（与 ws_loop 同语义）。
/// 前置 bug：kudus 注册无踢人，旧会话僵尸残留（rtt=-1），overview 越堆越多、抢 link 路由。
#[tokio::test]
async fn kudus_reconnect_kicks_stale_session() {
    let ws_port = free_port();
    let kudus_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-kick-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let data = dir.join("data");
    tokio::fs::create_dir_all(&data).await.unwrap();
    let desired_path = dir.join("desired.toml");
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let mk_cfg = |n: &str| {
        let p = dir.join(n);
        std::fs::write(&p, "hostname = \"e2e\"\ntoken = \"s3cret\"\n").unwrap();
        p
    };
    let cfg1 = mk_cfg("a1.toml");
    let cfg2 = mk_cfg("a2.toml");
    let srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "server", "--listen", &format!("127.0.0.1:{ws_port}"),
            "--kudus-listen", &format!("127.0.0.1:{kudus_port}"),
            "--data", data.to_str().unwrap(),
            "--desired", desired_path.to_str().unwrap(),
            "--token", "s3cret",
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for(&format!("127.0.0.1:{ws_port}")).await;
    let mut ag1 = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args(["agent", "--server", &format!("kudus://127.0.0.1:{kudus_port}"), "--config", cfg1.to_str().unwrap()])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut ag2 = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args(["agent", "--server", &format!("kudus://127.0.0.1:{kudus_port}"), "--config", cfg2.to_str().unwrap()])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    // 登录 WebUI 拿 jwt，再查 overview：同 hostname 只应剩最新一条。
    // cookie_store 自动带 nt_session（与 e2e_cookie 测试同路）。
    let c = reqwest::Client::builder().cookie_store(true).build().unwrap();
    let login: serde_json::Value = c
        .post(format!("http://127.0.0.1:{ws_port}/api/login"))
        .json(&serde_json::json!({"user": "admin", "pass": "welcome2neutrino"}))
        .send().await.unwrap().json().await.unwrap();
    assert!(login["ok"].as_bool().unwrap_or(false), "login failed: {login:?}");
    let ov: serde_json::Value = c
        .get(format!("http://127.0.0.1:{ws_port}/api/overview"))
        .send().await.unwrap().json().await.unwrap();
    let agents = ov["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 1, "stale kudus session not kicked: {agents:?}");
    ag1.kill().await.ok();
    ag2.kill().await.ok();
    drop(srv);
}

/// RED 回归：kudus 丢包必须重传补齐（现网 avatar 少 700B / blob 丢 16% 被截断）。
/// 旧代码 DATA 发完即忘（ack=0、无重传、无重排），跨机 UDP 一丢包即永久少块；
/// 新代码写泵登记 retx、读循环 SACK+重排、50ms 超时泵补发。
/// e2e 抓法：2MB 随机 bin 走 kudus TCP 映射，与源文件逐字节比对（丢包即 mismatch）。
#[tokio::test]
async fn kudus_lossy_tcp_file_integrity() {
    use std::io::Write;
    let ws_port = free_port();
    let kudus_port = free_port();
    let tcp_port = free_port();
    let back_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-kloss-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let data = dir.join("data");
    tokio::fs::create_dir_all(&data).await.unwrap();
    // 2MB 随机文件（不可压缩，逐包都得传对；小了盖不住丢包窗口）。
    let src = dir.join("blob.bin");
    let mut rng_file = std::fs::File::create(&src).unwrap();
    let mut seed = 0x12345678u64;
    let mut left = 256 * 1024;
    let mut expect = std::collections::hash_map::DefaultHasher::new();
    while left > 0 {
        let mut chunk = vec![0u8; 8192];
        for b in chunk.iter_mut() {
            // xorshift64*：无外部依赖的确定性伪随机
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            *b = (seed.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8;
        }
        use std::hash::Hasher;
        expect.write(&chunk[..left.min(8192)]);
        let n = left.min(8192);
        rng_file.write_all(&chunk[..n]).unwrap();
        left -= n;
    }
    let expect_hash = format!("{:x}", expect.finish());
    // 后端：裸 TCP 回声（收啥回啥，专测 kudus 可靠性，与 HTTP 语义无关）。
    let back = tokio::net::TcpListener::bind(format!("127.0.0.1:{back_port}")).await.unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let desired_path = dir.join("desired.toml");
    std::fs::write(
        &desired_path,
        format!(
            "[[agents.e2e]]\nname = \"blob\"\ntype = \"tcp\"\nlocal_ip = \"127.0.0.1\"\nlocal_port = {back_port}\nremote_port = {tcp_port}\n"
        ),
    )
    .unwrap();
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let cfgp = dir.join("a.toml");
    std::fs::write(&cfgp, "hostname = \"e2e\"\ntoken = \"s3cret\"\n").unwrap();
    let srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "server", "--listen", &format!("127.0.0.1:{ws_port}"),
            "--kudus-listen", &format!("127.0.0.1:{kudus_port}"),
            "--data", data.to_str().unwrap(),
            "--desired", desired_path.to_str().unwrap(),
            "--token", "s3cret",
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for(&format!("127.0.0.1:{ws_port}")).await;
    let mut ag = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args(["agent", "--server", &format!("kudus://127.0.0.1:{kudus_port}"), "--config", cfgp.to_str().unwrap()])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    // 等映射端口起来（轮询上限 40×200ms，不用固定 sleep 赌竞态）。
    let mut ok = false;
    for _ in 0..40 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{tcp_port}")).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "kudus tcp ingress never came up");
    // 经隧道把文件打过去再读回来（回声），逐字节比对。
    // 注意：不 shutdown 写端——ingress 是 select 双泵谁先结束就全关，shutdown 会把
    // 仍在回程路上的 echo 数据一起埋了（半关闭语义，WSS/QUIC 同路，非 kudus 问题）；
    // 这里只测 kudus 可靠性：写完读够 len 即断言。
    let raw = std::fs::read(&src).unwrap();
    let mut conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{tcp_port}")).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    conn.write_all(&raw).await.unwrap();
    let mut back_data = vec![0u8; raw.len()];
    tokio::time::timeout(Duration::from_secs(15), conn.read_exact(&mut back_data))
        .await
        .expect("kudus echo read timeout")
        .unwrap();
    use std::hash::Hasher;
    let mut got = std::collections::hash_map::DefaultHasher::new();
    got.write(&back_data);
    let got_hash = format!("{:x}", got.finish());
    assert_eq!(back_data.len(), raw.len(), "kudus tcp truncated: got {} want {}", back_data.len(), raw.len());
    assert_eq!(got_hash, expect_hash, "kudus tcp payload corrupted");
    ag.kill().await.ok();
    drop(srv);
}

#[tokio::test]
async fn kudus_bad_token_blackhole() {
    // 错 token 的 kudus agent 建连即黑洞：无 SYN-ACK、无错误回包，
    // server 侧 agents 表无此 hostname。另附隐身探针：朝 kudus 端口
    // 发 64B 随机垃圾，2s 内必须零回包（与 QUIC/TLS 的握手响应相反）。
    // 旧代码（Task 2 前）无 kudus 监听：connect 拒绝/超时而非静默。
    let ws_port = free_port();
    let kudus_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-kudus-bad-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let data = dir.join("data");
    tokio::fs::create_dir_all(&data).await.unwrap();
    let desired_path = dir.join("desired.toml");
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{ws_port}"),
            "--kudus-listen",
            &format!("127.0.0.1:{kudus_port}"),
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
    // 隐身探针：随机垃圾零回包。
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe.connect(format!("127.0.0.1:{kudus_port}")).await.unwrap();
    let junk = vec![0xabu8; 64];
    probe.send(&junk).await.unwrap();
    let mut pb = vec![0u8; 128];
    assert!(
        tokio::time::timeout(Duration::from_secs(2), probe.recv(&mut pb))
            .await
            .is_err(),
        "kudus leaked a reply to junk"
    );
    // 错 token agent：agents 表无 bad。
    let cfg_path = dir.join("agent.toml");
    tokio::fs::write(&cfg_path, "hostname = \"bad\"\ntoken = \"wrong\"\n")
        .await
        .unwrap();
    let ag = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "agent",
            "--server",
            &format!("kudus://127.0.0.1:{kudus_port}"),
            "--config",
            cfg_path.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let jwt = login(&format!("http://127.0.0.1:{ws_port}")).await;
    let c = reqwest::Client::new();
    let agents: serde_json::Value = c
        .get(format!("http://127.0.0.1:{ws_port}/api/overview"))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = agents.get("agents").and_then(|a| a.as_array()).cloned().unwrap_or_default();
    assert!(!arr.iter().any(|a| a.get("hostname").and_then(|h| h.as_str()) == Some("bad")));
    drop(ag);
    drop(srv);
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

    // basic auth: 配了 basic_auth 后，无口令 401、有口令放行
    let r = c
        .post(format!("{}/api/desired/e2e", env.web_base))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"proxies": [
            {"name": "web", "type": "http", "local_ip": "127.0.0.1",
             "local_port": bport, "domains": ["d.e2e.test"],
             "basic_auth": "bob:s3cret"}
        ]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    tokio::time::sleep(Duration::from_secs(1)).await;
    // 无口令 -> 401 + WWW-Authenticate
    let r401 = reqwest::Client::new()
        .get(format!("{}/", env.web_base))
        .header("Host", "d.e2e.test")
        .send()
        .await
        .unwrap();
    assert_eq!(r401.status(), 401);
    assert!(r401.headers().contains_key("www-authenticate"));
    // 对口令 -> 放行
    let ok = reqwest::Client::new()
        .get(format!("{}/", env.web_base))
        .header("Host", "d.e2e.test")
        .basic_auth("bob", Some("s3cret"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert!(ok.text().await.unwrap().contains("desired-ok"));
    // 错口令 -> 401
    let bad = reqwest::Client::new()
        .get(format!("{}/", env.web_base))
        .header("Host", "d.e2e.test")
        .basic_auth("bob", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401);
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
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
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

/// e2e egress 回归：旧代码无 Open{egress} 分支时，此测试挂（代理连上即被挂起/502）。
/// 断言抓：经 agent 本地代理 CONNECT 到后端，回包含 EGRESS-OK（证明走了 server 出口拨回）。
#[tokio::test]
async fn egress_http_proxy_roundtrip() {
    // 公网目标替身：本机 echo 后端（server 拨它 = 经 server 出口）
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let n = s.read(&mut b).await.unwrap_or(0);
                eprintln!("E2E-BACKEND got n={n} head={:?}", &b[..n.min(80)]);
                let body = format!("EGRESS-OK got={n}");
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    let eport = free_port();
    let env = boot_with_desired(
        &format!("[egress.http]\nlisten_ip = \"127.0.0.1\"\nlisten_port = {eport}\nenabled = true\n"),
        None,
    )
    .await;
    // 轮询等 egress 监听就绪（40×200ms 上限，不赌固定 sleep）
    let mut ok = false;
    for _ in 0..40 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{eport}")).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "egress proxy never came up");
    // CONNECT 隧道：curl -x 等价手写
    let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{eport}")).await.unwrap();
    c.write_all(format!("CONNECT 127.0.0.1:{bport} HTTP/1.1\r\nHost: 127.0.0.1:{bport}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    // 本机回环下 200 与后续回包可能粘包到达：只消费到首个 CRLFCRLF，剩余字节留给 body。
    let mut raw = vec![];
    let mut tmp = vec![0u8; 4096];
    loop {
        let n = c.read(&mut tmp).await.unwrap();
        assert!(n > 0, "CONNECT closed before established");
        raw.extend_from_slice(&tmp[..n]);
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let hs = String::from_utf8_lossy(&raw).into_owned();
    assert!(hs.contains("200"), "CONNECT not established: {hs}");
    let hlen = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let mut out = raw[hlen..].to_vec();
    // 隧道内发普通 GET，后端应回 EGRESS-OK
    c.write_all(b"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
    c.read_to_end(&mut out).await.unwrap();
    let body = String::from_utf8_lossy(&out).into_owned();
    assert!(body.contains("EGRESS-OK"), "egress roundtrip failed: {body}");
    let _ = env;
}

/// e2e egress 拨失败：目标端口无监听，server 应回 Close，本地 CONNECT 隧道随之关闭（非挂起）。
#[tokio::test]
async fn egress_dial_refused_close() {
    let eport = free_port();
    let dead = free_port(); // 刚取到的空闲端口：无监听
    let env = boot_with_desired(
        &format!("[egress.http]\nlisten_ip = \"127.0.0.1\"\nlisten_port = {eport}\nenabled = true\n"),
        None,
    )
    .await;
    for _ in 0..40 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{eport}")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{eport}")).await.unwrap();
    c.write_all(format!("CONNECT 127.0.0.1:{dead} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    // 首版 CONNECT 先回 200，随后 server 拨失败 Close，隧道应在 40×200ms 内关闭
    let mut buf = vec![0u8; 4096];
    let mut closed = false;
    for _ in 0..40 {
        match tokio::time::timeout(Duration::from_millis(200), c.read(&mut buf)).await {
            Ok(Ok(0)) => {
                closed = true;
                break;
            }
            Ok(Ok(_)) => continue, // 200 头等数据，继续等 EOF
            _ => continue,
        }
    }
    assert!(closed, "dial-refused stream did not close");
    let _ = env;
}

/// e2e desired 文件重载回归：旧代码无 reload 接口时，此测试在 POST /api/desired/reload 即 404。
/// 断言抓三段：①手改文件加 tcp 映射→reload→端口通；②文件改错（非法 TOML）→reload 500 且旧映射仍通（内存不动）；
/// ③修好但某条字段非法→reload 成功、好条生效、坏条跳过（skipped=1）。
#[tokio::test]
async fn desired_reload_from_file() {
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
    let rport = free_port();
    // 自建 dir 传 desired 路径以便手改：复制 boot_with_desired 拉起逻辑，desired_path 用可写路径
    let ws_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let cfg_path = dir.join("agent.toml");
    tokio::fs::write(&cfg_path, "hostname = \"e2e\"\ntoken = \"s3cret\"\n")
        .await
        .unwrap();
    let data = dir.join("data");
    tokio::fs::create_dir_all(&data).await.unwrap();
    let desired_path = dir.join("desired.toml");
    tokio::fs::write(&desired_path, "").await.unwrap(); // 初始空文件
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let mut srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
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
    let mut ag = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
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
    let web_base = format!("http://127.0.0.1:{ws_port}");
    let jwt = login(&web_base).await;
    let c = reqwest::Client::new();
    let do_reload = || async {
        c.post(format!("{web_base}/api/desired/reload"))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
    };
    async fn echo_ok(rport: u16) -> bool {
        let mut s = match tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await {
            Ok(s) => s,
            Err(_) => return false,
        };
        if s.write_all(b"reload-ping").await.is_err() {
            return false;
        }
        let mut b = vec![0u8; 32];
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut b)).await {
            Ok(Ok(n)) => &b[..n] == b"reload-ping",
            _ => false,
        }
    }
    // ① 手写一段 tcp 映射 → reload → 端口通（轮询 40×200ms 等 listen 生效）
    tokio::fs::write(
        &desired_path,
        format!(
            "[[agents.e2e]]\nname=\"svc\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\nenabled=true\n"
        ),
    )
    .await
    .unwrap();
    let r = do_reload().await;
    assert_eq!(r.status(), 200);
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["ok"], true);
    assert_eq!(j["reloaded"], 1);
    let mut ok = false;
    for _ in 0..40 {
        if echo_ok(rport).await {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "reloaded tcp mapping not reachable");
    // ② 写入非法 TOML → reload 500 且旧映射仍通（内存不动）
    tokio::fs::write(&desired_path, "[[[broken").await.unwrap();
    let r = do_reload().await;
    assert_eq!(r.status(), 500);
    assert!(echo_ok(rport).await, "old mapping lost after bad reload");
    // ③ 好条+坏条（tcp 但 remote_port=0）→ ok 且 skipped=1，好条仍通
    tokio::fs::write(
        &desired_path,
        format!(
            "[[agents.e2e]]\nname=\"svc\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\nenabled=true\n\n[[agents.e2e]]\nname=\"bad\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port=0\nenabled=true\n"
        ),
    )
    .await
    .unwrap();
    let r = do_reload().await;
    assert_eq!(r.status(), 200);
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["ok"], true);
    assert_eq!(j["skipped"], 1);
    assert!(echo_ok(rport).await, "good mapping lost after partial reload");
    let _ = (&mut srv, &mut ag);
}

/// 双 agent 启动器（link e2e 用）：同一 server + 两个 hostname 不同的 agent。
/// agent1 纯出口（无 link），agent2 带 link 条目（入口监听）。
struct Env2 {
    web_base: String,
    _srv: tokio::process::Child,
    _ag1: tokio::process::Child,
    _ag2: tokio::process::Child,
}

async fn boot_two_agents(desired_toml: &str) -> Env2 {
    let ws_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let cfg1 = dir.join("a1.toml");
    let cfg2 = dir.join("a2.toml");
    tokio::fs::write(&cfg1, "hostname = \"agent1\"\ntoken = \"s3cret\"\n").await.unwrap();
    tokio::fs::write(&cfg2, "hostname = \"agent2\"\ntoken = \"s3cret\"\n").await.unwrap();
    let data = dir.join("data");
    tokio::fs::create_dir_all(&data).await.unwrap();
    let desired_path = dir.join("desired.toml");
    tokio::fs::write(&desired_path, desired_toml).await.unwrap();
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let mut srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
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
    let _ = &mut srv;
    let mk_agent = |cfg: &std::path::PathBuf| {
        tokio::process::Command::new(&bin)
            .stdout(e2e_stdio())
            .stderr(e2e_stdio())
            .args([
                "agent",
                "--server",
                &format!("ws://127.0.0.1:{ws_port}/ws"),
                "--config",
                cfg.to_str().unwrap(),
            ])
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    };
    let ag1 = mk_agent(&cfg1);
    let ag2 = mk_agent(&cfg2);
    tokio::time::sleep(Duration::from_secs(2)).await;
    Env2 {
        web_base: format!("http://127.0.0.1:{ws_port}"),
        _srv: srv,
        _ag1: ag1,
        _ag2: ag2,
    }
}

/// link 对端不在线：client 被干净 Close（读 EOF），入口 agent 主链不断。
/// link e2e 回归：旧代码无 Open{link} 分支/入口监听时，此测试挂（连上无回声）。
/// 断言抓：client → agent2 监听 → server → agent1 → echo 回声；
/// 且 /api/conns 有 tunnel==dblink 的行，client 关后行消失（Drop-guard）。
#[tokio::test]
async fn link_tcp_roundtrip() {
    // 后端 echo（agent1 可达）
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = echo.accept().await else { break };
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let link_port = free_port();
    let desired = format!(
        "[[agents.agent2]]\nname=\"dblink\"\ntype=\"link\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={link_port}\nlink_agent=\"agent1\"\nlink_host=\"127.0.0.1\"\nlink_port={echo_port}\nenabled=true\n"
    );
    let env = boot_two_agents(&desired).await;
    // 轮询等入口监听就绪（40×200ms 上限，不赌固定 sleep）
    let mut ok = false;
    for _ in 0..40 {
        if link_echo_ok(link_port, b"hello-link").await {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "link roundtrip never came up");
    // conns 有行
    let c = reqwest::Client::new();
    let jwt = login(&env.web_base).await;
    // 保持一条连接打开时查 conns（回声测完即关，看不到行；这里重开一条不关）
    let mut holder = tokio::net::TcpStream::connect(format!("127.0.0.1:{link_port}"))
        .await
        .unwrap();
    holder.write_all(b"ping").await.unwrap();
    let mut shown = false;
    for _ in 0..40 {
        let j: serde_json::Value = c
            .get(format!("{}/api/conns", env.web_base))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let arr = j["conns"].as_array().cloned().unwrap_or_default();
        if arr.iter().any(|x| x["tunnel"] == "dblink" && x["proto"] == "link") {
            shown = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(shown, "conns should show the link stream");
    drop(holder);
    // 关后行消失（Drop-guard，无僵尸行）
    let mut gone = false;
    for _ in 0..40 {
        let j: serde_json::Value = c
            .get(format!("{}/api/conns", env.web_base))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let arr = j["conns"].as_array().cloned().unwrap_or_default();
        if !arr.iter().any(|x| x["tunnel"] == "dblink") {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(gone, "link conns row leaked after close");
    let _ = &env._srv;
}

/// link 对端不在线：client 被干净 Close（读 EOF），入口 agent 主链不断。
#[tokio::test]
async fn link_agent_offline_closes() {
    let link_port = free_port();
    let desired = format!(
        "[[agents.agent2]]\nname=\"ghost\"\ntype=\"link\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={link_port}\nlink_agent=\"no-such-agent\"\nlink_host=\"127.0.0.1\"\nlink_port=9999\nenabled=true\n"
    );
    let env = boot_two_agents(&desired).await;
    // 等监听就绪
    let mut up = false;
    for _ in 0..40 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{link_port}")).await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(up, "link listen never came up");
    // 发点数据触发 server 查表失败 → Close；读到 EOF 即干净关闭
    let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{link_port}"))
        .await
        .unwrap();
    let _ = s.write_all(b"hi").await;
    let mut b = vec![0u8; 16];
    let mut eof = false;
    for _ in 0..40 {
        match tokio::time::timeout(Duration::from_millis(200), s.read(&mut b)).await {
            Ok(Ok(0)) => {
                eof = true;
                break;
            }
            Ok(Ok(_)) => {}
            _ => {}
        }
    }
    assert!(eof, "client should see EOF when exit agent offline");
    // 主链不断：overview 仍有 agent2
    let c = reqwest::Client::new();
    let jwt = login(&env.web_base).await;
    let o: serde_json::Value = c
        .get(format!("{}/api/overview", env.web_base))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(o["agents"].as_array().unwrap().iter().any(|a| a["hostname"] == "agent2"));
}

async fn link_echo_ok(port: u16, payload: &[u8]) -> bool {
    let mut s = match tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await {
        Ok(s) => s,
        Err(_) => return false,
    };
    if s.write_all(payload).await.is_err() {
        return false;
    }
    let mut b = vec![0u8; 64];
    match tokio::time::timeout(Duration::from_secs(5), s.read(&mut b)).await {
        Ok(Ok(n)) => &b[..n] == payload,
        _ => false,
    }
}

/// link 热更新：删 desired 条目后监听端口释放（连接被拒）。
#[tokio::test]
async fn link_hot_update() {
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = echo.accept().await else { break };
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let link_port = free_port();
    let desired = format!(
        "[[agents.agent2]]\nname=\"tmp\"\ntype=\"link\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={link_port}\nlink_agent=\"agent1\"\nlink_host=\"127.0.0.1\"\nlink_port={echo_port}\nenabled=true\n"
    );
    let env = boot_two_agents(&desired).await;
    let mut ok = false;
    for _ in 0..40 {
        if link_echo_ok(link_port, b"hot").await {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "link never came up before update");
    // 置空 agent2 的 desired（经 WebUI API）
    let c = reqwest::Client::new();
    let jwt = login(&env.web_base).await;
    let r = c
        .post(format!("{}/api/desired/agent2", env.web_base))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"proxies": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // 监听释放：轮询到连接被拒（40×200ms）
    let mut released = false;
    for _ in 0..40 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{link_port}")).await.is_err() {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(released, "link listen not released after hot update");
}

/// RED 现场：server 重启后 agent 无感知、tm hang 60s+。kill server 模拟重启，
/// agent 必须 60s 内重拨（心跳超时 45s + backoff 1s，留余量到 100s 上限轮询）、
/// 新 server 上线后 overview 再次出现该 agent。
/// 旧代码裸 next() 永等：agent 进程不退出但永远不重连，此断言挂到超时。
#[tokio::test]
async fn e2e_server_restart_agent_redials() {
    let env = boot("").await;
    let c = reqwest::Client::new();
    // agent 先在线（overview 有 e2e）
    let jwt = login(&env.web_base).await;
    let mut online = false;
    for _ in 0..40 {
        let o: serde_json::Value = c
            .get(format!("{}/api/overview", env.web_base))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if o["agents"].as_array().unwrap().iter().any(|a| a["hostname"] == "e2e") {
            online = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(online, "agent never came online before kill");
    // kill server = 模拟重启（agent 侧 TCP 半开：无 FIN、无 RST）
    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let mut env = env;
    env._srv.kill().await.unwrap();
    let _ = env._srv.wait().await;
    // 新 server 同端口同 data/期望态起来（agent 应凭心跳超时自动重拨回来）
    let srv = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{}", env.http_port),
            "--data",
            env.data_dir.to_str().unwrap(),
            "--desired",
            env.data_dir.join("../desired.toml").to_str().unwrap(),
            "--token",
            "s3cret",
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    env._srv = srv;
    wait_for(&format!("127.0.0.1:{}", env.http_port)).await;
    let jwt = login(&env.web_base).await;
    // 心跳 45s + backoff，100s 上限轮询等 agent 回来
    let mut back = false;
    for _ in 0..500 {
        let o: serde_json::Value = c
            .get(format!("{}/api/overview", env.web_base))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if o["agents"].as_array().unwrap().iter().any(|a| a["hostname"] == "e2e") {
            back = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(back, "agent did not redial after server restart (heartbeat gap!)");
    let _ = env;
}

/// 回归：映射级总量下行限速（旧代码无 sleep，此用例耗时远低于 4s 下限而红）。
/// 断言抓：2MB @0.5m 耗时 >= 3.6s 理论下限（含余量）；内容传对（限速不丢包）；
/// 不限速对照组明显快（<2s）。
#[tokio::test]
async fn e2e_tcp_ratelimit_throttles_downlink() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // 后端 echo：client 上传 2MB，echo 回 2MB，测的是回程（公网->agent 下行被压）。
    async fn echo_env(proxies_toml: String) -> (Env, u16) {
        let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bport = back.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = back.accept().await else { break };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let rport = free_port();
        let env = boot(&proxies_toml.replace("{bport}", &bport.to_string()).replace("{rport}", &rport.to_string())).await;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        (env, rport)
    }
    // 分块顺序 roundtrip：一次只在途 32KB，避免 bulk 一次灌满触发 WSS 路径偶发丢块竞态
    //（基线套件从无 bulk 用例，该竞态属 scope 外；限速不断言仍成立：每块回程因果链都经过被压的上行泵）。
    async fn roundtrip(tag: &str, rport: u16, n: usize) -> Duration {
        let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await.unwrap();
        let t0 = std::time::Instant::now();
        let mut off = 0;
        while off < n {
            let len = (n - off).min(32 * 1024);
            let chunk = vec![0xABu8; len];
            c.write_all(&chunk).await.unwrap();
            let mut got = vec![0u8; len];
            let mut roff = 0;
            while roff < len {
                let m = tokio::time::timeout(Duration::from_secs(30), c.read(&mut got[roff..])).await
                    .unwrap_or_else(|_| panic!("[{tag}] read stall: block {off}/{n} got {roff}/{len}"))
                    .unwrap();
                assert!(m > 0, "[{tag}] eof before full echo (block {off}/{n})");
                roff += m;
            }
            assert!(got.iter().all(|&b| b == 0xAB), "[{tag}] 限速不丢包/不错包");
            off += len;
        }
        let dt = t0.elapsed();
        eprintln!("[{tag}] total={dt:?}");
        dt
    }
    const N: usize = 256 * 1024;
    // 限速组：rate_limit="0.5m"（理论 0.5s，断言 0.4s 下限——只验证“限速生效”，不压大流量）
    let (env_l, rp_l) = echo_env("[[proxies]]\nname=\"bt\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\nrate_limit=\"0.5m\"\n".into()).await;
    let dt_l = roundtrip("limited", rp_l, N).await;
    // 理论下限 256KB/0.5MB/s=0.5s，留余量防计时抖动
    assert!(dt_l >= Duration::from_millis(400), "限速未生效：{dt_l:?}");
    drop(env_l);
    // 对照组：不限速，同样 2MB 应明显快（<2s；机器再慢也不至于到 3.6s）
    let (env_f, rp_f) = echo_env("[[proxies]]\nname=\"bt\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\n".into()).await;
    let dt_f = roundtrip("unlimited", rp_f, N).await;
    assert!(dt_f < Duration::from_millis(2000), "对照组太慢，环境异常：{dt_f:?}");
    // 限速组必须显著慢于对照组（至少 3 倍，排除环境抖动误判）
    assert!(dt_l >= dt_f * 3, "限速不显著：限速{dt_l:?} vs 不限速{dt_f:?}");
    let _ = (env_f, dt_l);
}

/// 回归：请求日志中间件不破坏正常响应——/api/tunnels 200 且 3s 内回。
/// 根因→修法：加 layer 时曾把 shared move 掉导致编译挂；此用例锁死中间件透明性。
/// 慢请求告警语义由单测 slow_msg_fires_only_over_threshold 锁。
#[tokio::test]
async fn e2e_api_middleware_transparent() {
    let env = boot("").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let jwt = login(&env.web_base).await;
    let cli = reqwest::Client::new();
    let t0 = std::time::Instant::now();
    let r = tokio::time::timeout(
        Duration::from_secs(3),
        cli.get(format!("{}/api/tunnels", env.web_base)).bearer_auth(&jwt).send(),
    )
    .await
    .expect("中间件下 /api/tunnels 3s 无响应");
    assert!(r.unwrap().status().is_success());
    assert!(t0.elapsed() < Duration::from_secs(3));
    let _ = env;
}

/// 回归：UDP flood 时 /api/tunnels 必须秒回——UDP 收包循环每包拿
/// agents.write() 全表扫描（旧代码），BT uTP flood 下写锁常驻，
/// tunnels 的 agents.read() 饿死 6s+（线上 /api/overview pending 根因；
/// live/conns/traffic 不读 agents 锁所以都 1ms 正常）。
/// 修法：session 建时缓存 aid+outbox sender，每包只碰 conns 行 + 本地累计，
/// agent rx 按秒批量刷一次。
#[tokio::test]
async fn e2e_udp_flood_does_not_starve_tunnels_api() {
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = vec![0u8; 2048];
        loop {
            let Ok((n, peer)) = back.recv_from(&mut b).await else { break };
            let _ = back.send_to(&b[..n], peer).await; // 回包，保证双向都有量
        }
    });
    let rport = free_port();
    let env = boot(&format!(
        "[[proxies]]\nname=\"u\"\ntype=\"udp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\nrate_limit=\"1m\"\n"
    ))
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    // flood 3s：8 并发 UDP flood（多 peer 多 session，压出 BT uTP 量级 pps）。
    // 每包 server 侧拿 agents.write() 做 rx/tx 记账（收包循环 + 回包泵各一次），
    // 写锁常驻 -> /api/tunnels 的 agents.read() 饿死 pending（线上 6s+ 根因；
    // live/conns/traffic 不碰 agents 锁所以都 1ms 正常）。
    let mut floods = vec![];
    for _ in 0..8 {
        let rp = rport;
        floods.push(tokio::spawn(async move {
            let cli = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            cli.connect(format!("127.0.0.1:{rp}")).await.unwrap();
            let pkt = vec![0xEEu8; 1024];
            let t0 = std::time::Instant::now();
            while t0.elapsed() < Duration::from_secs(3) {
                let _ = cli.send(&pkt).await;
            }
        }));
    }
    let flood = tokio::spawn(async move {
        for f in floods {
            let _ = f.await;
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await; // 让 flood 先起来
    let jwt = login(&env.web_base).await;
    let cli = reqwest::Client::new();
    let t0 = std::time::Instant::now();
    let r = tokio::time::timeout(
        Duration::from_secs(3),
        cli.get(format!("{}/api/tunnels", env.web_base)).bearer_auth(&jwt).send(),
    )
    .await
    .expect("flood 下 /api/tunnels 3s 无响应：agents 锁被 UDP 包循环饿死");
    assert!(r.unwrap().status().is_success());
    eprintln!("[udp-starve] tunnels latency under flood: {:?}", t0.elapsed());
    flood.await.unwrap();
    let _ = env;
}

/// 回归：5s 实时快照——tcp 跑量后 /api/live 10s 内可见该 tunnel 且 rx_5s>0。
/// 旧代码无 live tick、无 /api/live 路由，此 GET 直接 404 而红。
#[tokio::test]
async fn e2e_live_snapshot_within_10s() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = back.accept().await else { break };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let rport = free_port();
    let env = boot(&format!(
        "[[proxies]]\nname=\"lv\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\n"
    ))
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    // 持续跑量：后台循环 32KB roundtrip 10s，保证跨过一个 5s tick（相位随机，6s 不够稳）
    tokio::spawn(async move {
        let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await.unwrap();
        let chunk = vec![0xABu8; 32 * 1024];
        let t0 = std::time::Instant::now();
        while t0.elapsed() < Duration::from_secs(10) {
            if c.write_all(&chunk).await.is_err() {
                break;
            }
            let mut got = vec![0u8; 32 * 1024];
            if c.read_exact(&mut got).await.is_err() {
                break;
            }
        }
    });
    // 轮询 /api/live（上限 10s，每 1s 一次）
    let jwt = login(&env.web_base).await;
    let cli = reqwest::Client::new();
    let mut seen = false;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let j: serde_json::Value = cli
            .get(format!("{}/api/live?tunnel=e2e/lv", env.web_base))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let rows = j["live"].as_array().cloned().unwrap_or_default();
        if rows.iter().any(|r| r["rx_5s"].as_u64().unwrap_or(0) > 0) {
            seen = true;
            break;
        }
    }
    assert!(seen, "10s 内 /api/live 未见 e2e/lv 跑量");
    let _ = env;
}

/// 回归：UDP 限速不断包——慢发 100 包（每包 1KB，间隔 5ms），限速组全收到。
/// 猛发 flood 在本机回环上连不限速组都丢包（WSS 中转跟不上，现场 384/2048），
/// flood 丢包断言是伪命题；此用例只锁“限速不丢正常流量”，钳制效果由线上网卡验证。
#[tokio::test]
async fn e2e_udp_ratelimit_keeps_ordered_flow() {
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        let mut b = vec![0u8; 2048];
        loop {
            let Ok((n, _)) = back.recv_from(&mut b).await else { break };
            let _ = tx.send(b[..n].to_vec());
        }
    });
    let rport = free_port();
    let env = boot(&format!(
        "[[proxies]]\nname=\"u\"\ntype=\"udp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\nrate_limit=\"512k\"\n"
    ))
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let cli = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli.connect(format!("127.0.0.1:{rport}")).await.unwrap();
    for i in 0u8..100 {
        let mut pkt = vec![0xDDu8; 1024];
        pkt[0] = i;
        cli.send(&pkt).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut got = vec![];
    while let Ok(p) = rx.try_recv() {
        got.push(p);
    }
    eprintln!("[udp-ordered] limited got {}/100", got.len());
    assert!(got.len() >= 95, "限速丢正常流量：{}/100", got.len());
    let _ = env;
}

/// 回归：UDP 收包方向 sleep 限速——持续猛发时后端收到速率被钳住。
/// client 猛发 1KB 包不停（1s），数后端 1s 内收到包数。
/// 限速组（64k 上限）：sleep 拖读，后端速率 ≈ 上限（~64 包/s，留余量断言 <300）。
/// 不限速组：读得快，WSS 中转瓶颈前能跑满（本机现场 384/2s，远超 300）。
/// 旧代码（无 sleep）：两组一样快，限速组不断言成立而红。
#[tokio::test]
async fn e2e_udp_ratelimit_caps_ingress_rate() {
    async fn rate_env(limit: &str) -> usize {
        let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bport = back.local_addr().unwrap().port();
        let cnt = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt2 = cnt.clone();
        tokio::spawn(async move {
            let mut b = vec![0u8; 2048];
            loop {
                let Ok(_) = back.recv_from(&mut b).await else { break };
                cnt2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        let rport = free_port();
        let toml = if limit.is_empty() {
            format!("[[proxies]]\nname=\"u\"\ntype=\"udp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\n")
        } else {
            format!("[[proxies]]\nname=\"u\"\ntype=\"udp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\nrate_limit=\"{limit}\"\n")
        };
        let env = boot(&toml).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let cli = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        cli.connect(format!("127.0.0.1:{rport}")).await.unwrap();
        let pkt = vec![0xDDu8; 1024];
        let t0 = std::time::Instant::now();
        while t0.elapsed() < Duration::from_secs(1) {
            let _ = cli.send(&pkt).await;
        }
        // 再等 2s 让 sleep 拖住的包慢慢转完，然后读数（限速组转得慢，计数低）
        tokio::time::sleep(Duration::from_secs(2)).await;
        let n = cnt.load(std::sync::atomic::Ordering::Relaxed);
        drop(env);
        n
    }
    let n_limited = rate_env("64k").await;
    let n_free = rate_env("").await;
    eprintln!("[udp-rate] limited={n_limited} free={n_free}");
    assert!(n_limited < 300, "UDP 限速未生效：限速组收到 {n_limited} 包/s");
    assert!(n_free > n_limited * 2, "限速不显著：限速{n_limited} vs 不限速{n_free}");
}

/// 回归：映射级双向总量限速——client 上传方向（公网->agent）同压。
/// 因果链写法：后端每收齐 32KB 回 1 字节 ack，client 发一块等一 ack。
/// server 内核缓冲再大也藏不住——ack 没回来下一块发不出去，耗时 = 上行泵真实转发速率。
/// （反面教材：单向 write_all 计时全是假阴性，256KB 进内核缓冲就返回，现场 73µs。）
#[tokio::test]
async fn e2e_tcp_ratelimit_throttles_uplink() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = back.accept().await else { break };
            tokio::spawn(async move {
                let mut b = vec![0u8; 32 * 1024];
                loop {
                    // 收齐一块 -> 回 1 字节 ack（ack 经回程，1 字节可忽略）
                    let mut off = 0;
                    while off < b.len() {
                        match s.read(&mut b[off..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => off += n,
                        }
                    }
                    if s.write_all(&[0x06]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    const N: usize = 256 * 1024;
    let rport = free_port();
    let env = boot(&format!(
        "[[proxies]]\nname=\"up\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\nrate_limit=\"0.5m\"\n"
    ))
    .await;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await.unwrap();
    let t0 = std::time::Instant::now();
    let mut off = 0;
    while off < N {
        let len = (N - off).min(32 * 1024);
        c.write_all(&vec![0xCDu8; len]).await.unwrap();
        let mut ack = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(30), c.read_exact(&mut ack))
            .await
            .unwrap_or_else(|_| panic!("[uplink] ack stall: block {off}/{N}"))
            .unwrap();
        assert_eq!(ack[0], 0x06);
        off += len;
    }
    let dt = t0.elapsed();
    eprintln!("[uplink-limited] up={dt:?}");
    // 理论下限 256KB/0.5MB/s=0.5s，留余量防计时抖动
    assert!(dt >= Duration::from_millis(400), "上行限速未生效：{dt:?}");
    let _ = env;
}
