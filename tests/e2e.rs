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
    http_port: u16,
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
        http_port: ws_port,
        web_base: format!("http://127.0.0.1:{ws_port}"),
        _srv: srv,
        _ag1: ag1,
        _ag2: ag2,
    }
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
    let _ = env.http_port;
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
