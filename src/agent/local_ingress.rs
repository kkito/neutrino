//! agent 本地 HTTP 入口：内网 `http://<name><suffix>` 直访名下 http 隧道。
//! 转发面见 Task 2；本文件先落纯函数（单测锁定）。
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

use super::web::AgentStatus;
use crate::server::http_util::{extract_host, inject_xfp};

/// 剥泛域名：host 已小写去端口；suffix 须小写且以 '.' 开头。
/// 单 label 才接受（`a.b.suffix` 拒绝防越权）；miss 返回 None（调用方回 404 目录页）。
pub(crate) fn strip_ingress_name(host: &str, suffix: &str) -> Option<String> {
    if suffix.is_empty() || !suffix.starts_with('.') {
        return None;
    }
    let label = host.strip_suffix(suffix)?;
    if label.is_empty() || label.contains('.') {
        return None;
    }
    Some(label.to_string())
}

/// 404 目录页：只列隧道名（不泄露 token/上行地址）。返回 (status, body)。
pub(crate) fn directory_page(names: &[String]) -> (u16, Vec<u8>) {
    let mut body = String::from("no such tunnel\navailable:");
    for n in names {
        body.push(' ');
        body.push_str(n);
    }
    body.push('\n');
    (404, body.into_bytes())
}

/// 本地入口监听：与 session/上行解耦——读 `status.proxies` 实时快照，Config 热更新即时生效；
/// 断网时照常用（本地直连本机服务，不依赖上行）。bind 失败只 warn＋status 标错，不 abort 主循环。
/// 根因→修法：监听 task 与 session 主链解耦（同 egress/serve_link 模式），bind 失败直接返回。
pub(crate) async fn serve_local_ingress(cfg: super::LocalIngress, status: Arc<RwLock<AgentStatus>>) {
    {
        let mut st = status.write().await;
        st.local_ingress_listen = format!("{}:{}", cfg.listen_ip, cfg.listen_port);
        st.local_ingress_on = cfg.enabled;
        st.local_ingress_err = None;
    }
    if !cfg.enabled {
        return;
    }
    let suffix = cfg.suffix.to_lowercase();
    if suffix.is_empty() || !suffix.starts_with('.') {
        status.write().await.local_ingress_err =
            Some("suffix empty or missing leading dot (e.g. .local.xxx.com)".into());
        return;
    }
    let lis = match tokio::net::TcpListener::bind(format!("{}:{}", cfg.listen_ip, cfg.listen_port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("local ingress bind failed: {e:#}");
            status.write().await.local_ingress_err = Some(format!("bind failed: {e:#}"));
            return;
        }
    };
    tracing::info!("local ingress on {}:{} suffix {suffix}", cfg.listen_ip, cfg.listen_port);
    loop {
        let Ok((inbound, _)) = lis.accept().await else {
            continue;
        };
        let (st, sf) = (status.clone(), suffix.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_conn(inbound, st, &sf).await {
                tracing::debug!("local ingress conn ended: {e:#}");
            }
        });
    }
}

/// 单连接：读头→抽 host→剥后缀→查快照→basic_auth→XFP→dial 本地→双向泵。
/// miss 回 404 目录页；auth 失败回 401（浏览器弹框）；本地 dial 失败回 502。
async fn handle_conn(
    mut inbound: tokio::net::TcpStream,
    status: Arc<RwLock<AgentStatus>>,
    suffix: &str,
) -> anyhow::Result<()> {
    // 读到完整请求头（上限 64K，防慢连接撑内存；同 egress）
    let mut buf = vec![];
    let mut tmp = vec![0u8; 8192];
    loop {
        let n = inbound.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            anyhow::bail!("head too large");
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head_str = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let host = extract_host(&head_str);
    // 快照：只读一次（连接级一致性；热配下一连接即生效）
    let proxies = status.read().await.proxies.clone();
    let http_names: Vec<String> = proxies
        .iter()
        .filter(|p| p.ptype == "http" && p.enabled)
        .map(|p| p.name.clone())
        .collect();
    let label = strip_ingress_name(&host, suffix);
    let proxy = label.as_deref().and_then(|l| {
        proxies.iter().find(|p| p.ptype == "http" && p.enabled && p.name == *l)
    });
    let Some(p) = proxy.cloned() else {
        let (code, body) = directory_page(&http_names);
        respond(&mut inbound, code, "text/plain", &[], &body).await?;
        return Ok(());
    };
    // 头收集成 HeaderMap（basic_auth 校验用；与 server 入口同语义）
    let mut headers = http::HeaderMap::new();
    for ln in head_str.lines().skip(1) {
        let t = ln.trim();
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            if let (Ok(kn), Ok(vv)) = (
                k.trim().parse::<http::HeaderName>(),
                v.trim().parse::<http::HeaderValue>(),
            ) {
                headers.append(kn, vv);
            }
        }
    }
    if !crate::common::proto::check_basic_auth(&headers, p.basic_auth.as_deref()) {
        respond(
            &mut inbound,
            401,
            "text/plain",
            &[("WWW-Authenticate".into(), format!("Basic realm=\"{}\"", p.name))],
            b"auth required\n",
        )
        .await?;
        return Ok(());
    }
    // XFP 注入（配了才改写；复用 server 侧纯函数）
    let mut head = buf[..head_end].to_vec();
    if let Some(proto) = p.set_x_forwarded_proto.as_deref() {
        head = inject_xfp(&head, proto);
    }
    // dial 本地服务（body 已在 buf 里的一并带上：head_end 之后的是首包 body）
    let mut up = match tokio::net::TcpStream::connect((p.local_ip.as_str(), p.local_port)).await {
        Ok(u) => u,
        Err(e) => {
            tracing::debug!("local ingress dial {}:{} failed: {e:#}", p.local_ip, p.local_port);
            respond(&mut inbound, 502, "text/plain", &[], b"agent dial refused\n").await?;
            return Ok(());
        }
    };
    up.write_all(&head).await?;
    if buf.len() > head_end {
        up.write_all(&buf[head_end..]).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut up).await;
    Ok(())
}

/// 最小 HTTP 响应（固定 content-length＋close；内网排错够用，不做 chunked）。
async fn respond(
    w: &mut tokio::net::TcpStream,
    code: u16,
    ctype: &str,
    extra: &[(String, String)],
    body: &[u8],
) -> anyhow::Result<()> {
    let reason = match code {
        401 => "Unauthorized",
        404 => "Not Found",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let mut h = format!(
        "HTTP/1.1 {code} {reason}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (k, v) in extra {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str("\r\n");
    w.write_all(h.as_bytes()).await?;
    w.write_all(body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_matches_single_label() {
        assert_eq!(strip_ingress_name("web.local.e2e", ".local.e2e"), Some("web".into()));
    }

    #[test]
    fn strip_case_insensitive_host() {
        // extract_host 已小写，此处锁：大写 host 要求调用方先小写——纯函数按原样比，
        // 大写 suffix 场景由调用方归一化；这里只锁小写命中。
        assert_eq!(strip_ingress_name("WEB.LOCAL.E2E".to_lowercase().as_str(), ".local.e2e"), Some("web".into()));
    }

    #[test]
    fn strip_rejects_multi_label() {
        // 越权拒绝：a.b.suffix 不能映射到任何隧道
        assert_eq!(strip_ingress_name("evil.deep.local.e2e", ".local.e2e"), None);
    }

    #[test]
    fn strip_rejects_empty_label() {
        assert_eq!(strip_ingress_name(".local.e2e", ".local.e2e"), None);
    }

    #[test]
    fn strip_rejects_bad_suffix() {
        assert_eq!(strip_ingress_name("web.local.e2e", "local.e2e"), None); // 无前导点
        assert_eq!(strip_ingress_name("web.local.e2e", ""), None);
    }

    #[test]
    fn strip_rejects_non_suffix_host() {
        assert_eq!(strip_ingress_name("web.other.io", ".local.e2e"), None);
    }


    #[tokio::test]
    async fn handle_conn_routes_by_suffix_and_auth() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // backend 固定回 BACKEND
        let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bport = back.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = back.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = vec![0u8; 4096];
                    let _ = s.read(&mut b).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\nconnection: close\r\n\r\nBACKEND")
                        .await;
                });
            }
        });
        // status.proxies 快照：web（无 auth）+ sec（basic_auth u:p）
        let status = Arc::new(RwLock::new(AgentStatus {
            version: "t".into(),
            server_url: "ws://x/ws".into(),
            hostname: "h".into(),
            proxies: vec![
                crate::common::proto::ProxyConfig {
                    name: "web".into(), ptype: "http".into(),
                    local_ip: "127.0.0.1".into(), local_port: bport,
                    domains: vec![], remote_port: 0, set_x_forwarded_proto: None,
                    basic_auth: None, enabled: true,
                    link_agent: String::new(), link_host: String::new(), link_port: 0,
                    rate_limit: None,
                },
                crate::common::proto::ProxyConfig {
                    name: "sec".into(), ptype: "http".into(),
                    local_ip: "127.0.0.1".into(), local_port: bport,
                    domains: vec![], remote_port: 0, set_x_forwarded_proto: None,
                    basic_auth: Some("u:p".into()), enabled: true,
                    link_agent: String::new(), link_host: String::new(), link_port: 0,
                    rate_limit: None,
                },
            ],
            ..Default::default()
        }));
        async fn get(port: u16, host: &str, auth: Option<&str>) -> (String, Vec<u8>) {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let mut req = format!("GET / HTTP/1.1\r\nHost: {host}\r\n");
            if let Some(a) = auth {
                req.push_str(&format!("Authorization: Basic {}\r\n", { use base64::Engine as _; base64::engine::general_purpose::STANDARD.encode(a) }));
            }
            req.push_str("\r\n");
            s.write_all(req.as_bytes()).await.unwrap();
            let mut b = vec![];
            s.read_to_end(&mut b).await.unwrap();
            let h = b.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(b.len());
            (String::from_utf8_lossy(&b[..h]).to_string(), b[h..].to_vec())
        }
        // serve 起在 127.0.0.1:0
        let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lport = lis.local_addr().unwrap().port();
        drop(lis);
        let cfg = super::super::LocalIngress {
            enabled: true, listen_ip: "127.0.0.1".into(), listen_port: lport, suffix: ".local.e2e".into(),
        };
        let st2 = status.clone();
        tokio::spawn(async move { super::serve_local_ingress(cfg, st2).await; });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // 命中
        let (h, b) = get(lport, "web.local.e2e", None).await;
        assert!(h.contains("200") && b == b"BACKEND", "hit failed: {h}");
        // miss 列名
        let (h, b) = get(lport, "nope.local.e2e", None).await;
        assert!(h.contains("404") && String::from_utf8_lossy(&b).contains("web"), "miss page: {h}");
        // 多 label 拒绝
        let (h, _) = get(lport, "evil.deep.local.e2e", None).await;
        assert!(h.contains("404"), "multi-label must 404: {h}");
        // auth：无头 401，有头 200
        let (h, _) = get(lport, "sec.local.e2e", None).await;
        assert!(h.contains("401") && h.contains("WWW-Authenticate"), "auth missing: {h}");
        let (h, b) = get(lport, "sec.local.e2e", Some("u:p")).await;
        assert!(h.contains("200") && b == b"BACKEND", "auth ok failed: {h}");
    }
    #[test]
    fn directory_page_lists_names_without_secrets() {
        let (code, body) = directory_page(&["web".into(), "sec".into()]);
        assert_eq!(code, 404);
        let s = String::from_utf8(body).unwrap();
        assert!(s.contains("web") && s.contains("sec"));
        assert!(!s.contains("token") && !s.contains("wss://") && !s.contains("kudus://"));
    }
}
