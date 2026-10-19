//! server WebUI API：login/overview/tunnels/logs/config/desired/toggle。
use crate::common::proto::*;
use super::auth::{auth_ok, mint_jwt, unauthorized};
use super::state::{apply_proxies_for_agent, log_ev, AgentInfo, S};
use axum::{extract::{Path, State}, http::{header, HeaderMap, StatusCode}, response::{Html, IntoResponse, Json}};
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;

pub(crate) async fn index_page() -> Html<&'static str> {
    Html(include_str!("../../web/index.html"))
}

#[derive(Deserialize)]
pub(crate) struct LoginReq {
    user: String,
    pass: String,
}

pub(crate) async fn api_login(
    State((s, _)): State<(S, Arc<String>)>,
    Json(r): Json<LoginReq>,
) -> impl IntoResponse {
    let h = s.password_hash.read().await.clone();
    let ok = if h.is_empty() {
        r.user == "admin" && r.pass == "welcome2neutrino"
    } else {
        r.user == "admin" && bcrypt::verify(&r.pass, &h).unwrap_or(false)
    };
    if !ok {
        log_ev(&s, format!("webui login failed user={}", r.user));
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false}))).into_response();
    }
    let jwt = mint_jwt(&s.jwt_secret);
    let mut resp = Json(serde_json::json!({"ok": true, "token": jwt.clone()})).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        format!("nt_session={jwt}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
            .parse()
            .unwrap(),
    );
    resp
}

pub(crate) async fn api_overview(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let ag = s.agents.read().await;
    let list: Vec<AgentInfo> = ag
        .values()
        .map(|h| {
            let mut i = h.info.clone();
            i.online_secs = (chrono::Utc::now() - h.connected_at).num_seconds();
            i
        })
        .collect();
    Json(serde_json::json!({"agents": list})).into_response()
}

pub(crate) async fn api_tunnels(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let ag = s.agents.read().await;
    let mut out = vec![];
    for hh in ag.values() {
        for p in &hh.info.proxies {
            out.push(serde_json::json!({
                "agent": hh.info.hostname, "agent_id": hh.info.agent_id,
                "name": p.name, "enabled": p.enabled,
                "type": p.ptype, "domains": p.domains, "remote_port": p.remote_port,
                "target": format!("{}:{}", p.local_ip, p.local_port),
                "status": if p.enabled { "online" } else { "disabled" },
            }));
        }
    }
    Json(serde_json::json!({"tunnels": out})).into_response()
}

pub(crate) async fn api_logs(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let v = s.events.read().await.clone();
    Json(serde_json::json!({"logs": v})).into_response()
}

#[derive(Deserialize)]
pub(crate) struct ConfigReq {
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    hostname: String,
    proxies: Vec<ProxyConfig>,
}

/// Push proxy list to agent (hot update, WSS stays up).
pub(crate) async fn api_config(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
    Json(r): Json<ConfigReq>,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    // resolve target agents
    let targets: Vec<(String, String, mpsc::UnboundedSender<ServerMsg>)> = {
        let ag = s.agents.read().await;
        ag.iter()
            .filter(|(_, hh)| {
                (!r.agent_id.is_empty() && hh.info.agent_id == r.agent_id)
                    || (!r.hostname.is_empty() && hh.info.hostname == r.hostname)
                    || (r.agent_id.is_empty() && r.hostname.is_empty())
            })
            .map(|(id, hh)| (id.clone(), hh.info.hostname.clone(), hh.ctl.clone()))
            .collect()
    };
    if targets.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "reason": "no such agent"})),
        )
            .into_response();
    }
    for (aid, hostname, ctl) in &targets {
        let _ = ctl.send(ServerMsg::Config {
            proxies: r.proxies.clone(),
        });
        apply_proxies_for_agent(&s, aid, &r.proxies).await;
        log_ev(&s, format!("config pushed to '{hostname}' ({} proxies)", r.proxies.len()));
    }
    Json(serde_json::json!({"ok": true, "pushed": targets.len()})).into_response()
}

/// Parse desired file text into (hostname -> valid proxies, skipped count).
/// 根因→修法：load 只在启动时调一次，手改文件无感知；重载接口与启动加载共用此纯函数，
/// 坏 TOML 整单拒绝（内存不动），坏条逐条跳过、好条生效。
fn parse_desired_text(text: &str) -> Result<(HashMap<String, Vec<ProxyConfig>>, usize), String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    let agents = v.get("agents").ok_or_else(|| "missing [agents] table".to_string())?;
    if !agents.is_table() {
        return Err("agents is not a table".to_string());
    }
    let mut fresh: HashMap<String, Vec<ProxyConfig>> = HashMap::new();
    let mut skipped = 0;
    for (hostname, val) in agents.as_table().unwrap() {
        // 文件形状：[[agents.<hostname>]] 数组表，每项直接就是 ProxyConfig（与 data/desired.toml 一致）
        let list: Vec<ProxyConfig> =
            serde_json::from_value(serde_json::to_value(val).unwrap_or_default()).unwrap_or_default();
        let mut good = vec![];
        for p in list {
            match validate_proxy(&p) {
                Ok(()) => good.push(p),
                Err(e) => {
                    skipped += 1;
                    tracing::warn!("desired reload skip {hostname}/{}: {e}", p.name);
                }
            }
        }
        fresh.insert(hostname.clone(), good);
    }
    Ok((fresh, skipped))
}

/// Validate one proxy entry from the desired-CRUD form.
fn validate_proxy(p: &ProxyConfig) -> Result<(), String> {
    if p.name.is_empty() {
        return Err("name required".into());
    }
    match p.ptype.as_str() {
        "http" => {
            if p.domains.is_empty() {
                return Err("http proxy requires domains".into());
            }
            Ok(())
        }
        "tcp" | "https" | "udp" => {
            if p.remote_port == 0 {
                return Err(format!("{} proxy requires remote_port", p.ptype));
            }
            Ok(())
        }
        t => Err(format!("unknown type '{t}'")),
    }
}

#[derive(Deserialize)]
pub(crate) struct DesiredReq {
    proxies: Vec<ProxyConfig>,
}

/// Read desired proxies for one hostname.
pub(crate) async fn api_desired_get(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
    Path(hostname): Path<String>,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let proxies = s.desired.read().await.get(&hostname).cloned().unwrap_or_default();
    Json(serde_json::json!({"proxies": proxies})).into_response()
}

/// Replace desired proxies: persist to file, apply to routing, push if online.
pub(crate) async fn api_desired_set(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
    Path(hostname): Path<String>,
    Json(r): Json<DesiredReq>,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    for p in &r.proxies {
        if let Err(e) = validate_proxy(p) {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false, "reason": e}))).into_response();
        }
    }
    // persist first; on write failure keep memory untouched
    {
        let mut st = crate::common::desired::DesiredStore::load(&s.desired_path);
        for (hh, pp) in s.desired.read().await.iter() {
            if hh != &hostname {
                st.set(hh.clone(), pp.clone());
            }
        }
        st.set(hostname.clone(), r.proxies.clone());
        let probe = format!("{}.tmp", st.path);
        if let Err(e) = std::fs::write(&probe, b"probe") {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"ok": false, "reason": e.to_string()}))).into_response();
        }
        let _ = std::fs::remove_file(&probe);
        st.save();
    }
    s.desired.write().await.insert(hostname.clone(), r.proxies.clone());
    let targets: Vec<(String, mpsc::UnboundedSender<ServerMsg>)> = {
        s.agents.read().await.values()
            .filter(|hh| hh.info.hostname == hostname)
            .map(|hh| (hh.info.agent_id.clone(), hh.ctl.clone()))
            .collect()
    };
    let mut pushed = 0;
    for (aid, ctl) in &targets {
        let _ = ctl.send(ServerMsg::Config { proxies: r.proxies.clone() });
        apply_proxies_for_agent(&s, aid, &r.proxies).await;
        pushed += 1;
    }
    log_ev(&s, format!("desired set for '{hostname}' ({} proxies, pushed {pushed})", r.proxies.len()));
    Json(serde_json::json!({"ok": true, "pushed": pushed})).into_response()
}

/// Reload desired from file: 手改 desired.toml 后点按钮生效（替代重启）。
/// 根因→修法：load 只在启动时调一次，手改文件无感知；本接口重读全量替换内存，
/// 不落盘（文件即源）。坏 TOML 内存不动；坏条跳过、好条生效。
pub(crate) async fn api_desired_reload(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let text = match std::fs::read_to_string(&s.desired_path) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("desired reload failed ({}): {e}", s.desired_path);
            log_ev(&s, format!("desired reload failed: {e}"));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "reason": e.to_string()})),
            )
                .into_response();
        }
    };
    let (fresh, skipped) = match parse_desired_text(&text) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("desired reload failed ({}): {e}", s.desired_path);
            log_ev(&s, format!("desired reload failed: {e}"));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "reason": e})),
            )
                .into_response();
        }
    };
    let reloaded: usize = fresh.values().map(|v| v.len()).sum();
    *s.desired.write().await = fresh.clone();
    // 对在线 agent 按 hostname 推送（复用 api_desired_set 后半段语义，不落盘）
    let mut pushed = 0;
    for (hostname, proxies) in &fresh {
        let targets: Vec<(String, mpsc::UnboundedSender<ServerMsg>)> = {
            s.agents
                .read()
                .await
                .values()
                .filter(|hh| hh.info.hostname == *hostname)
                .map(|hh| (hh.info.agent_id.clone(), hh.ctl.clone()))
                .collect()
        };
        for (aid, ctl) in &targets {
            let _ = ctl.send(ServerMsg::Config { proxies: proxies.clone() });
            apply_proxies_for_agent(&s, aid, proxies).await;
            pushed += 1;
        }
    }
    log_ev(&s, format!("desired reloaded ({reloaded} ok, {skipped} skipped, pushed {pushed})"));
    Json(serde_json::json!({"ok": true, "reloaded": reloaded, "skipped": skipped, "pushed": pushed}))
        .into_response()
}

#[derive(Deserialize)]
pub(crate) struct ToggleReq {
    enabled: bool,
}

/// Enable/disable one proxy by name, then hot-push full list to that agent.
pub(crate) async fn api_toggle(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
    Path((agent, name)): Path<(String, String)>,
    Json(r): Json<ToggleReq>,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let (aid, ctl, proxies) = {
        let mut ag = s.agents.write().await;
        let found = ag.values_mut().find(|hh| {
            hh.info.agent_id == agent || hh.info.hostname == agent
        });
        let Some(hh) = found else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"ok": false, "reason": "no such agent"})),
            )
                .into_response();
        };
        let mut hit = false;
        for p in hh.info.proxies.iter_mut() {
            if p.name == name {
                p.enabled = r.enabled;
                hit = true;
            }
        }
        if !hit {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"ok": false, "reason": "no such proxy"})),
            )
                .into_response();
        }
        (hh.info.agent_id.clone(), hh.ctl.clone(), hh.info.proxies.clone())
    };
    let _ = ctl.send(ServerMsg::Config {
        proxies: proxies.clone(),
    });
    apply_proxies_for_agent(&s, &aid, &proxies).await;
    log_ev(&s, format!("tunnel {agent}/{name} enabled={}", r.enabled));
    Json(serde_json::json!({"ok": true})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_auth_gate() {
        use crate::common::proto::check_basic_auth;
        fn h(auth: Option<&str>) -> http::HeaderMap {
            let mut m = http::HeaderMap::new();
            if let Some(a) = auth {
                m.insert(http::header::AUTHORIZATION, a.parse().unwrap());
            }
            m
        }
        // 没配 = 直接放行
        assert!(check_basic_auth(&h(None), None));
        assert!(check_basic_auth(&h(None), Some("")));
        // 配了：无头/错 scheme/错口令都拒绝，只有精确 user:pass 放行
        let exp = Some("admin:s3cret");
        assert!(!check_basic_auth(&h(None), exp));
        assert!(!check_basic_auth(&h(Some("Bearer xxx")), exp));
        assert!(!check_basic_auth(&h(Some("Basic YWRtaW46d3Jvbmc=")), exp)); // admin:wrong
        assert!(check_basic_auth(&h(Some("Basic YWRtaW46czNjcmV0")), exp)); // admin:s3cret
        // serde 兼容：老配置没 basic_auth 字段也能解析，默认 None
        let p: crate::common::proto::ProxyConfig = serde_json::from_str(
            r#"{"name":"w","type":"http","local_ip":"127.0.0.1","local_port":80,"domains":["a.test"]}"#,
        )
        .unwrap();
        assert_eq!(p.basic_auth, None);
    }

    #[test]
    fn desired_validation() {
        let ok_http = ProxyConfig {
            name: "w".into(),
            ptype: "http".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 80,
            domains: vec!["a.test".into()],
            remote_port: 0,
            set_x_forwarded_proto: None,
            basic_auth: None,
            enabled: true,
        };
        assert!(validate_proxy(&ok_http).is_ok());
        let mut bad = ok_http.clone();
        bad.domains.clear();
        assert!(validate_proxy(&bad).is_err());
        let mut tcp = ok_http.clone();
        tcp.ptype = "tcp".into();
        tcp.domains.clear();
        assert!(validate_proxy(&tcp).is_err());
        tcp.remote_port = 2222;
        assert!(validate_proxy(&tcp).is_ok());
        let mut unk = tcp.clone();
        unk.ptype = "socks".into();
        assert!(validate_proxy(&unk).is_err());
    }

    #[test]
    fn desired_reload_route_beats_hostname_param() {
        // Axum 路由语义：静态段 /api/desired/reload 优先于 /api/desired/:hostname。
        // 本测试锁定 run() 内注册顺序（reload 先于 :hostname）：若有人调换顺序导致
        // reload 被当 hostname 解析，此处即红。旧代码无 reload 路由时 POST 落到
        // :hostname 的 set 分支（行为缺失即红）。
        let src = include_str!("mod.rs");
        let reload_pos = src.find("\"/api/desired/reload\"").expect("reload route exists");
        let param_pos = src.find("\"/api/desired/:hostname\"").expect("hostname route exists");
        assert!(reload_pos < param_pos, "reload must be registered before :hostname");
    }

    #[test]
    fn reload_desired_rejects_bad_toml() {
        assert!(parse_desired_text("[[[broken").is_err());
        assert!(parse_desired_text("agents = 123").is_err());
    }

    #[test]
    fn reload_desired_skips_invalid_entries() {
        let text = "[[agents.e2e]]\nname = \"good\"\ntype = \"tcp\"\nlocal_ip = \"127.0.0.1\"\nlocal_port = 80\nremote_port = 2222\nenabled = true\n\n[[agents.e2e]]\nname = \"bad\"\ntype = \"tcp\"\nlocal_ip = \"127.0.0.1\"\nlocal_port = 80\nremote_port = 0\nenabled = true\n";
        let (fresh, skipped) = parse_desired_text(text).unwrap();
        assert_eq!(skipped, 1);
        assert_eq!(fresh["e2e"].len(), 1);
        assert_eq!(fresh["e2e"][0].name, "good");
    }

    #[test]
    fn server_webui_clarifies_agent_view_ip() {
        // server WebUI 填的是 agent 视角的目标地址，页面必须说清楚，
        // 否则用户会误填 server 本机的 127.0.0.1。
        let html = include_str!("../../web/index.html");
        assert!(html.contains("agent"), "missing agent-perspective hint");
        assert!(html.contains("127.0.0.1 = agent"), "missing loopback hint");
    }

    #[test]
    fn server_webui_checkbox_not_full_width() {
        // .modal input{width:100%} 会把 checkbox 也撑满一行，
        // 必须有 checkbox 例外规则保证对齐。
        let html = include_str!("../../web/index.html");
        assert!(html.contains("type=checkbox") || html.contains("type=\"checkbox\""));
        assert!(html.contains("input[type=checkbox]") || html.contains("input[type=\"checkbox\"]"));
    }

}
