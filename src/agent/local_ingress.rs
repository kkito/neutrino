//! agent 本地 HTTP 入口：内网 `http://<name><suffix>` 直访名下 http 隧道。
//! 转发面见 Task 2；本文件先落纯函数（单测锁定）。

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

    #[test]
    fn directory_page_lists_names_without_secrets() {
        let (code, body) = directory_page(&["web".into(), "sec".into()]);
        assert_eq!(code, 404);
        let s = String::from_utf8(body).unwrap();
        assert!(s.contains("web") && s.contains("sec"));
        assert!(!s.contains("token") && !s.contains("wss://") && !s.contains("kudus://"));
    }
}
