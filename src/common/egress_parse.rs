//! Agent-local HTTP forward proxy request parsing (pure, no IO).
//! 根因→修法：egress 首版只做 HTTP，一切从本地监听读到的请求头开始；
//! CONNECT 与绝对 URI 两种形态在此统一解析成目标 host:port，IO 由 serve 层做。

/// 解析出的代理目标。
pub enum ProxyTarget {
    /// CONNECT 隧道：后续字节全透传。
    Connect { host: String, port: u16 },
    /// 普通 HTTP 绝对 URI：head 原样转发后透传。
    Forward {
        host: String,
        port: u16,
        head: Vec<u8>,
    },
}

fn split_host_port(h: &str) -> (String, u16) {
    match h.rsplit_once(':') {
        Some((hh, p)) => match p.parse::<u16>() {
            Ok(n) => (hh.trim().to_string(), n),
            Err(_) => (h.to_string(), 80),
        },
        None => (h.to_string(), 80),
    }
}

/// 解析代理请求头。返回 (目标, 头长度)。
/// 头不完整（无 \r\n\r\n）返回 None，调用方继续读；
/// 非 CONNECT 且非绝对 URI 返回 None，调用方回 400。
pub fn parse_proxy_request(buf: &[u8]) -> Option<(ProxyTarget, usize)> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = head.lines();
    let req = lines.next()?;
    let mut parts = req.split_whitespace();
    let (m, target) = (parts.next()?, parts.next()?);
    if m.eq_ignore_ascii_case("CONNECT") {
        let (h, p) = split_host_port(target);
        Some((ProxyTarget::Connect { host: h, port: p }, end))
    } else {
        // 普通 HTTP：只接受绝对 URI（GET http://host/path ...）
        let after = target.split("://").nth(1)?;
        let hostport = after.split('/').next()?;
        if hostport.is_empty() {
            return None;
        }
        let (h, p) = split_host_port(hostport);
        Some((
            ProxyTarget::Forward {
                host: h,
                port: p,
                head: buf[..end].to_vec(),
            },
            end,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_with_port() {
        let (t, _) = parse_proxy_request(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        .unwrap();
        assert!(matches!(t, ProxyTarget::Connect{host,port} if host=="example.com" && port==443));
    }

    #[test]
    fn connect_no_port_defaults_80() {
        let (t, _) = parse_proxy_request(b"CONNECT example.com HTTP/1.1\r\n\r\n").unwrap();
        assert!(matches!(t, ProxyTarget::Connect{port:80,..}));
    }

    #[test]
    fn get_absolute_uri() {
        let raw = b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (t, n) = parse_proxy_request(raw).unwrap();
        assert_eq!(n, raw.len());
        assert!(matches!(t, ProxyTarget::Forward{host,port:80,..} if host=="example.com"));
    }

    #[test]
    fn incomplete_returns_none() {
        assert!(parse_proxy_request(b"CONNECT exa").is_none());
    }
}
