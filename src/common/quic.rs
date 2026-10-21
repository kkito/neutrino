//! QUIC transport framing: length-prefixed control frames + dgram-in-stream.
//! Root cause (why not newline-delimited JSON): a payload string containing
//! `\n` or a sticky/half TCP-style read would corrupt the stream; a u32-BE
//! length prefix makes framing unambiguous. QUIC streams are already reliable
//! and ordered, so `read_exact(len)` closes the half-packet gap.
use std::fmt;

#[derive(Debug, Clone)]
pub enum Transport {
    Ws(String),
    Quic { host: String, port: u16 },
    Kudus { host: String, port: u16 },
    Invalid,
}

pub const CONTROL_MAX: usize = 1_048_576;
pub const DGRAM_MAX: usize = 65527;

#[derive(Debug)]
pub struct FrameError(pub String);

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for FrameError {}

pub fn encode_frame(json: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + json.len());
    v.extend_from_slice(&(json.len() as u32).to_be_bytes());
    v.extend_from_slice(json);
    v
}

pub fn encode_frame_checked(json: &[u8]) -> Result<Vec<u8>, FrameError> {
    if json.len() > CONTROL_MAX {
        return Err(FrameError("control frame too large".into()));
    }
    Ok(encode_frame(json))
}

/// returns (complete payload frames, consumed bytes)
pub fn decode_frames(buf: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut out = Vec::new();
    let mut off = 0;
    while buf.len() - off >= 4 {
        let len =
            u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        if len > CONTROL_MAX {
            break; // malicious: stop, caller closes conn
        }
        if buf.len() - off - 4 < len {
            break; // half packet
        }
        out.push(buf[off + 4..off + 4 + len].to_vec());
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
    if payload.len() > DGRAM_MAX {
        return Err(FrameError("dgram too large".into()));
    }
    Ok(encode_dgram(payload))
}

pub fn decode_dgram(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() - 2 < len {
        return None;
    }
    Some((&buf[2..2 + len], 2 + len))
}

pub fn parse_server_url(url: &str) -> Transport {
    if url.starts_with("ws://") || url.starts_with("wss://") {
        return Transport::Ws(url.to_string());
    }
    if let Some(rest) = url.strip_prefix("quic://") {
        let rest = rest.trim_end_matches('/');
        if let Some((h, p)) = rest.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                if !h.is_empty() && port != 0 {
                    return Transport::Quic {
                        host: h.to_string(),
                        port,
                    };
                }
            }
        }
    }
    if let Some(rest) = url.strip_prefix("kudus://") {
        let rest = rest.trim_end_matches('/');
        if let Some((h, p)) = rest.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                if !h.is_empty() && port != 0 {
                    return Transport::Kudus {
                        host: h.to_string(),
                        port,
                    };
                }
            }
        }
    }
    Transport::Invalid
}

/// 解析 kudus/quic 上行地址：IP 字面量直解，域名走 DNS。
/// 根因→修法：旧代码 "{host}:{port}".parse::<SocketAddr>() 遇域名直接 bail
/// （macmini 配 kudus://hk.kkito.cn 会话 0 秒结束，2026-10-22 现场）。
pub async fn resolve_server_addr(host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    use tokio::net::lookup_host;
    lookup_host(format!("{host}:{port}"))
        .await?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("no address for {host}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_sticky_and_half() {
        let a = encode_frame(br#"{"t":"ping","ts":1}"#);
        let b = encode_frame(br#"{"t":"pong","ts":2}"#);
        let mut sticky = Vec::new();
        sticky.extend_from_slice(&a);
        sticky.extend_from_slice(&b);
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
        let hdr = (CONTROL_MAX as u32 + 1).to_be_bytes().to_vec();
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

    #[tokio::test]
    async fn resolve_server_addr_ip_and_hostname() {
        // 根因→修法：kudus/quic session 用 "{host}:{port}".parse::<SocketAddr>()，
        // 域名（如 hk.kkito.cn）直接 bail，会话 0 秒结束（macmini 2026-10-22 现场）。
        // IP 字面量保持直解，域名走 DNS。
        let a = resolve_server_addr("127.0.0.1", 36182).await.unwrap();
        assert_eq!(a.to_string(), "127.0.0.1:36182");
        let b = resolve_server_addr("localhost", 36182).await.unwrap();
        assert_eq!(b.port(), 36182);
        assert!(resolve_server_addr("nonexistent.invalid.", 36182).await.is_err());
    }

    #[test]
    fn parse_transport_by_scheme() {
        assert!(matches!(
            parse_server_url("ws://127.0.0.1:7440/ws"),
            Transport::Ws(_)
        ));
        assert!(matches!(
            parse_server_url("wss://tunnel.nat.kkito.cn:7443/ws"),
            Transport::Ws(_)
        ));
        let Transport::Quic { host, port } = parse_server_url("quic://127.0.0.1:7444")
        else {
            panic!("quic")
        };
        assert_eq!((host.as_str(), port), ("127.0.0.1", 7444));
        assert!(matches!(
            parse_server_url("http://x/"),
            Transport::Invalid
        ));
    }
}
