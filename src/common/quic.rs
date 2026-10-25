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
    // 防御：u16 长度前缀装不下 >65535 的包。旧版直接 `as u16` 溢出成伪随机
    // 长度（300000 as u16 = 41248），接收端按错长度拆包 → 大响应每次截断
    // 的字节数都不一样（现场：157785 / 168783 / 238625 三跑三值）。
    // 这里硬截断到 DGRAM_MAX，并保证调用方不该单包发这么大的片。
    let payload = if payload.len() > DGRAM_MAX {
        tracing::warn!(
            "encode_dgram: payload {} > DGRAM_MAX {}, truncating",
            payload.len(),
            DGRAM_MAX
        );
        &payload[..DGRAM_MAX]
    } else {
        payload
    };
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

/// 拆一个 QUIC 数据帧的 payload 为若干片段。
///
/// 背景（根因）：QUIC 数据帧内层既要承载 UDP 单包边界，也要承载任意 TCP/TLS
/// 字节流。旧实现在两端都「先试 decode_dgram，失败才当裸字节」——这对 TCP 是
/// 灾难：TLS 记录头 `16 03 03 00 7a ...` 前两字节 `0x1603` 被读成长度 5635，
/// 于是前 2 字节被吞掉、后续整段错位，curl 报 `wrong version number`
/// （2026-10-25 实测：HTTPS 响应 >10KB 必挂，plain HTTP 却全好）。
///
/// 修法：把「是否套了 dgram 帧」变成帧内的显式标记，不再靠猜测。
/// `udp == true` 表示发送方用 encode_dgram 逐包封装过，按 dgram 帧拆；
/// `udp == false` 表示裸字节流，整段原样返回（绝不动前两个字节）。
pub fn split_payload(payload: &[u8], udp: bool) -> Vec<&[u8]> {
    if !udp {
        return if payload.is_empty() { Vec::new() } else { vec![payload] };
    }
    let mut out = Vec::new();
    let mut off = 0;
    while let Some((dg, used)) = decode_dgram(&payload[off..]) {
        off += used;
        out.push(dg);
    }
    if out.is_empty() {
        // 标记为 udp 但拆不出完整 dgram 帧：按单片透传，不丢数据。
        out.push(payload);
    }
    out
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
    fn encode_dgram_never_truncates_silently() {
        // 回归：u16 长度前缀对 >65535 的 payload 会溢出成伪随机长度
        // （300000 as u16 == 41248），接收端按错长度拆包，导致每次截断
        // 的字节数都不一样。这里锁定：超限必被截到 DGRAM_MAX。
        let big = vec![0x5Au8; 300_000];
        let framed = encode_dgram(&big);
        assert!(framed.len() <= DGRAM_MAX + 2);
        let (body, _) = decode_dgram(&framed).expect("truncated frame must still parse");
        assert_eq!(body.len(), DGRAM_MAX);
    }

    #[test]
    fn split_payload_never_swallows_tcp_bytes() {
        // 回归：QUIC 下行 HTTPS 响应。TLS 记录头 `16 03 03 00 7a ...` 前两字节
        // 0x1603=5635 曾被旧代码（无条件 decode_dgram）读成长度，导致前 2 字节被吞、
        // 整段错位。现场：curl -x 查 1MB → curl: (56) wrong version number；
        // kudus 同目标 200/1000000 正常。断言：非 udp 帧必须原样返回。
        let mut tls = vec![0x16, 0x03, 0x03, 0x00, 0x7a];
        tls.extend(std::iter::repeat(0xAB).take(6000));
        let parts = split_payload(&tls, false);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], &tls[..], "TCP 字节一个都不能动");
    }

    #[test]
    fn split_payload_splits_dgram_only_when_flagged_udp() {
        let mut two = Vec::new();
        two.extend_from_slice(&encode_dgram(b"aaa"));
        two.extend_from_slice(&encode_dgram(b"bbbb"));
        assert_eq!(split_payload(&two, true), vec![&b"aaa"[..], &b"bbbb"[..]]);
        // 同样字节若标记为非 udp，就是一个整段。
        assert_eq!(split_payload(&two, false), vec![&two[..]]);
    }

    #[test]
    fn split_payload_udp_falls_back_when_dgram_incomplete() {
        // 标记 udp 但给的是一段拆不出完整 dgram 帧的数据：不能静默丢弃。
        let junk = [0x00, 0x09, 0x01]; // 声明 9 字节，实得 1 字节
        assert_eq!(split_payload(&junk, true), vec![&junk[..]]);
        assert!(split_payload(&[], false).is_empty());
    }

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
