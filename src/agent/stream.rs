//! agent 流泵：HTTP 响应泵 + chunked 编解码纯函数 + idle 收尾。
use crate::common::proto::*;
use super::session::Ctx;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::Message;

pub(crate) async fn http_response_pump(ctx: Arc<Ctx>, sid: u32, mut lr: tokio::net::tcp::OwnedReadHalf) {
    use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::Message;
    let mut b = vec![0u8; 32 * 1024];
    // 首包：必须含完整响应头，否则按裸流透传
    let mut head = vec![];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), lr.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(n)) => {
                head.extend_from_slice(&b[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if head.len() > 64 * 1024 {
                    break; // 头过大：兜底裸流
                }
            }
        }
    }
    let hpos = head.windows(4).position(|w| w == b"\r\n\r\n");
    let (hlen, body_prefix) = match hpos {
        Some(i) => (i + 4, head[i + 4..].to_vec()),
        None => {
            let _ = ctx.out.send(Message::Binary(encode_data(sid, &head).into()));
            stream_body_until_idle(ctx.clone(), sid, &mut lr).await;
            return;
        }
    };
    let hdr_txt = String::from_utf8_lossy(&head[..hlen]);
    let is_chunked = hdr_txt.lines().any(|l| {
        matches!(l.split_once(':'), Some((k, v))
            if k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.to_lowercase().contains("chunked"))
    });
    if is_chunked {
        // chunked：解码成纯 body，改写响应头（去 TE，加 Content-Length）再发。
        // client 看到的就是普通定长响应，尾部不再有 `0`。
        let mut buf = body_prefix;
        let body = loop {
            if let Some((body, _)) = try_decode_chunked(&buf) {
                break body;
            }
            match tokio::time::timeout(std::time::Duration::from_secs(10), lr.read(&mut b)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break greedy_decode_chunked(&buf),
                Ok(Ok(n)) => buf.extend_from_slice(&b[..n]),
            }
            if buf.len() > 32 * 1024 * 1024 + 65536 {
                break greedy_decode_chunked(&buf);
            }
        };
        let fixed_head = rewrite_chunked_head(&head[..hlen], body.len());
        let _ = ctx.out.send(Message::Binary(encode_data(sid, &fixed_head).into()));
        let _ = ctx.out.send(Message::Binary(encode_data(sid, &body).into()));
        return;
    }
    if hdr_txt.lines().any(|l| {
        matches!(l.split_once(':'), Some((k, v))
            if k.trim().eq_ignore_ascii_case("connection")
                && v.to_lowercase().contains("close"))
    }) {
        // connection: close：先发头（server 靠首包解析状态行），再靠 EOF 收尾。
        let _ = ctx.out.send(Message::Binary(encode_data(sid, &head[..hlen]).into()));
        if !body_prefix.is_empty() {
            let _ = ctx.out.send(Message::Binary(encode_data(sid, &body_prefix).into()));
        }
        stream_body_until_idle(ctx.clone(), sid, &mut lr).await;
        return;
    }
    let want: usize = content_length(&hdr_txt).unwrap_or(0);
    // 定长响应：先发头 + 已读 body 前缀，server 首包即解析出状态行。
    let _ = ctx.out.send(Message::Binary(encode_data(sid, &head[..hlen]).into()));
    if !body_prefix.is_empty() {
        let _ = ctx.out.send(Message::Binary(encode_data(sid, &body_prefix).into()));
    }
    let mut got = body_prefix.len();
    let mut extra = want.saturating_sub(got);
    while extra > 0 {
        match tokio::time::timeout(std::time::Duration::from_secs(10), lr.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                if ctx.out.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                    break;
                }
                got += n;
                extra = want.saturating_sub(got);
            }
        }
    }
}

/// 从响应头文本提取 Content-Length（无则 None）。
fn content_length(hdr: &str) -> Option<usize> {
    hdr.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("content-length") {
            v.trim().parse::<usize>().ok()
        } else {
            None
        }
    })
}

/// 从 chunked body 字节流尝试解出一整个响应（prefix+后续累计）。
/// 成功返回 (解码后body, 消耗字节数)；数据不全返回 None（继续读网）。
/// 失败（非法块头）返回 Some((原样, len))：兜底透传，不卡死。
fn try_decode_chunked(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut out: Vec<u8> = vec![];
    let mut pos = 0;
    loop {
        let rel = buf[pos..].windows(2).position(|w| w == b"\r\n")?;
        let line_end = pos + rel;
        let line = std::str::from_utf8(&buf[pos..line_end]).ok()?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).ok()?;
        if size > 16 * 1024 * 1024 {
            return Some((buf.to_vec(), buf.len())); // 超大：兜底透传
        }
        if size == 0 {
            // 0-chunk + trailer 空行：trailer 不要（client 不需要）。
            // 逐行消费直到空行（含空行自身的 CRLF），消耗字节数必须
            // 等于 framing 全长，否则调用方按“不全”继续读网会 hang。
            let mut t = line_end + 2;
            loop {
                let rel2 = buf[t..].windows(2).position(|w| w == b"\r\n")?;
                let le = t + rel2;
                if rel2 == 0 {
                    t = le + 2; // 空行：`0\r\n\r\n` 极简结尾也走这里
                    break;
                }
                t = le + 2;
                if t - (line_end + 2) > 8192 {
                    break; // trailer 过长：丢弃收尾
                }
            }
            return Some((out, t));
        }
        let data_start = line_end + 2;
        let data_end = data_start.checked_add(size)?;
        if buf.len() < data_end + 2 {
            return None; // 块数据还没收齐
        }
        if &buf[data_end..data_end + 2] != b"\r\n" {
            return Some((buf.to_vec(), buf.len())); // 格式坏：兜底透传
        }
        out.extend_from_slice(&buf[data_start..data_end]);
        pos = data_end + 2;
        if out.len() > 32 * 1024 * 1024 {
            return Some((out, pos)); // 超预算：有多少发多少并收尾
        }
    }
}

/// 把 chunked 响应头改写成定长：删 Transfer-Encoding，加 Content-Length。
/// 这样 client 收到的就是普通响应，不会再看到 chunk framing 的 `0`。
fn rewrite_chunked_head(head: &[u8], body_len: usize) -> Vec<u8> {
    let txt = String::from_utf8_lossy(head);
    let mut lines: Vec<String> = vec![];
    for (i, l) in txt.lines().enumerate() {
        if i == 0 {
            lines.push(l.to_string());
            continue;
        }
        let Some((k, _)) = l.split_once(':') else { continue };
        if k.trim().eq_ignore_ascii_case("transfer-encoding")
            || k.trim().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        lines.push(l.to_string());
    }
    lines.push(format!("content-length: {body_len}"));
    let mut out = lines.join("\r\n").into_bytes();
    out.extend_from_slice(b"\r\n\r\n");
    out
}

/// 尽力解：framing 不全时把已收齐的块拼出来（收尾用）。
fn greedy_decode_chunked(buf: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    let mut pos = 0;
    while let Some(rel) = buf[pos..].windows(2).position(|w| w == b"\r\n") {
        let line_end = pos + rel;
        let Ok(line) = std::str::from_utf8(&buf[pos..line_end]) else { break };
        let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16) else { break };
        if size == 0 {
            break;
        }
        let ds = line_end + 2;
        let Some(de) = ds.checked_add(size) else { break };
        if buf.len() < de {
            break;
        }
        out.extend_from_slice(&buf[ds..de]);
        pos = de + 2;
        if pos > buf.len() {
            break;
        }
    }
    out
}

/// 流式透传直到后端 EOF 或 5s 读空闲（chunked/close 连接的收尾方式）。
pub(crate) async fn stream_body_until_idle(ctx: Arc<Ctx>, sid: u32, lr: &mut tokio::net::tcp::OwnedReadHalf) {
    let mut b = vec![0u8; 32 * 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), lr.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                if ctx.out.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                    break;
                }
            }
        }
    }
}

/// UDP over stream: each Binary frame = one datagram. Agent dials a connected
/// UDP socket to local_ip:local_port and shuttles datagrams both ways.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_body_decodes_fully_before_forward() {
        // RED: chunked framing（块大小行/`0` 结束块）绝不能透传给 client。
        // 现场：server 剥掉 Transfer-Encoding 头后按裸流转发，agent 若原样
        // 转发 chunk framing，curl 尾部就会多出 `0`（外加块大小行污染 body）。
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = super::try_decode_chunked(raw);
        assert_eq!(r, Some((b"hello world".to_vec(), raw.len())));
        // 不完整的不消费，继续等网
        assert_eq!(super::try_decode_chunked(b"5\r\nhel"), None);
        // 带扩展名 + trailer 也要解
        let raw2 = b"5;ext=1\r\nhello\r\n0\r\nX-T: 1\r\n\r\n";
        let r2 = super::try_decode_chunked(raw2);
        assert_eq!(r2, Some((b"hello".to_vec(), raw2.len())));
        // 改写头：去 TE、补 Content-Length，首行保留
        let h = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n";
        let fixed = super::rewrite_chunked_head(h, 11);
        let ft = String::from_utf8_lossy(&fixed);
        assert!(ft.contains("content-length: 11"));
        assert!(!ft.to_lowercase().contains("transfer-encoding"));
        assert!(ft.starts_with("HTTP/1.1 200 OK"));
    }

}
