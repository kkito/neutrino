//! agent 流泵：HTTP 响应泵 + chunked 编解码纯函数 + idle 收尾。
//! 发送端经 `Sender` 抽象：WSS 用 WsSender（Message），QUIC 用 QuicSender（复用帧）。
use crate::common::proto::*;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// 发包器：agent 数据泵的发送端抽象（WSS 发 Message，QUIC 发 control 复用帧）。
/// 根因→修法：WSS `out: UnboundedSender<Message>` 与 QUIC `out: UnboundedSender<Vec<u8>>`
/// 类型不同，泵逻辑相同——`Sender` 统一 `data/ctrl/close` 三种发送，两种传输各实现一次。
pub(crate) trait Sender: Clone + Send + 'static {
    fn send_data(&self, sid: u32, chunk: &[u8]);
    #[allow(dead_code)]
    fn send_ctrl(&self, m: &ClientMsg);
    #[allow(dead_code)]
    fn send_close(&self, sid: u32, reason: &str) {
        self.send_ctrl(&ClientMsg::Close { stream: sid, reason: reason.into() });
    }
}

#[derive(Clone)]
pub(crate) struct WsSender(pub(crate) mpsc::UnboundedSender<Message>);

impl Sender for WsSender {
    fn send_data(&self, sid: u32, chunk: &[u8]) {
        let _ = self.0.send(Message::Binary(encode_data(sid, chunk).into()));
    }
    fn send_ctrl(&self, m: &ClientMsg) {
        if let Ok(j) = serde_json::to_string(m) {
            let _ = self.0.send(Message::Text(j.into()));
        }
    }
}

#[derive(Clone)]
pub(crate) struct QuicSender(pub(crate) mpsc::UnboundedSender<Vec<u8>>);
impl Sender for QuicSender {
    fn send_data(&self, sid: u32, chunk: &[u8]) {
        use crate::common::quic::{encode_dgram, encode_frame};
        // 与下行对称：一律套 dgram 帧，server 侧按 split_payload(.., true) 拆。
        // 根因→修法：旧版裸发 encode_data，server 读循环无条件试 decode_dgram，
        // 上行 TLS 字节前 2 字节被当长度吞掉（HTTPS 大响应必挂）。
        let _ = self
            .0
            .send(encode_frame(&encode_data(sid, &encode_dgram(chunk))));
    }
    fn send_ctrl(&self, m: &ClientMsg) {
        use crate::common::quic::encode_frame;
        if let Ok(j) = serde_json::to_vec(m) {
            let _ = self.0.send(encode_frame(&j));
        }
    }
}

/// kudus 发送端：包 [`Pkt`] 封帧（每包独立加密 datagram），泵逻辑与 WSS/QUIC 同构。
/// 根因→修法：`http_response_pump` 只依赖 `Sender`，kudus 只需实现一次即复用三分支。
#[derive(Clone)]
pub(crate) struct KudusSender(pub(crate) crate::agent::kudus_session::Pkt);

impl Sender for KudusSender {
    fn send_data(&self, sid: u32, chunk: &[u8]) {
        // http_response_pump/egress/link 的 TCP 字节流：逐片发（见 send_data_stream 注释）。
        // 注意：Sender trait 是同步的，背压不能在此做——由各泵 task 在调 send 前
        // wait_window().await（异步让出，不卡 reactor）；此处只管切分发送。
        self.0.send_data_stream(sid, chunk);
    }
    fn send_ctrl(&self, m: &ClientMsg) {
        let _ = self.0.send_ctrl(m);
    }
}

pub(crate) async fn http_response_pump<S: Sender>(tx: S, sid: u32, mut lr: tokio::net::tcp::OwnedReadHalf) {
    use tokio::io::AsyncReadExt as _;
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
            tx.send_data(sid, &head);
            stream_body_until_idle(tx.clone(), sid, &mut lr).await;
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
        tx.send_data(sid, &fixed_head);
        // 根因→修法：旧版把整个 body 当一包 `send_data`，超过 dgram 的 u16
        // 长度上限（65535）就溢出成伪随机长度，接收端按错长度拆包 → 截断
        // （2026-10-25 现场：同样 300KB 三跑得 157785/168783/238625）。
        // 定长分支（下方）本就 32KB 一片，这里对齐成同一分片大小。
        for piece in body.chunks(32 * 1024) {
            tx.send_data(sid, piece);
        }
        return;
    }
    if hdr_txt.lines().any(|l| {
        matches!(l.split_once(':'), Some((k, v))
            if k.trim().eq_ignore_ascii_case("connection")
                && v.to_lowercase().contains("close"))
    }) {
        // connection: close：先发头（server 靠首包解析状态行），再靠 EOF 收尾。
        tx.send_data(sid, &head[..hlen]);
        if !body_prefix.is_empty() {
            tx.send_data(sid, &body_prefix);
        }
        stream_body_until_idle(tx.clone(), sid, &mut lr).await;
        return;
    }
    let want: usize = content_length(&hdr_txt).unwrap_or(0);
    // 定长响应：先发头 + 已读 body 前缀，server 首包即解析出状态行。
    tx.send_data(sid, &head[..hlen]);
    if !body_prefix.is_empty() {
        tx.send_data(sid, &body_prefix);
    }
    let mut got = body_prefix.len();
    let mut extra = want.saturating_sub(got);
    while extra > 0 {
        match tokio::time::timeout(std::time::Duration::from_secs(10), lr.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                tx.send_data(sid, &b[..n]);
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
pub(crate) async fn stream_body_until_idle<S: Sender>(tx: S, sid: u32, lr: &mut tokio::net::tcp::OwnedReadHalf) {
    use tokio::io::AsyncReadExt as _;
    let mut b = vec![0u8; 32 * 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), lr.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                tx.send_data(sid, &b[..n]);
            }
        }
    }
}

/// UDP over stream: each Binary frame = one datagram. Agent dials a connected
/// UDP socket to local_ip:local_port and shuttles datagrams both ways.

#[cfg(test)]
mod tests {
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
