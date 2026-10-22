//! kudus 传输：自研 UDP 可靠传输，全随机隐身。
//! 包格式：`[session 4B BE 明文][nonce 24B 随机][XChaCha20-Poly1305 密文+16B tag]`。
//! key = SHA256(token)，两边预共享，无协商、无证书、无 TLS。
//! 明文（解密后）= `[ver 1B|flags 1B|seq 4B BE|ack 4B BE|sack 32B|ts_ms 8B BE][proto_frame]`。
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// v1 重传超时：固定 200ms（设计 RTO=max(200ms,2×SRTT)，SRTT 度量 v2 再做）。
pub const KUDUS_RTO: Duration = Duration::from_millis(200);
/// 重排/重传缓冲上限：防对端疯发撑爆内存（超了丢新包，等重传补）。
pub const KUDUS_WINDOW: usize = 512;

/// kudus 看门狗阈值：75s 无任何帧即判死（server/agent 双端共用）。
/// 根因→修法：WSS 的 45s 按"3×15s server Ping"算；kudus agent 上行最坏 30s 一包，
/// 45s 只容忍丢 1 包，75s 容忍连丢 2 包不误踢。WSS 的 IDLE_KICK_SECS 不动。
pub const KUDUS_IDLE_KICK_SECS: i64 = 75;

/// 心跳间隔状态机：慢档 15~30s 随机（防多 agent 对齐惊群 + NAT 保活），
/// 丢包进快档 5~8s 随机，回慢档需连续 3 周期无丢包（迟滞防翻转）。
/// 纯计算 + 计数器，可单测；`lossy` 由调用方传 `retx 非空`。
pub struct Heartbeat {
    fast: bool,
    calm_hit: u8,
}

impl Heartbeat {
    pub fn new() -> Self {
        Self { fast: false, calm_hit: 0 }
    }
    pub fn is_fast(&self) -> bool {
        self.fast
    }
    pub fn next_interval(&mut self, lossy: bool) -> Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        if lossy {
            self.fast = true;
            self.calm_hit = 0;
            Duration::from_secs(rng.gen_range(5..=8))
        } else if self.fast {
            self.calm_hit += 1;
            if self.calm_hit >= 3 {
                self.fast = false;
                self.calm_hit = 0;
                Duration::from_secs(rng.gen_range(15..=30))
            } else {
                Duration::from_secs(rng.gen_range(5..=8))
            }
        } else {
            Duration::from_secs(rng.gen_range(15..=30))
        }
    }
}

/// 纯判定：now-last_seen 超 75s 即僵尸（kudus 版；WSS 用 state::is_idle_stale 45s，不动）。
pub fn kudus_idle_stale(last_seen_unix: i64, now_unix: i64) -> bool {
    now_unix - last_seen_unix > KUDUS_IDLE_KICK_SECS
}

/// 接收重排缓冲：按 seq 有序投递，洞后包缓存等待补洞。
/// 根因→修法：v1 到包即投，跨机丢包即永久少一块（avatar/blob 截断），必须缓存等补齐。
pub struct ReorderBuf {
    next: u32,
    buf: HashMap<u32, Vec<u8>>,
}

impl ReorderBuf {
    pub fn new(next: u32) -> Self {
        Self { next, buf: HashMap::new() }
    }
    /// 到包：返回可按序投递的 payload。重复/过旧/超窗返回空。
    pub fn push(&mut self, seq: u32, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        // 过旧/重复：已投过（next 之前）或已缓存
        if seq.wrapping_sub(self.next) >= 0x8000_0000 || self.buf.contains_key(&seq) {
            return out;
        }
        if self.buf.len() >= KUDUS_WINDOW {
            return out; // 超窗丢新包（对端重传会补）
        }
        self.buf.insert(seq, payload);
        while let Some(p) = self.buf.remove(&self.next) {
            out.push(p);
            self.next = self.next.wrapping_add(1);
        }
        out
    }
    /// 最高连续已收 seq（ACK 累积基）。
    pub fn ack(&self) -> u32 {
        self.next.wrapping_sub(1)
    }
    /// 已缓存乱序包的 SACK bitmap（基为 ack()）。
    pub fn sack(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        let base = self.ack();
        for k in self.buf.keys() {
            sack_mark(&mut s, base, *k);
        }
        s
    }
}

/// 发送重传缓冲：on_send 记 seq→(payload, sent_ms)；on_ack 按累积+SACK 清；
/// take_expired 吐超时未确认包（调用方原样重发并刷新计时）。
pub struct RetxBuf {
    next: u32,
    seqs: HashMap<u32, (Vec<u8>, u64)>,
}

impl RetxBuf {
    pub fn new(start: u32) -> Self {
        Self { next: start, seqs: HashMap::new() }
    }
    /// 登记一次发送，返回分配的 seq。
    pub fn on_send(&mut self, payload: Vec<u8>) -> u32 {
        let s = self.next;
        self.next = self.next.wrapping_add(1);
        self.seqs.insert(s, (payload, now_ms()));
        s
    }
    /// 对端 ACK：清累积确认（<=ack）+ SACK 洞外已到包。
    pub fn on_ack(&mut self, ack: u32, sack: &[u8; 32]) {
        self.seqs.retain(|&seq, _| {
            if seq == ack || ack.wrapping_sub(seq) < 0x8000_0000 {
                return false; // 累积确认覆盖
            }
            let d = seq.wrapping_sub(ack);
            if d >= 1 && d <= KUDUS_SACK_BITS as u32 {
                let i = (d - 1) as usize;
                if sack[i / 8] & (1 << (i % 8)) != 0 {
                    return false; // SACK 已到
                }
            }
            true
        });
    }
    /// 取出超时未确认包（刷新其计时防连爆），按 seq 排序。
    pub fn take_expired(&mut self, rto: Duration, now: u64) -> Vec<(u32, Vec<u8>)> {
        let mut due: Vec<(u32, Vec<u8>)> = Vec::new();
        for (seq, (p, sent)) in self.seqs.iter_mut() {
            if now.wrapping_sub(*sent) >= rto.as_millis() as u64 {
                *sent = now;
                due.push((*seq, p.clone()));
            }
        }
        due.sort_by_key(|(s, _)| *s);
        due
    }
    pub fn is_empty(&self) -> bool {
        self.seqs.is_empty()
    }
    pub fn len(&self) -> usize {
        self.seqs.len()
    }
}

/// 单个 UDP datagram 载荷上限（防 IP 分片）。
/// server 下行单流切片上限：proto_frame 预算 ≈1140B（见 KUDUS_MAX_UDP）。
/// UDP 上行由 [`Pkt::send_udp`] 另行限长，此处只管 TCP/HTTP/egress/link 字节流。
pub const KUDUS_DATA_CHUNK: usize = 1000;
/// 单 datagram 上限：以太网 MTU 内，避免 IP 分片（分片=特征+丢包放大）。
pub const KUDUS_MAX_UDP: usize = 1232;
/// SACK bitmap 位数（乱序窗口）。
pub const KUDUS_SACK_BITS: usize = 256;

pub const FLAG_SYN: u8 = 0x01;
pub const FLAG_ACK: u8 = 0x02;
pub const FLAG_FIN: u8 = 0x04;
pub const FLAG_DATA: u8 = 0x08;

/// 定长包头（密文内）：1+1+4+4+32+8 = 50B。
pub const HDR_LEN: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KudusHdr {
    pub ver: u8,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub sack: [u8; 32],
    pub ts_ms: u64,
}

pub fn encode_hdr(h: &KudusHdr) -> [u8; HDR_LEN] {
    let mut b = [0u8; HDR_LEN];
    b[0] = h.ver;
    b[1] = h.flags;
    b[2..6].copy_from_slice(&h.seq.to_be_bytes());
    b[6..10].copy_from_slice(&h.ack.to_be_bytes());
    b[10..42].copy_from_slice(&h.sack);
    b[42..50].copy_from_slice(&h.ts_ms.to_be_bytes());
    b
}

pub fn decode_hdr(b: &[u8]) -> Option<(KudusHdr, &[u8])> {
    if b.len() < HDR_LEN {
        return None;
    }
    let mut sack = [0u8; 32];
    sack.copy_from_slice(&b[10..42]);
    let h = KudusHdr {
        ver: b[0],
        flags: b[1],
        seq: u32::from_be_bytes([b[2], b[3], b[4], b[5]]),
        ack: u32::from_be_bytes([b[6], b[7], b[8], b[9]]),
        sack,
        ts_ms: u64::from_be_bytes([
            b[42], b[43], b[44], b[45], b[46], b[47], b[48], b[49],
        ]),
    };
    Some((h, &b[HDR_LEN..]))
}

/// key = SHA256(token)：两边事先约定，包里不传任何密钥材料。
pub fn derive_key(token: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(token.as_bytes()).into()
}

pub fn seal(key: &[u8; 32], nonce24: &[u8; 24], plain: &[u8]) -> Vec<u8> {
    use chacha20poly1305::{AeadInPlace, Key, KeyInit, XChaCha20Poly1305};
    use chacha20poly1305::aead::generic_array::GenericArray;
    let c = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut buf = plain.to_vec();
    c.encrypt_in_place(GenericArray::from_slice(nonce24), b"", &mut buf)
        .expect("xchacha seal");
    buf
}

/// tag 失败返回 None：调用方静默丢包（黑洞），不回包、不记 warn。
pub fn open(key: &[u8; 32], nonce24: &[u8; 24], cipher_tag: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::{AeadInPlace, Key, KeyInit, XChaCha20Poly1305};
    use chacha20poly1305::aead::generic_array::GenericArray;
    let c = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut buf = cipher_tag.to_vec();
    c.decrypt_in_place(GenericArray::from_slice(nonce24), b"", &mut buf)
        .ok()?;
    Some(buf)
}

/// `[session 4B BE][nonce 24B][cipher...]`。调用方先 seal 得到 cipher。
pub fn encode_packet(session: u32, nonce24: &[u8; 24], cipher: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 24 + cipher.len());
    v.extend_from_slice(&session.to_be_bytes());
    v.extend_from_slice(nonce24);
    v.extend_from_slice(cipher);
    v
}

/// 最小 28B，否则 None（短包直接丢）。
pub fn decode_packet(buf: &[u8]) -> Option<(u32, &[u8; 24], &[u8])> {
    if buf.len() < 28 {
        return None;
    }
    let session = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let nonce: &[u8; 24] = buf[4..28].try_into().ok()?;
    Some((session, nonce, &buf[28..]))
}

/// SACK：在以 base_ack 为基的 256 位 bitmap 里标 seq 已到（bit i = base_ack+1+i）。
pub fn sack_mark(sack: &mut [u8; 32], base_ack: u32, seq: u32) {
    let d = seq.wrapping_sub(base_ack);
    if d == 0 || d > KUDUS_SACK_BITS as u32 {
        return;
    }
    let i = (d - 1) as usize;
    sack[i / 8] |= 1 << (i % 8);
}

/// 上下行 seq 域隔离：server 下行 seq 从此起跳，agent 上行帧（Open/Close/Register/Ping）
/// 永远落不到下行重排窗口里。根因→修法：此前两端各从 1 自增，agent 读泵以 server
/// 下行首包为 next，上行控制帧 seq 恰好命中下行窗口被当重排序丢弃，Open 永不到。
pub const KUDUS_SEQ_GAP: u32 = 1 << 30;
/// SACK 查洞：base_ack+1..base_ack+window 内未置位的 seq 列表（需重传）。
pub fn sack_missing(sack: &[u8; 32], base_ack: u32, window: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let n = window.min(KUDUS_SACK_BITS as u32);
    for i in 0..n {
        if sack[(i / 8) as usize] & (1 << (i % 8)) == 0 {
            out.push(base_ack + 1 + i);
        }
    }
    out
}

pub fn fresh_nonce() -> [u8; 24] {
    use rand::RngCore;
    let mut n = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_slow_fast_hysteresis() {
        // 根因→修法：固定 30s 心跳多 agent 对齐惊群；丢包无加密。慢档 15~30s 随机，
        // 丢包进快档 5~8s，回慢档需 3 连好（防翻转）。
        let mut hb = super::Heartbeat::new();
        assert!(!hb.is_fast());
        for _ in 0..20 {
            let d = hb.next_interval(false);
            assert!(d >= std::time::Duration::from_secs(15) && d <= std::time::Duration::from_secs(30));
            assert!(!hb.is_fast());
        }
        let d = hb.next_interval(true); // 丢 1 包即进快档
        assert!(hb.is_fast());
        assert!(d >= std::time::Duration::from_secs(5) && d <= std::time::Duration::from_secs(8));
        hb.next_interval(false);
        hb.next_interval(false);
        assert!(hb.is_fast()); // 2 连好仍在快档
        hb.next_interval(false);
        assert!(!hb.is_fast()); // 3 连好回慢档
    }

    #[test]
    fn kudus_idle_kick_threshold() {
        // 看门狗 75s：容忍连丢 2 包（最坏 30s 间隔 + 1 次丢包不误踢）。
        assert!(super::kudus_idle_stale(0, 76));
        assert!(!super::kudus_idle_stale(0, 75));
        assert!(!super::kudus_idle_stale(100, 105));
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = derive_key("s3cret");
        let n = fresh_nonce();
        let c = seal(&k, &n, b"hello-kudus");
        let p = open(&k, &n, &c).unwrap();
        assert_eq!(p, b"hello-kudus");
    }

    #[test]
    fn wrong_token_is_blackhole() {
        let k1 = derive_key("right");
        let k2 = derive_key("wrong");
        let n = fresh_nonce();
        let c = seal(&k1, &n, b"secret");
        assert!(open(&k2, &n, &c).is_none()); // tag fails -> drop, no reply
    }

    #[test]
    fn tampered_nonce_fails() {
        let k = derive_key("t");
        let mut n = fresh_nonce();
        let c = seal(&k, &n, b"x");
        n[0] ^= 1;
        assert!(open(&k, &n, &c).is_none());
    }

    #[test]
    fn packet_hdr_roundtrip() {
        let k = derive_key("t");
        let n = fresh_nonce();
        let h = KudusHdr {
            ver: 1,
            flags: FLAG_DATA,
            seq: 101,
            ack: 99,
            sack: [0u8; 32],
            ts_ms: 12345,
        };
        let mut plain = encode_hdr(&h).to_vec();
        plain.extend_from_slice(b"payload");
        let pkt = encode_packet(0xdead_beef, &n, &seal(&k, &n, &plain));
        let (sess, nonce, ct) = decode_packet(&pkt).unwrap();
        assert_eq!(sess, 0xdead_beef);
        let opened = open(&k, nonce, ct).unwrap();
        let (h2, body) = decode_hdr(&opened).unwrap();
        assert_eq!((h2.seq, h2.ack), (101, 99));
        assert_eq!(body, b"payload");
        assert!(decode_packet(&pkt[..10]).is_none()); // short datagram
    }

    #[test]
    fn sack_marks_only_holes() {
        let mut sack = [0u8; 32];
        sack_mark(&mut sack, 100, 102);
        sack_mark(&mut sack, 100, 104);
        let missing = sack_missing(&sack, 100, 8);
        // 101,103,105..107 missing; 100 is acked base, 102/104 present
        assert!(missing.contains(&101) && missing.contains(&103));
        assert!(!missing.contains(&102) && !missing.contains(&104));
    }

    /// RED:丢包恢复——先丢 seq=2，后补到，输出必须按 1,2,3 有序补齐。
    /// 旧代码无重排缓冲（到包即投），丢包即永久少一块（现网 avatar/blob 截断）。
    #[test]
    fn reorder_recovers_loss_in_order() {
        let mut rx = ReorderBuf::new(1);
        assert_eq!(rx.push(1, b"a".to_vec()), vec![b"a".to_vec()]);
        assert!(rx.push(3, b"c".to_vec()).is_empty()); // 2 丢了：3 先缓存不投
        assert_eq!(rx.push(2, b"b".to_vec()), vec![b"b".to_vec(), b"c".to_vec()]); // 补 2 即补齐
        assert_eq!(rx.ack(), 3);
    }

    /// RED:超时重传——发 1,2,3，只 ack 到 1，取超时即吐出 2,3；ack 到 3 后清空。
    #[test]
    fn retx_expires_and_acks() {
        let mut tx = RetxBuf::new(1);
        let s1 = tx.on_send(b"a".to_vec());
        let s2 = tx.on_send(b"b".to_vec());
        let _s3 = tx.on_send(b"c".to_vec());
        assert_eq!((s1, s2), (1, 2));
        tx.on_ack(1, &[0u8; 32]);
        let due = tx.take_expired(Duration::from_millis(200), now_ms() + 1000);
        assert_eq!(due.len(), 2); // 2,3 超时待重传
        tx.on_ack(3, &[0u8; 32]);
        assert!(tx.is_empty());
    }

    #[test]
    fn parse_kudus_scheme() {
        use crate::common::quic::{parse_server_url, Transport};
        assert!(matches!(
            parse_server_url("kudus://127.0.0.1:7445"),
            Transport::Kudus { .. }
        ));
        assert!(matches!(
            parse_server_url("ws://127.0.0.1:7440/ws"),
            Transport::Ws(_)
        ));
    }
}
