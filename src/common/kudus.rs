//! kudus 传输：自研 UDP 可靠传输，全随机隐身。
//! 包格式：`[session 4B BE 明文][nonce 24B 随机][XChaCha20-Poly1305 密文+16B tag]`。
//! key = SHA256(token)，两边预共享，无协商、无证书、无 TLS。
//! 明文（解密后）= `[ver 1B|flags 1B|seq 4B BE|ack 4B BE|sack 32B|ts_ms 8B BE][proto_frame]`。
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Debug, Clone, PartialEq, Eq)]
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
