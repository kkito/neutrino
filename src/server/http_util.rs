//! HTTP 入站纯函数：host 提取/XFP 注入/轮询（无 IO，易单测）。
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) fn extract_host(head: &str) -> String {
    head.lines()
        .find_map(|l| {
            let t = l.trim();
            if t.len() > 5 && t[..5].eq_ignore_ascii_case("host:") {
                Some(t[5..].trim().split(':').next().unwrap_or("").to_lowercase())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

/// Inject/replace `X-Forwarded-Proto: <proto>` into an HTTP request head.
/// Returns rewritten bytes; if no header terminator found, returns input as-is.
pub(crate) fn inject_xfp(head: &[u8], proto: &str) -> Vec<u8> {
    let pos = match head.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i,
        None => return head.to_vec(),
    };
    let (hdr, rest) = head.split_at(pos + 4);
    let mut out: Vec<u8> = Vec::with_capacity(head.len() + 32);
    // hdr ends with \r\n\r\n; strip it, filter lines, re-emit
    let inner = &hdr[..pos];
    let mut first = true;
    for ln in inner.split(|&c| c == b'\n') {
        let mut t: &[u8] = ln;
        while t.last() == Some(&b'\r') { t = &t[..t.len()-1]; }
        while t.first() == Some(&b' ') || t.first() == Some(&b'\t') { t = &t[1..]; }
        if !first && t.len() >= 18 && t[..18].eq_ignore_ascii_case(b"x-forwarded-proto:") {
            continue;
        }
        if !first && t.is_empty() { continue; }
        out.extend_from_slice(t);
        out.extend_from_slice(b"\r\n");
        first = false;
    }
    out.extend_from_slice(format!("X-Forwarded-Proto: {proto}\r\n").as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&rest[..]);
    out
}

#[allow(dead_code)]
pub(crate) fn trim_crlf(mut b: &[u8]) -> &[u8] {    while let Some((&c, rest)) = b.split_first() {
        if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

#[allow(dead_code)]
pub(crate) fn pick_rr(list: &[String], ctr: &AtomicUsize) -> Option<String> {
    if list.is_empty() {
        return None;
    }
    let i = ctr.fetch_add(1, Ordering::Relaxed) % list.len();
    list.get(i).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_extract() {
        assert_eq!(
            extract_host("GET / HTTP/1.1\r\nHost: Git.NAT.kkito.cn:7443\r\n\r\n"),
            "git.nat.kkito.cn"
        );
        assert_eq!(extract_host("GET / HTTP/1.1\r\n\r\n"), "");
    }

    #[test]
    fn xfp_inject_replaces() {
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-Proto: http\r\n\r\nbody";
        let out = inject_xfp(raw, "https");
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.matches("X-Forwarded-Proto:").count(), 1);
        assert!(s.contains("X-Forwarded-Proto: https"));
        assert!(s.ends_with("body"));
    }

    #[test]
    fn xfp_inject_adds() {
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let s = String::from_utf8(inject_xfp(raw, "https")).unwrap();
        assert!(s.contains("X-Forwarded-Proto: https\r\n\r\n"));
    }

    #[test]
    fn xfp_no_terminator_passthrough() {
        let raw = b"GET / partial";
        assert_eq!(inject_xfp(raw, "https"), raw);
    }

    #[test]
    fn rr_cycles() {
        let list = vec!["a".to_string(), "b".to_string()];
        let c = AtomicUsize::new(0);
        assert_eq!(
            vec![
                pick_rr(&list, &c),
                pick_rr(&list, &c),
                pick_rr(&list, &c)
            ],
            vec![
                Some("a".to_string()),
                Some("b".to_string()),
                Some("a".to_string())
            ]
        );
        assert_eq!(pick_rr(&[], &c), None);
    }

}
