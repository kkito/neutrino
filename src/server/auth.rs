//! server 鉴权：JWT 签发/校验 + Bearer/cookie 门禁。

use axum::http::{header, HeaderMap};

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}

pub(crate) fn mint_jwt(secret: &str) -> String {
    let c = Claims {
        sub: "admin".into(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp(),
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &c,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap_or_default()
}

pub(crate) fn verify_jwt(secret: &str, token: &str) -> bool {
    jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    )
    .map(|d| d.claims.sub == "admin")
    .unwrap_or(false)
}

pub(crate) fn auth_ok(headers: &HeaderMap, secret: &str) -> bool {
    // Bearer takes precedence (tests/CLI), else HttpOnly cookie `nt_session`
    if let Some(a) = headers.get(header::AUTHORIZATION) {
        if let Ok(s) = a.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                if verify_jwt(secret, t.trim()) {
                    return true;
                }
            }
        }
    }
    if let Some(c) = headers.get(header::COOKIE) {
        if let Ok(s) = c.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(t) = part.strip_prefix("nt_session=") {
                    if verify_jwt(secret, t.trim()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderMap};
    #[test]
    fn jwt_roundtrip_and_reject() {
        let sec = "test-secret-123";
        let t = mint_jwt(sec);
        assert!(verify_jwt(sec, &t));
        assert!(!verify_jwt(sec, "bogus"));
        assert!(!verify_jwt("other", &t));
    }

    #[test]
    fn auth_header_and_cookie() {
        let sec = "s3cr3t";
        let t = mint_jwt(sec);
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, format!("Bearer {t}").parse().unwrap());
        assert!(auth_ok(&h, sec));
        let mut c = HeaderMap::new();
        c.insert(header::COOKIE, format!("x=1; nt_session={t}").parse().unwrap());
        assert!(auth_ok(&c, sec));
        assert!(!auth_ok(&HeaderMap::new(), sec));
    }

}

pub(crate) fn unauthorized() -> axum::response::Response {
    use axum::response::IntoResponse;
    (axum::http::StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"ok": false}))).into_response()
}
