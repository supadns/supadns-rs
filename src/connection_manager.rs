use reqwest::Url;
use crate::doh_resolver::{resolve_doh, is_supabase_domain};

/// Build a reqwest Client that resolves Supabase domains through DoH.
/// Uses rustls for TLS, which handles SNI correctly via the Host header.
pub fn smart_client() -> reqwest::Client {
    reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .expect("failed to build reqwest client")
}

/// Convenience: GET request with automatic DoH fallback for Supabase domains.
pub async fn smart_get(url: &str, headers: Option<reqwest::header::HeaderMap>) -> Result<reqwest::Response, String> {
    smart_request(reqwest::Method::GET, url, headers, None).await
}

/// Generic request with DoH fallback.
/// Tries normal DNS first, falls back to DoH for *.supabase.co on failure.
pub async fn smart_request(
    method: reqwest::Method,
    url: &str,
    headers: Option<reqwest::header::HeaderMap>,
    body: Option<Vec<u8>>,
) -> Result<reqwest::Response, String> {
    let client = smart_client();

    // 1. Try normal request
    let mut req_builder = client.request(method.clone(), url);
    if let Some(ref h) = headers {
        req_builder = req_builder.headers(h.clone());
    }
    if let Some(ref b) = body {
        req_builder = req_builder.body(b.clone());
    }

    match req_builder.send().await {
        Ok(resp) => return Ok(resp),
        Err(e) => {
            let parsed = Url::parse(url).map_err(|e| e.to_string())?;
            let hostname = parsed.host_str().unwrap_or("");

            if !is_supabase_domain(hostname) || !is_connection_error(&e) {
                return Err(e.to_string());
            }

            // 2. DoH fallback
            fetch_via_doh(method, url, headers, body).await
        }
    }
}

fn is_connection_error(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout() || {
        let msg = err.to_string().to_lowercase();
        msg.contains("dns") || msg.contains("resolve") || msg.contains("getaddrinfo")
    }
}

async fn fetch_via_doh(
    method: reqwest::Method,
    url: &str,
    headers: Option<reqwest::header::HeaderMap>,
    body: Option<Vec<u8>>,
) -> Result<reqwest::Response, String> {
    let parsed = Url::parse(url).map_err(|e| e.to_string())?;
    let hostname = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(443);
    let resolved_ip = resolve_doh(hostname).await?;

    let addr: std::net::SocketAddr = format!("{}:{}", resolved_ip, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;

    // .resolve() maps hostname→IP while keeping the original hostname for TLS SNI
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .resolve(hostname, addr)
        .build()
        .map_err(|e| e.to_string())?;

    // Keep the original URL — reqwest handles the IP routing internally
    let mut req_builder = client.request(method, url);

    if let Some(h) = headers {
        req_builder = req_builder.headers(h);
    }
    if let Some(b) = body {
        req_builder = req_builder.body(b);
    }

    req_builder.send().await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_smart_get_live() {
        let url = std::env::var("SUPABASE_URL")
            .unwrap_or_else(|_| "https://axyfgyzajxzafqxvhjyq.supabase.co".into());
        let key = std::env::var("SUPABASE_ANON_KEY")
            .expect("set SUPABASE_ANON_KEY env var to run live tests");

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("apikey", key.parse().unwrap());

        let result = smart_get(
            &format!("{}/auth/v1/settings", url),
            Some(headers),
        )
        .await;

        assert!(result.is_ok(), "smart_get failed: {:?}", result);
        let resp = result.unwrap();
        println!("Auth status: {}", resp.status());
        assert!(resp.status().is_success() || resp.status().as_u16() == 401);
    }
}
