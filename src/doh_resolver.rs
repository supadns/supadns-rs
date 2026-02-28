use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DOH_ENDPOINTS: &[&str] = &[
    "https://dns.quad9.net/dns-query",
    "https://cloudflare-dns.com/dns-query",
];

const DOH_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_TTL_SECS: u64 = 30;

// --- Cache ---

struct CacheEntry {
    ip: String,
    expires_at: Instant,
}

static CACHE: std::sync::LazyLock<Mutex<HashMap<String, CacheEntry>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_cached(hostname: &str) -> Option<String> {
    let cache = CACHE.lock().ok()?;
    let entry = cache.get(hostname)?;
    if Instant::now() > entry.expires_at {
        return None;
    }
    Some(entry.ip.clone())
}

fn set_cache(hostname: &str, ip: &str, ttl: u64) {
    let effective_ttl = ttl.max(MIN_TTL_SECS);
    if let Ok(mut cache) = CACHE.lock() {
        cache.insert(
            hostname.to_string(),
            CacheEntry {
                ip: ip.to_string(),
                expires_at: Instant::now() + Duration::from_secs(effective_ttl),
            },
        );
    }
}

pub fn clear_cache() {
    if let Ok(mut cache) = CACHE.lock() {
        cache.clear();
    }
}

// --- DNS wire-format (RFC 1035) ---

pub fn encode_dns_query(hostname: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header: ID=1, RD=1, QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x01]); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // Question
    for label in hostname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root
    buf.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    buf
}

pub fn decode_dns_response(data: &[u8]) -> Option<(String, u64)> {
    if data.len() < 12 {
        return None;
    }

    let mut offset = 12;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;

    // Skip questions
    for _ in 0..qdcount {
        while offset < data.len() && data[offset] != 0 {
            if data[offset] & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }
            offset += data[offset] as usize + 1;
        }
        if offset < data.len() && data[offset] == 0 {
            offset += 1;
        }
        offset += 4; // QTYPE + QCLASS
    }

    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    for _ in 0..ancount {
        if offset >= data.len() {
            break;
        }
        // Skip name
        if data[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            while offset < data.len() && data[offset] != 0 {
                offset += data[offset] as usize + 1;
            }
            offset += 1;
        }

        if offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        offset += 2; // rclass
        let ttl = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as u64;
        offset += 4;
        let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if rtype == 1 && rdlength == 4 && offset + 4 <= data.len() {
            let ip = format!(
                "{}.{}.{}.{}",
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            );
            return Some((ip, ttl));
        }
        offset += rdlength;
    }

    None
}

// --- Public API ---

/// Resolve hostname to IPv4 via DoH. Quad9 first, Cloudflare fallback.
pub async fn resolve_doh(hostname: &str) -> Result<String, String> {
    if let Some(ip) = get_cached(hostname) {
        return Ok(ip);
    }

    let query = encode_dns_query(hostname);
    let client = reqwest::Client::builder()
        .timeout(DOH_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;

    let mut errors = Vec::new();

    for endpoint in DOH_ENDPOINTS {
        match client
            .post(*endpoint)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query.clone())
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors.push(format!("HTTP {} from {}", resp.status(), endpoint));
                    continue;
                }
                match resp.bytes().await {
                    Ok(body) => {
                        if let Some((ip, ttl)) = decode_dns_response(&body) {
                            set_cache(hostname, &ip, ttl);
                            return Ok(ip);
                        }
                        errors.push(format!("no A record from {}", endpoint));
                    }
                    Err(e) => errors.push(e.to_string()),
                }
            }
            Err(e) => errors.push(e.to_string()),
        }
    }

    Err(format!(
        "all DoH endpoints failed for {}: {}",
        hostname,
        errors.join("; ")
    ))
}

pub fn is_supabase_domain(hostname: &str) -> bool {
    hostname == "supabase.co" || hostname.ends_with(".supabase.co")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_dns_query() {
        let result = encode_dns_query("example.com");
        assert!(result.len() > 12);
        assert_eq!(result[0..2], [0x00, 0x01]); // ID
        assert_eq!(result[2..4], [0x01, 0x00]); // flags
        assert_eq!(result[4..6], [0x00, 0x01]); // QDCOUNT
    }

    #[test]
    fn test_decode_no_answers() {
        let mut buf = vec![
            0x00, 0x01, 0x81, 0x80,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // question: example.com A IN
        buf.extend_from_slice(&[0x07]);
        buf.extend_from_slice(b"example");
        buf.extend_from_slice(&[0x03]);
        buf.extend_from_slice(b"com");
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

        assert!(decode_dns_response(&buf).is_none());
    }

    #[test]
    fn test_decode_a_record() {
        let mut buf = vec![
            0x00, 0x01, 0x81, 0x80,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        buf.extend_from_slice(&[0x07]);
        buf.extend_from_slice(b"example");
        buf.extend_from_slice(&[0x03]);
        buf.extend_from_slice(b"com");
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        // answer: pointer, A, IN, TTL=300, 93.184.216.34
        buf.extend_from_slice(&[
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x01, 0x2C,
            0x00, 0x04,
            93, 184, 216, 34,
        ]);

        let result = decode_dns_response(&buf);
        assert!(result.is_some());
        let (ip, ttl) = result.unwrap();
        assert_eq!(ip, "93.184.216.34");
        assert_eq!(ttl, 300);
    }

    #[test]
    fn test_cache() {
        clear_cache();
        assert!(get_cached("test.supabase.co").is_none());
        set_cache("test.supabase.co", "1.2.3.4", 600);
        assert_eq!(get_cached("test.supabase.co"), Some("1.2.3.4".to_string()));
        clear_cache();
    }

    #[test]
    fn test_is_supabase_domain() {
        assert!(is_supabase_domain("myproject.supabase.co"));
        assert!(is_supabase_domain("supabase.co"));
        assert!(!is_supabase_domain("google.com"));
        assert!(!is_supabase_domain("supabase.com"));
        assert!(!is_supabase_domain("notsupabase.co"));
    }

    #[tokio::test]
    async fn test_resolve_doh_real() {
        clear_cache();
        // Uses env var or falls back to a known public Supabase domain
        let host = std::env::var("SUPABASE_HOST")
            .unwrap_or_else(|_| "supabase.co".into());
        let result = resolve_doh(&host).await;
        assert!(result.is_ok(), "DoH resolution failed: {:?}", result);
        let ip = result.unwrap();
        assert!(!ip.is_empty());
        println!("Resolved {} to: {}", host, ip);
    }
}
