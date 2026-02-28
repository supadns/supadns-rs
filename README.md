# SupaDNS (Rust)

**Bypass blocked DNS for Supabase using DNS-over-HTTPS (DoH).**

If your ISP blocks `*.supabase.co` via DNS poisoning, standard HTTP requests will fail. `supadns` provides a wrapper around `reqwest` that detects these DNS failures and transparently routes the connection through DNS-over-HTTPS (Quad9 and Cloudflare) while preserving strict TLS SNI validation.

## Add to Cargo.toml

```toml
[dependencies]
supadns = "1.0"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
tokio = { version = "1", features = ["full"] }
```

## Quick Start

SupaDNS intercepts requests to `*.supabase.co`. If system DNS fails, it automatically falls back to DoH.

```rust
use supadns::smart_get;
use reqwest::header::HeaderMap;

#[tokio::main]
async fn main() {
    let mut headers = HeaderMap::new();
    headers.insert("apikey", "your-anon-key".parse().unwrap());
    headers.insert("Authorization", "Bearer your-anon-key".parse().unwrap());

    // Automatically handles DoH fallback if DNS is poisoned/blocked
    let resp = smart_get(
        "https://myproject.supabase.co/rest/v1/todos?select=*",
        Some(headers),
    ).await.expect("Request failed");

    println!("Status: {}", resp.status());
    let body = resp.text().await.unwrap();
    println!("Response: {}", body);
}
```

## Advanced Requests

For `POST`, `PATCH`, or custom payloads, use `smart_request`:

```rust
use supadns::smart_request;
use reqwest::Method;

let mut headers = HeaderMap::new();
// ... setup headers

let body = br#"{"task": "buy milk"}"#.to_vec();

let resp = smart_request(
    Method::POST,
    "https://myproject.supabase.co/rest/v1/todos",
    Some(headers),
    Some(body)
).await.unwrap();
```

## Standalone DoH Resolution

If you just need to bypass DNS and get the IPv4 address:

```rust
use supadns::resolve_doh;

#[tokio::main]
async fn main() {
    let ip = resolve_doh("myproject.supabase.co").await.unwrap();
    println!("Resolved: {}", ip); // -> 104.18.x.x
}
```

## How It Works (TLS SNI Preservation)

The hardest part of direct IP connection with Cloudflare is preserving TLS SNI. 

1. **System DNS First**: Always tries a standard `reqwest` call first.
2. **Failure Detection**: Catches DNS/timeout errors specifically for `*.supabase.co` domains.
3. **DoH Fallback**: Resolves the IPv4 address via `https://dns.quad9.net/dns-query`.
4. **TLS SNI**: Uses `reqwest::ClientBuilder::resolve(hostname, ip)`. This tells `reqwest` and `rustls` exactly which IP to dial, but preserves the original hostname in the URL so the SSL certificate is strictly verified and the HTTP `Host` header remains correct.

## Requirements

- Rust ≥ 1.70
- `reqwest` (must use `rustls-tls` feature)
- `tokio`

## License
MIT
