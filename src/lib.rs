mod doh_resolver;
mod connection_manager;

pub use doh_resolver::{resolve_doh, is_supabase_domain, clear_cache};
pub use connection_manager::{smart_client, smart_get, smart_request};
