//! eBPF-based executable memory tracing library for Linux userspace

// Public modules
pub use models::{Event, EventType, Page};
pub use tracer::Tracer;

mod bpf_runtime;
mod error;
mod event_handler;
mod models;
mod tracer;
mod utils;
