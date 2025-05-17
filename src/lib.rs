//! eBPF-based Linux userspace executable memory tracing library
//!
//! # Examples
//! ```
//! use emt::trace_process;
//!
//! # fn main() -> anyhow::Result<()> {
//! let mut tracer = trace_process(1234)?;
//! // ... do work ...
//! # Ok(())
//! # }
//! ```

mod analyzer;
mod ebpf;
mod handler;
mod models;

pub use handler::Handler;
pub use models::{Event, EventType};

/// Starts tracing executable memory of a process
///
/// # Arguments
/// * `pid` - Target process ID
///
/// # Returns
/// Initialized and started `MemoryTracer` instance
pub fn trace_process(pid: i32) -> anyhow::Result<Handler> {
    let mut tracer = Handler::new(pid);
    tracer.start()?;
    Ok(tracer)
}