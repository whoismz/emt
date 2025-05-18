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

mod bpf_runtime;
mod event_handler;
mod memory_analyzer;
mod models;
mod tracer;
mod utils;

pub use models::{Event, EventType};
pub use tracer::Tracer;

/// Starts tracing executable memory of a process
///
/// # Arguments
/// * `pid` - Target process ID
///
/// # Returns
/// Initialized and started `MemoryTracer` instance
pub fn trace_process(pid: i32) -> anyhow::Result<Tracer> {
    let mut tracer = Tracer::new(pid);
    tracer.start()?;
    Ok(tracer)
}
