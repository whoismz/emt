//! eBPF-based Linux userspace executable memory tracing library
//!
//! # Examples
//! ```
//! use emt::trace_process;
//!
//! # fn main() -> anyhow::Result<()> {
//! let mut tracer = trace_process(1234)?;
//! //  do work
//! # Ok(())
//! # }
//! ```

mod bpf_runtime;
mod event_handler;
mod memory_analyzer;
mod models;
mod tracer;
mod utils;
mod error;

pub use error::EmtError;
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
    if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
        anyhow::bail!("No such PID: {}", pid);
    }
    
    let mut tracer = Tracer::new(pid);
    tracer.start()?;
    Ok(tracer)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_models() {
        use crate::models::Page;
        use std::time::SystemTime;

        let page = Page {
            addr: 0x1000,
            size: 4096,
            timestamp: SystemTime::now(),
            source_file: None,
            content: None,
        };

        assert_eq!(page.addr, 0x1000);
        assert_eq!(page.size, 4096);
    }
}
