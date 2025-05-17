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
mod memory_analyzer;
mod models;
mod tracer;

pub use models::{EventType, MemoryEvent};
pub use tracer::MemoryTracer;

/// Starts tracing executable memory of a process
///
/// # Arguments
/// * `pid` - Target process ID
///
/// # Returns
/// Initialized and started `MemoryTracer` instance
pub fn trace_process(pid: i32) -> anyhow::Result<MemoryTracer> {
    let mut tracer = MemoryTracer::new(pid);
    tracer.start()?;
    Ok(tracer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_models() {
        use crate::models::ExecutablePage;
        use std::time::SystemTime;

        let page = ExecutablePage {
            address: 0x1000,
            size: 4096,
            timestamp: SystemTime::now(),
            source_file: None,
            content: None,
            protection_flags: 0x5,
        };

        assert_eq!(page.address, 0x1000);
        assert_eq!(page.size, 4096);
    }
}
