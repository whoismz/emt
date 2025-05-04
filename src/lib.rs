//! eBPF-based Linux userspace executable memory tracing library
//!
//! # Examples
//! ```
//! use emt::trace_process;
//!
//! # fn main() -> anyhow::Result<()> {
//! let mut tracer = trace_process(1234, "./output", false)?;
//! // ... do work ...
//! # Ok(())
//! # }
//! ```

mod bpf_runtime;
mod memory_analyzer;
mod models;
mod tracer;

pub use bpf_runtime::BpfRuntime;
pub use memory_analyzer::MemoryAnalyzer;
pub use models::{EventType, ExecutablePage, MemoryEvent};
pub use tracer::MemoryTracer;

/// Starts tracing executable memory of a process
///
/// # Arguments
/// * `pid` - Target process ID
/// * `output_dir` - Directory to store trace data
/// * `save_content` - Whether to save memory content
///
/// # Returns
/// Initialized and started `MemoryTracer` instance
pub fn trace_process(
    pid: i32,
    output_dir: impl AsRef<std::path::Path>,
    save_content: bool,
) -> anyhow::Result<MemoryTracer> {
    let mut tracer = MemoryTracer::new(pid, output_dir, save_content);
    tracer.start()?;
    Ok(tracer)
}

pub fn check_environment() -> anyhow::Result<&'static str> {
    // Check if we can access procfs
    let process = procfs::process::Process::myself()?;
    println!("Current process PID: {}", process.pid);

    Ok("Environment check passed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment() {
        assert!(check_environment().is_ok());
    }

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
