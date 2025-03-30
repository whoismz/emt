mod bpf_loader;
mod memory_analyzer;
mod models;
mod tracer;

pub use bpf_loader::BpfTracer;
pub use memory_analyzer::MemoryAnalyzer;
pub use models::{EventType, ExecutablePage, MemoryEvent};
pub use tracer::MemoryTracer;

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
            protection_flags: 0x5, // PROT_READ | PROT_EXEC
        };

        assert_eq!(page.address, 0x1000);
        assert_eq!(page.size, 4096);
    }
}
