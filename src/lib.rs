//! A Rust library for monitoring executable memory in Linux userspace using ptrace and eBPF.

// Public modules
pub mod ebpf;
pub mod ptrace;

// Internal modules
mod error;
mod models;
mod utils;

// Re-export eBPF types
pub use ebpf::{BpfRuntime, EventHandler, Tracer};

// Re-export models
pub use models::{Event, EventType, Page};

// Re-export ptrace types
pub use ptrace::controller::MemoryExecEvent;
pub use ptrace::{MonitorResult, RwxMonitor, RwxMonitorBuilder};
pub use ptrace::{PtraceController, RegionState, RemoteSyscall, RwxRegion};

// Re-export error types
pub use error::{EmtError, Result};
