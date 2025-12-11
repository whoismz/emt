//! A Rust library for monitoring executable memory in Linux userspace using ptrace.

// Public modules
pub use models::{Event, EventType, Page};
pub use tracer::Tracer;

// RWX monitoring
pub use ptrace::controller::MemoryExecEvent;
pub use ptrace::{PtraceController, RegionState, RemoteSyscall, RwxRegion};
pub use rwx_monitor::{MonitorResult, RwxMonitor, RwxMonitorBuilder};

// Internal modules
mod bpf_runtime;
mod error;
mod event_handler;
mod models;
pub mod ptrace;
mod rwx_monitor;
mod tracer;
mod utils;

// Re-export error types
pub use error::{EmtError, Result};
