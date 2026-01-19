//! A Rust library for monitoring executable memory in Linux userspace using ptrace and eBPF.

pub mod ebpf;
pub mod ptrace;

mod error;
mod models;
mod utils;

pub use ebpf::{BpfRuntime, EventHandler, Tracer};
pub use models::{Event, EventType, Page};

pub use ptrace::{
    FaultType, MemoryExecEvent, MonitorResult, PtraceController, RegionSource, RegionState,
    RegionTracker, RemoteSyscall, RwxMonitor, RwxMonitorBuilder, TrackedRegion,
};

pub use error::{EmtError, Result};
