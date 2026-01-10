//! Ptrace-based process tracing for memory monitoring.

pub mod controller;
pub mod monitor;
pub mod region;
pub mod remote_syscall;

pub use controller::{MemoryExecEvent, PtraceController};
pub use monitor::{MonitorResult, RwxMonitor, RwxMonitorBuilder};
pub use region::{RegionState, RegionTracker, TrackedRegion};
pub use remote_syscall::RemoteSyscall;
