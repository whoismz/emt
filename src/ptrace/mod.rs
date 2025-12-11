//! Ptrace-based process tracing for RWX memory monitoring.

pub mod controller;
pub mod remote_syscall;
pub mod rwx_region;

pub use controller::PtraceController;
pub use remote_syscall::RemoteSyscall;
pub use rwx_region::{RegionState, RwxRegion, RwxRegionTracker, TrackerStats};
