//! eBPF-based Linux userspace executable memory tracing library
//!
//! # Examples
//! ```
//! use emt::Tracer;
//!
//! # fn main() -> anyhow::Result<()> {
//! // Create a new tracer for a target process
//! let mut tracer = Tracer::new(1214781);
//!
//! // Start tracing
//! tracer.start()?;
//!
//! // Do some work while tracing
//! std::thread::sleep(std::time::Duration::from_secs(2));
//!
//! // Stop tracing and get collected data
//! let memory_data = tracer.stop()?;
//!
//! // Process collected memory pages
//! for page in memory_data {
//!     println!("0x{:016x} - {:?} - {:?}", page.addr, page.size, page.timestamp);
//! }
//!
//! # Ok(())
//! # }
//! ```

mod bpf_runtime;
mod error;
mod event_handler;
mod memory_analyzer;
mod models;
mod tracer;
mod utils;

pub use error::EmtError;
pub use models::{Event, EventType, Page};
pub use tracer::Tracer;
