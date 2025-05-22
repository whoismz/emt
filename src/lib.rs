//! eBPF-based Linux userspace executable memory tracing library
//!
//! # Examples
//! ```
//! // import the emt library
//! use emt::Tracer;
//!
//! fn main() -> anyhow::Result<()> {
//!     // create a new tracer for a target process
//!     let mut tracer = Tracer::new(2025);
//!
//!     // start tracing
//!     tracer.start()?;
//!
//!     // wait seconds
//!     std::thread::sleep(std::time::Duration::from_secs(10));
//!
//!     // stop tracing and get memory pages
//!     let pages = tracer.stop()?;
//!
//!     // process the pages you got
//!     for page in pages {
//!         println!("0x{:016x} - 0x{:016x} - {} bytes", page.addr, page.addr + page.size - 1, page.size);
//!     }
//!
//!     Ok(())
//! }
//! ```

mod bpf_runtime;
mod error;
mod event_handler;
mod models;
mod tracer;
mod utils;

pub use error::EmtError;
pub use models::{Event, EventType, Page};
pub use tracer::Tracer;
