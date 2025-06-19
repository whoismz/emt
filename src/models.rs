use std::path::PathBuf;
use std::time::SystemTime;

/// Enumeration of memory event types.
#[derive(Debug)]
pub enum EventType {
    Map,
    Unmap,
    Mprotect,
}

/// Struct representing a memory event.
#[repr(C)]
pub struct Event {
    pub event_type: EventType,
    pub addr: usize,
    pub size: usize,
    pub timestamp: SystemTime,
    pub timestamp_str: String,
    pub pid: i32,
    pub content: Option<Vec<u8>>,
}

impl Event {
    /// Creates a shutdown event
    pub fn shutdown() -> Self {
        Self {
            event_type: EventType::Unmap,
            addr: 0,
            size: 0,
            timestamp: SystemTime::now(),
            timestamp_str: String::new(),
            pid: -1,
            content: None,
        }
    }
}

/// Represents a memory page
#[derive(Clone, Debug)]
pub struct Page {
    pub addr: usize,
    pub size: usize,
    pub timestamp: String,
    pub source_file: Option<PathBuf>,
    pub content: Option<Vec<u8>>,
}

impl Page {
    /// Creates a new Page
    pub fn new(addr: usize, size: usize, timestamp: String, source_file: Option<PathBuf>) -> Self {
        Self {
            addr,
            size,
            timestamp,
            source_file,
            content: None,
        }
    }
}
