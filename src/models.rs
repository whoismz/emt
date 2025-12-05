use std::path::PathBuf;
use std::time::SystemTime;

/// Enumeration of memory event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Regular mmap with executable permission
    Map,
    /// Memory unmap event
    Unmap,
    /// mprotect adding executable permission
    Mprotect,
    /// RWX mmap detected (read+write+exec)
    RwxMap,
    /// RWX mprotect detected (read+write+exec)
    RwxMprotect,
    /// Tracer shutdown event
    Shutdown,
}

impl EventType {
    /// Returns true if this event type represents an RWX operation
    pub fn is_rwx(&self) -> bool {
        matches!(self, EventType::RwxMap | EventType::RwxMprotect)
    }

    /// Returns true if this event type adds executable memory
    pub fn adds_executable(&self) -> bool {
        matches!(
            self,
            EventType::Map | EventType::Mprotect | EventType::RwxMap | EventType::RwxMprotect
        )
    }
}

/// Struct representing a memory event.
#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub event_type: EventType,
    pub addr: usize,
    pub size: usize,
    pub timestamp: SystemTime,
    pub timestamp_str: String,
    pub pid: i32,
    pub content: Option<Vec<u8>>,
    /// Protection flags (for RWX events)
    pub prot: Option<u64>,
}

impl Event {
    /// Creates a shutdown event
    pub fn shutdown() -> Self {
        Self {
            event_type: EventType::Shutdown,
            addr: 0,
            size: 0,
            timestamp: SystemTime::now(),
            timestamp_str: String::new(),
            pid: -1,
            content: None,
            prot: None,
        }
    }

    /// Returns true if this event represents an RWX memory operation
    pub fn is_rwx(&self) -> bool {
        self.event_type.is_rwx()
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
    /// Whether this page was originally requested with RWX permissions
    pub was_rwx: bool,
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
            was_rwx: false,
        }
    }

    /// Creates a new Page with RWX flag
    pub fn new_rwx(
        addr: usize,
        size: usize,
        timestamp: String,
        source_file: Option<PathBuf>,
    ) -> Self {
        Self {
            addr,
            size,
            timestamp,
            source_file,
            content: None,
            was_rwx: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_is_rwx() {
        assert!(!EventType::Map.is_rwx());
        assert!(!EventType::Unmap.is_rwx());
        assert!(!EventType::Mprotect.is_rwx());
        assert!(EventType::RwxMap.is_rwx());
        assert!(EventType::RwxMprotect.is_rwx());
        assert!(!EventType::Shutdown.is_rwx());
    }

    #[test]
    fn test_event_type_adds_executable() {
        assert!(EventType::Map.adds_executable());
        assert!(!EventType::Unmap.adds_executable());
        assert!(EventType::Mprotect.adds_executable());
        assert!(EventType::RwxMap.adds_executable());
        assert!(EventType::RwxMprotect.adds_executable());
        assert!(!EventType::Shutdown.adds_executable());
    }

    #[test]
    fn test_shutdown_event() {
        let event = Event::shutdown();
        assert!(matches!(event.event_type, EventType::Shutdown));
        assert_eq!(event.pid, -1);
        assert_eq!(event.addr, 0);
        assert!(event.content.is_none());
        assert!(event.prot.is_none());
    }

    #[test]
    fn test_page_new() {
        let page = Page::new(0x1000, 4096, "2024-01-01".to_string(), None);
        assert_eq!(page.addr, 0x1000);
        assert_eq!(page.size, 4096);
        assert!(!page.was_rwx);
        assert!(page.content.is_none());
    }

    #[test]
    fn test_page_new_rwx() {
        let page = Page::new_rwx(0x2000, 4096, "2024-01-01".to_string(), None);
        assert_eq!(page.addr, 0x2000);
        assert!(page.was_rwx);
    }
}
