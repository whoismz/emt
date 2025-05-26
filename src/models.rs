use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug)]
pub enum EventType {
    Map,
    Unmap,
    Mprotect,
}

#[repr(C)]
pub struct Event {
    pub event_type: EventType,
    pub addr: usize,
    pub size: usize,
    pub timestamp: SystemTime,
    pub pid: i32,
    pub content: Option<Vec<u8>>,
}

impl Event {
    /// Creates a shutdown signal event
    pub fn shutdown() -> Self {
        Self {
            event_type: EventType::Unmap,
            addr: 0,
            size: 0,
            timestamp: SystemTime::now(),
            pid: -1,
            content: None,
        }
    }

    /// Checks if this is a shutdown event
    pub fn is_shutdown(&self) -> bool {
        self.pid == -1
    }

    /// Checks if this event contains the specified address
    pub fn contains_address(&self, addr: usize) -> bool {
        addr >= self.addr && addr < self.addr + self.size
    }

    /// Checks if this event overlaps with the given range
    pub fn overlaps(&self, addr: usize, size: usize) -> bool {
        let self_end = self.addr + self.size;
        let other_end = addr + size;
        self.addr < other_end && self_end > addr
    }

    /// Returns the end address of the memory region
    pub fn end_addr(&self) -> usize {
        self.addr + self.size
    }
}

#[derive(Clone, Debug)]
pub struct Page {
    pub addr: usize,
    pub size: usize,
    pub timestamp: SystemTime,
    pub source_file: Option<PathBuf>,
    pub content: Option<Vec<u8>>,
}

impl Page {
    pub fn new(
        addr: usize,
        size: usize,
        timestamp: SystemTime,
        source_file: Option<PathBuf>,
    ) -> Self {
        Self {
            addr,
            size,
            timestamp,
            source_file,
            content: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn is_same(&self, other: &Self) -> bool {
        self.addr == other.addr && self.size == other.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_event_creation() {
        let event = Event {
            event_type: EventType::Map,
            addr: 0x1000,
            size: 4096,
            timestamp: UNIX_EPOCH + Duration::from_secs(1000),
            pid: 1234,
            content: Some(vec![0x90, 0x90, 0x90, 0x90]),
        };

        assert_eq!(event.addr, 0x1000);
        assert_eq!(event.size, 4096);
        assert_eq!(event.pid, 1234);
        assert!(matches!(event.event_type, EventType::Map));
        assert!(event.content.is_some());
        assert_eq!(event.content.as_ref().unwrap().len(), 4);
    }

    #[test]
    fn test_event_shutdown() {
        let shutdown_event = Event::shutdown();

        assert!(matches!(shutdown_event.event_type, EventType::Unmap));
        assert_eq!(shutdown_event.addr, 0);
        assert_eq!(shutdown_event.size, 0);
        assert_eq!(shutdown_event.pid, -1);
        assert!(shutdown_event.content.is_none());
    }

    #[test]
    fn test_event_is_shutdown() {
        let normal_event = Event {
            event_type: EventType::Map,
            addr: 0x1000,
            size: 4096,
            timestamp: UNIX_EPOCH,
            pid: 1234,
            content: None,
        };

        let shutdown_event = Event {
            event_type: EventType::Unmap,
            addr: 0,
            size: 0,
            timestamp: UNIX_EPOCH,
            pid: -1,
            content: None,
        };

        assert!(!normal_event.is_shutdown());
        assert!(shutdown_event.is_shutdown());
    }
}
