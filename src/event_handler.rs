use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use log::debug;

use crate::models::{Event, EventType, Page};
use crate::utils;

const PAGE_SIZE: usize = 4096;

/// Handles memory events and keeps track of memory pages for a specific target PID.
pub struct EventHandler {
    event_counter: AtomicUsize,
    known_pages: HashMap<usize, Page>,
}

impl EventHandler {
    /// Creates a new EventHandler for a specific target PID.
    pub fn new() -> Self {
        Self {
            event_counter: AtomicUsize::new(1),
            known_pages: HashMap::new(),
        }
    }

    /// Creates a page from a memory event.
    fn get_page_from_event(event: &Event) -> Page {
        Page {
            addr: event.addr,
            size: PAGE_SIZE,
            timestamp: event.timestamp_str.clone(),
            source_file: None,
            content: event.content.clone(),
            was_rwx: event.event_type.is_rwx(),
        }
    }

    /// Returns a sorted list of all currently known pages, sorted by timestamp (ascending).
    /// Pages with equal timestamps are sorted by address (ascending).
    pub fn get_all_pages(&self) -> Vec<Page> {
        let mut pages: Vec<Page> = self.known_pages.values().cloned().collect();
        pages.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then(a.addr.cmp(&b.addr)));
        pages
    }

    /// Processes a single memory event.
    pub fn process(&mut self, event: Event) -> bool {
        let event_id = self.event_counter.fetch_add(1, Ordering::SeqCst);

        if !matches!(event.event_type, EventType::Unmap) {
            debug!(
                "{}: type: {:?}, addr: {:x}, size: {}, timestamp: {:?}, rwx: {}",
                event_id,
                event.event_type,
                event.addr,
                event.size,
                event.timestamp_str,
                event.event_type.is_rwx(),
            );
        }

        if let Some(content) = &event.content {
            utils::print_memory_content(content, event.addr);
        }

        match event.event_type {
            EventType::Map => {
                let page = EventHandler::get_page_from_event(&event);
                self.known_pages.insert(page.addr, page);
            }

            EventType::RwxMap => {
                let page = EventHandler::get_page_from_event(&event);
                self.known_pages.insert(page.addr, page);
            }

            EventType::Mprotect => {
                let page = EventHandler::get_page_from_event(&event);
                self.known_pages.insert(page.addr, page);
            }

            EventType::RwxMprotect => {
                let page = EventHandler::get_page_from_event(&event);
                self.known_pages.insert(page.addr, page);
            }

            EventType::Unmap => {
                let page = EventHandler::get_page_from_event(&event);
                self.known_pages.remove(&page.addr);
            }

            EventType::Shutdown => {
                return false;
            }
        }
        true
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Event, EventType};
    use std::time::SystemTime;

    fn create_test_event(event_type: EventType, addr: usize, size: usize, pid: i32) -> Event {
        Event {
            event_type,
            addr,
            size,
            timestamp: SystemTime::now(),
            timestamp_str: String::new(),
            pid,
            content: None,
            prot: None,
        }
    }

    #[test]
    fn test_event_handler_creation() {
        let handler = EventHandler::new();
        assert_eq!(handler.known_pages.len(), 0);
        assert_eq!(handler.event_counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_process_shutdown_event() {
        let mut handler = EventHandler::new();
        let event = Event {
            event_type: EventType::Shutdown,
            addr: 0x1000,
            size: 0x1000,
            timestamp: SystemTime::now(),
            timestamp_str: String::new(),
            pid: -1,
            content: None,
            prot: None,
        };

        let result = handler.process(event);
        assert!(!result);
    }

    #[test]
    fn test_process_map_event() {
        let mut handler = EventHandler::new();
        let event = create_test_event(EventType::Map, 0x1000, 0x1000, 1);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 1);
        assert!(handler.known_pages.contains_key(&0x1000));
    }

    #[test]
    fn test_process_mprotect_event() {
        let mut handler = EventHandler::new();
        let event = create_test_event(EventType::Mprotect, 0x2000, 0x1000, 1);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 1);
        assert!(handler.known_pages.contains_key(&0x2000));
    }

    #[test]
    fn test_event_counter_increment() {
        let mut handler = EventHandler::new();
        let initial_counter = handler.event_counter.load(Ordering::SeqCst);

        let event1 = create_test_event(EventType::Map, 0x1000, 0x1000, 1);
        handler.process(event1);
        assert_eq!(
            handler.event_counter.load(Ordering::SeqCst),
            initial_counter + 1
        );

        let event2 = create_test_event(EventType::Mprotect, 0x2000, 0x1000, 1);
        handler.process(event2);
        assert_eq!(
            handler.event_counter.load(Ordering::SeqCst),
            initial_counter + 2
        );
    }
}
