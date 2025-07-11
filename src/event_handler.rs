use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use log::debug;

use crate::models::{Event, EventType, Page};
use crate::utils;

const PAGE_SIZE: usize = 4096;

/// Handles memory events and keeps track of memory pages for a specific target PID.
pub struct EventHandler {
    target_pid: i32,
    event_counter: AtomicUsize,
    known_pages: HashMap<usize, Page>,
}

impl EventHandler {
    /// Creates a new EventHandler for a specific target PID.
    pub fn new(target_pid: i32) -> Self {
        Self {
            target_pid,
            event_counter: AtomicUsize::new(1),
            known_pages: HashMap::new(),
        }
    }

    /// Divides a memory event into one or more memory pages.
    fn get_page_from_event(event: Event) -> Page {
        let page = Page {
            addr: event.addr,
            size: PAGE_SIZE,
            timestamp: event.timestamp_str,
            source_file: None,
            content: event.content,
        };
        
        page
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
        // Shutdown event
        if event.pid == -1 {
            return false;
        }

        // Ignore unrelated process
        if event.pid != self.target_pid {
            return true;
        }

        let event_id = self.event_counter.fetch_add(1, Ordering::SeqCst);

        if !matches!(event.event_type, EventType::Unmap) {
            debug!(
                "{}: type: {:?}, addr: {:x}, size: {}, timestamp: {:?}",
                event_id, event.event_type, event.addr, event.size, event.timestamp_str,
            );
        }

        if let Some(content) = &event.content {
            utils::print_memory_content(content, event.addr);
        }

        match event.event_type {
            EventType::Map => {
                let page = EventHandler::get_page_from_event(event);
                self.known_pages.insert(page.addr, page);
            }

            EventType::Mprotect => {
                let page = EventHandler::get_page_from_event(event);
                self.known_pages.insert(page.addr, page);
            }

            EventType::Unmap => {
                let page = EventHandler::get_page_from_event(event);
                self.known_pages.remove(&page.addr);
            }
        }
        true
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
        }
    }

    #[test]
    fn test_event_handler_creation() {
        let handler = EventHandler::new(1);
        assert_eq!(handler.target_pid, 1);
        assert_eq!(handler.known_pages.len(), 0);
        assert_eq!(handler.event_counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_get_pages_from_event_page_aligned() {
        let event = create_test_event(EventType::Map, 0x2000, 0x1000, 1);
        let pages = EventHandler::get_page_from_event(event);

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].addr, 0x2000);
    }

    #[test]
    fn test_get_pages_from_event_zero_size() {
        let event = create_test_event(EventType::Map, 0x1000, 0, 1);
        let pages = EventHandler::get_page_from_event(event);

        assert_eq!(pages.len(), 0);
    }

    #[test]
    fn test_process_wrong_pid() {
        let mut handler = EventHandler::new(1);
        let event = create_test_event(EventType::Map, 0x1000, 0x1000, 2);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 0);
    }

    #[test]
    fn test_process_shutdown_event() {
        let mut handler = EventHandler::new(1);
        let event = Event {
            event_type: EventType::Map,
            addr: 0x1000,
            size: 0x1000,
            timestamp: SystemTime::now(),
            timestamp_str: String::new(),
            pid: -1,
            content: None,
        };

        let result = handler.process(event);
        assert!(!result);
    }

    #[test]
    fn test_process_map_event() {
        let mut handler = EventHandler::new(1);
        let event = create_test_event(EventType::Map, 0x1000, 0x1000, 1);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 1);
        assert!(handler.known_pages.contains_key(&0x1000));
    }

    #[test]
    fn test_process_map_event_multiple_pages() {
        let mut handler = EventHandler::new(1);
        let event = create_test_event(EventType::Map, 0x1000, 0x3000, 1);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 3);
        assert!(handler.known_pages.contains_key(&0x1000));
        assert!(handler.known_pages.contains_key(&0x2000));
        assert!(handler.known_pages.contains_key(&0x3000));
    }

    #[test]
    fn test_process_mprotect_event() {
        let mut handler = EventHandler::new(1);
        let event = create_test_event(EventType::Mprotect, 0x2000, 0x1000, 1);

        let result = handler.process(event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 1);
        assert!(handler.known_pages.contains_key(&0x2000));
    }

    #[test]
    fn test_process_unmap_event() {
        let mut handler = EventHandler::new(1);

        let map_event = create_test_event(EventType::Map, 0x1000, 0x2000, 1);
        handler.process(map_event);
        assert_eq!(handler.known_pages.len(), 2);

        let unmap_event = create_test_event(EventType::Unmap, 0x1000, 0x1000, 1);
        let result = handler.process(unmap_event);
        assert!(result);
        assert_eq!(handler.known_pages.len(), 1);
        assert!(!handler.known_pages.contains_key(&0x1000));
        assert!(handler.known_pages.contains_key(&0x2000));
    }

    #[test]
    fn test_process_unmap_partial_overlap() {
        let mut handler = EventHandler::new(1);

        let map_event = create_test_event(EventType::Map, 0x1000, 0x4000, 1);
        handler.process(map_event);
        assert_eq!(handler.known_pages.len(), 4);

        let unmap_event = create_test_event(EventType::Unmap, 0x2000, 0x2000, 1);
        handler.process(unmap_event);
        assert_eq!(handler.known_pages.len(), 2);
        assert!(handler.known_pages.contains_key(&0x1000));
        assert!(!handler.known_pages.contains_key(&0x2000));
        assert!(!handler.known_pages.contains_key(&0x3000));
        assert!(handler.known_pages.contains_key(&0x4000));
    }

    #[test]
    fn test_event_counter_increment() {
        let mut handler = EventHandler::new(1);
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
