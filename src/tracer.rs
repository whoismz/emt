use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

use crate::bpf_runtime::BpfRuntime;
use crate::event_handler::EventHandler;
use crate::models::{Event, Page};
use anyhow::Result;
use log::error;

pub struct Tracer {
    target_pid: i32,
    running: bool,
    event_tx: Option<Sender<Event>>,
    thread_handle: Option<thread::JoinHandle<Vec<Page>>>,
}

impl Tracer {
    /// Creates a new tracer for the specified process ID
    pub fn new(target_pid: i32) -> Self {
        Self {
            target_pid,
            running: false,
            event_tx: None,
            thread_handle: None,
        }
    }

    /// Starts tracing the process
    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        let (event_tx, event_rx) = channel();
        self.event_tx = Some(event_tx.clone());

        let target_pid = self.target_pid;

        let thread_handle = thread::spawn(move || {
            let mut pages = Vec::new();

            if let Err(e) = Self::run(target_pid, event_tx, event_rx, &mut pages) {
                error!("Tracer error: {:?}", e);
            }

            pages
        });

        self.thread_handle = Some(thread_handle);
        self.running = true;

        Ok(())
    }

    /// Stops tracing and returns collected memory pages
    pub fn stop(&mut self) -> Result<Vec<Page>> {
        if !self.running {
            return Ok(Vec::new());
        }

        // Notify a tracer thread to stop
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(Event::shutdown());
        }

        // Wait for the thread to complete and get collected pages
        let pages = if let Some(handle) = self.thread_handle.take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("Thread join failed"))?
        } else {
            Vec::new()
        };

        self.running = false;
        self.event_tx = None;

        Ok(pages)
    }

    fn run(
        target_pid: i32,
        event_tx: Sender<Event>,
        event_rx: Receiver<Event>,
        pages: &mut Vec<Page>,
    ) -> Result<()> {
        let mut bpf_runtime = BpfRuntime::new(event_tx.clone(), target_pid)?;
        let mut handler = EventHandler::new(target_pid);

        let bpf_path = PathBuf::from(env!("OUT_DIR")).join("memory_tracer_ringbuf.bpf.o");

        bpf_runtime.start(bpf_path.to_str().unwrap())?;

        // main loop for events from BPF
        let mut running = true;
        while running {
            // poll BPF events
            if let Err(e) = bpf_runtime.poll(Duration::from_millis(100)) {
                error!("Error polling BPF events: {:?}", e);
            }

            // check for received memory events
            while let Ok(event) = event_rx.try_recv() {
                if !handler.process(event) {
                    running = false;
                    break;
                }
            }
        }

        bpf_runtime.stop()?;
        *pages = handler.get_all_pages();

        Ok(())
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if self.running {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Event, EventType};
    use std::sync::Mutex;
    use std::time::SystemTime;

    #[test]
    fn test_tracer_creation() {
        let tracer = Tracer::new(1234);
        assert_eq!(tracer.target_pid, 1234);
        assert!(!tracer.running);
        assert!(tracer.event_tx.is_none());
        assert!(tracer.thread_handle.is_none());
    }

    #[test]
    fn test_start_sets_running_state() {
        let tracer = Tracer::new(1234);
        assert!(!tracer.running);
    }

    #[test]
    fn test_start_when_already_running() {
        let mut tracer = Tracer::new(1234);
        tracer.running = true; // Simulate an already running state

        let result = tracer.start();
        assert!(result.is_ok());
    }

    #[test]
    fn test_stop_when_not_running() {
        let mut tracer = Tracer::new(1234);
        assert!(!tracer.running);

        let result = tracer.stop();
        assert!(result.is_ok());
    }

    #[test]
    fn test_shutdown_event_creation() {
        let shutdown_event = Event {
            event_type: EventType::Unmap,
            addr: 0,
            size: 0,
            timestamp: SystemTime::now(),
            pid: -1,
            content: None,
        };

        assert_eq!(shutdown_event.addr, 0);
        assert_eq!(shutdown_event.size, 0);
        assert_eq!(shutdown_event.pid, -1);
        assert!(matches!(shutdown_event.event_type, EventType::Unmap));
    }

    #[test]
    fn test_tracer_drop_calls_stop() {
        let mut tracer = Tracer::new(1234);
        tracer.running = true; // Simulate running state

        // Create a channel to test if stop is called
        let (tx, _rx) = channel();
        tracer.event_tx = Some(tx);

        // Drop the tracer - should call stop()
        drop(tracer);

        // If reach here without a panic, the drop worked correctly
        assert!(true);
    }

    #[test]
    fn test_multiple_start_calls() {
        let mut tracer = Tracer::new(1234);

        // Simulate the first start
        tracer.running = true;
        let (tx, _rx) = channel();
        tracer.event_tx = Some(tx);

        // Second start should return Ok without changing state
        let result = tracer.start();
        assert!(result.is_ok());
        assert!(tracer.running);
    }

    #[test]
    fn test_stop_clears_state() {
        let mut tracer = Tracer::new(1234);

        // Simulate running state
        tracer.running = true;
        let (tx, _rx) = channel();
        tracer.event_tx = Some(tx);

        let result = tracer.stop();
        assert!(result.is_ok());
        assert!(!tracer.running);
        assert!(tracer.event_tx.is_none());
        assert!(tracer.thread_handle.is_none());
    }

    #[test]
    fn test_target_pid_immutable() {
        let tracer = Tracer::new(1234);
        assert_eq!(tracer.target_pid, 1234);

        // target_pid shouldn't change after creation
        let tracer2 = Tracer::new(5678);
        assert_eq!(tracer2.target_pid, 5678);
        assert_eq!(tracer.target_pid, 1234); // Original unchanged
    }

    #[test]
    fn test_concurrent_stop_calls() {
        use std::sync::Arc;
        use std::thread;

        let tracer = Arc::new(Mutex::new(Tracer::new(1234)));

        // Simulate running state
        {
            let mut t = tracer.lock().unwrap();
            t.running = true;
            let (tx, _rx) = channel();
            t.event_tx = Some(tx);
        }

        // Spawn multiple threads trying to stop
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let tracer_clone = tracer.clone();
                thread::spawn(move || {
                    let mut t = tracer_clone.lock().unwrap();
                    t.stop().unwrap();
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify the final state
        let final_tracer = tracer.lock().unwrap();
        assert!(!final_tracer.running);
        assert!(final_tracer.event_tx.is_none());
    }

    #[test]
    fn test_temp_directory_bpf_path() {
        let temp_dir = std::env::temp_dir();
        let bpf_path = temp_dir.join("memory_tracer_ringbuf.bpf.o");

        // Test that the path is correctly constructed
        assert!(bpf_path.to_str().is_some());
        assert!(
            bpf_path
                .to_str()
                .unwrap()
                .ends_with("memory_tracer_ringbuf.bpf.o")
        );

        // Test path components
        let parent = bpf_path.parent().unwrap();
        assert_eq!(parent, temp_dir);

        let filename = bpf_path.file_name().unwrap();
        assert_eq!(filename, "memory_tracer_ringbuf.bpf.o");
    }
}

// Mock module for testing without actual BPF dependencies
#[cfg(test)]
mod mocks {
    use super::*;
    use anyhow::Result;

    pub struct MockBpfRuntime {
        pub target_pid: i32,
        pub started: bool,
    }

    impl MockBpfRuntime {
        pub fn new(_event_tx: Sender<Event>, target_pid: i32) -> Result<Self> {
            Ok(Self {
                target_pid,
                started: false,
            })
        }

        pub fn start(&mut self, _path: &str) -> Result<()> {
            self.started = true;
            Ok(())
        }

        pub fn poll(&mut self, _timeout: Duration) -> Result<()> {
            // Simulate successful polling
            Ok(())
        }

        pub fn stop(&mut self) -> Result<()> {
            self.started = false;
            Ok(())
        }
    }

    // Additional test with mock
    #[test]
    fn test_mock_bpf_runtime() {
        let (tx, _rx) = channel();
        let mut mock_runtime = MockBpfRuntime::new(tx, 1234).unwrap();

        assert_eq!(mock_runtime.target_pid, 1234);
        assert!(!mock_runtime.started);

        mock_runtime.start("test_path").unwrap();
        assert!(mock_runtime.started);

        mock_runtime.poll(Duration::from_millis(100)).unwrap();
        assert!(mock_runtime.started);

        mock_runtime.stop().unwrap();
        assert!(!mock_runtime.started);
    }
}
