use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

use log::error;
use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;

use crate::bpf_runtime::BpfRuntime;
use crate::error::{EmtError, Result};
use crate::event_handler::EventHandler;
use crate::models::{Event, Page};

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

        // Check if the target PID exists
        let pid = Pid::from_raw(self.target_pid);
        if let Err(err) = kill(pid, None) {
            if err != Errno::EPERM {
                return Err(EmtError::InvalidPid(self.target_pid));
            }
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
            handle.join().map_err(|_| EmtError::ThreadJoinError)?
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

    #[test]
    fn test_tracer_creation() {
        let tracer = Tracer::new(1);
        assert_eq!(tracer.target_pid, 1);
        assert!(!tracer.running);
        assert!(tracer.event_tx.is_none());
        assert!(tracer.thread_handle.is_none());
    }

    #[test]
    fn test_multi_starts() {
        let mut tracer = Tracer::new(1);

        // Simulate an already running state
        tracer.running = true;

        let result = tracer.start();
        assert!(result.is_ok());

        let _ = tracer.stop();
    }

    #[test]
    fn test_stop_when_not_running() {
        let mut tracer = Tracer::new(1);
        assert!(!tracer.running);

        let result = tracer.stop().unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_tracer_drop_calls_stop() {
        let mut tracer = Tracer::new(1);

        // Simulate running state
        tracer.running = true;
        let (tx, _rx) = channel();
        tracer.event_tx = Some(tx);

        // Drop the tracer - should call stop()
        drop(tracer);

        // If reach here without a panic, the drop worked correctly
        assert!(true);
    }

    #[test]
    fn test_stop_clears_state() {
        let mut tracer = Tracer::new(1);

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
    fn test_shutdown_event_helper() {
        let event = Event::shutdown();
        assert_eq!(event.pid, -1);
    }
}
