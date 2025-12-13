use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use log::{debug, error, info};
use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;

use super::PtraceController;
use crate::error::{EmtError, Result};

pub use super::controller::MemoryExecEvent;

/// RWX Memory Monitor
///
/// Monitors a target process for RWX memory operations and captures
/// dynamic code before it executes.
pub struct RwxMonitor {
    target_pid: i32,
    running: Arc<AtomicBool>,
    monitor_thread: Option<JoinHandle<MonitorResult>>,
    event_rx: Option<Receiver<MemoryExecEvent>>,
}

/// Result collected when monitor stops
#[derive(Debug, Default)]
pub struct MonitorResult {
    /// All captured memory execution events
    pub exec_events: Vec<MemoryExecEvent>,
    /// Any errors that occurred
    pub errors: Vec<String>,
}

impl RwxMonitor {
    /// Creates a new RWX monitor for the given target process.
    pub fn new(target_pid: i32) -> Self {
        Self {
            target_pid,
            running: Arc::new(AtomicBool::new(false)),
            monitor_thread: None,
            event_rx: None,
        }
    }

    /// Starts the monitor for RWX memory.
    pub fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(EmtError::AlreadyRunning);
        }

        // Verify target process exists
        let pid = Pid::from_raw(self.target_pid);
        if let Err(err) = kill(pid, None)
            && err != Errno::EPERM
        {
            return Err(EmtError::InvalidPid(self.target_pid));
        }

        // Create event channel
        let (event_tx, event_rx) = mpsc::channel();
        self.event_rx = Some(event_rx);

        let target_pid = self.target_pid;
        let running = Arc::clone(&self.running);

        // Set running to true BEFORE spawning thread to avoid race condition
        self.running.store(true, Ordering::SeqCst);

        // Synchronization channel for initialization
        let (init_tx, init_rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            let result = Self::run_monitor(target_pid, running, event_tx, init_tx);
            result
        });

        // Wait for initialization result
        match init_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {
                self.monitor_thread = Some(handle);
                info!("RWX monitor started for PID {}", self.target_pid);
                Ok(())
            }
            Ok(Err(e)) => {
                self.running.store(false, Ordering::SeqCst);
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                self.running.store(false, Ordering::SeqCst);
                let _ = handle.join();
                Err(EmtError::Other("Monitor initialization timed out".into()))
            }
        }
    }

    /// Stops the RWX monitor and returns collected results.
    pub fn stop(&mut self) -> Result<MonitorResult> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(MonitorResult::default());
        }

        // Signal stop by setting running to false
        self.running.store(false, Ordering::SeqCst);

        // Wait for thread to finish
        let result = if let Some(handle) = self.monitor_thread.take() {
            match handle.join() {
                Ok(result) => result,
                Err(_) => {
                    return Err(EmtError::ThreadJoinError);
                }
            }
        } else {
            MonitorResult::default()
        };

        self.event_rx = None;

        info!(
            "RWX monitor stopped. Captured {} execution events",
            result.exec_events.len()
        );

        Ok(result)
    }

    /// Returns whether the monitor is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Tries to receive the next execution event without blocking.
    pub fn try_recv_event(&self) -> Option<MemoryExecEvent> {
        self.event_rx.as_ref().and_then(|rx| rx.try_recv().ok())
    }

    /// Receives the next execution event, blocking until one is available
    pub fn recv_event_timeout(&self, timeout: Duration) -> Option<MemoryExecEvent> {
        self.event_rx
            .as_ref()
            .and_then(|rx| rx.recv_timeout(timeout).ok())
    }

    /// Main monitoring loop
    fn run_monitor(
        target_pid: i32,
        running: Arc<AtomicBool>,
        event_tx: Sender<MemoryExecEvent>,
        init_tx: Sender<Result<()>>,
    ) -> MonitorResult {
        let mut result = MonitorResult::default();

        // Internal channel for ptrace events
        let (ptrace_tx, ptrace_rx) = mpsc::channel();

        // Start ptrace controller
        let mut ptrace_controller = {
            let mut controller = PtraceController::new(target_pid);
            match controller.start(Some(ptrace_tx)) {
                Ok(()) => {
                    debug!("Ptrace controller started for PID {}", target_pid);
                    controller
                }
                Err(e) => {
                    let err_msg = format!("Failed to start ptrace controller: {}", e);
                    error!("{}", err_msg);
                    let _ = init_tx.send(Err(e));
                    result.errors.push(err_msg);
                    return result;
                }
            }
        };

        // Signal successful initialization
        let _ = init_tx.send(Ok(()));

        // Track events received during main loop
        let mut received_events: Vec<MemoryExecEvent> = Vec::new();

        // Main event loop - continues while running is true
        while running.load(Ordering::SeqCst) {
            // Check for ptrace events
            if let Ok(event) = ptrace_rx.try_recv() {
                debug!(
                    "Received execution event at 0x{:x}, {} bytes",
                    event.addr,
                    event.bytes.len()
                );

                // Forward to external listener (ignore send errors if channel closed)
                let _ = event_tx.send(event.clone());

                // Also track locally for result
                received_events.push(event);
            }

            // Small sleep to avoid busy-waiting
            thread::sleep(Duration::from_millis(10));
        }

        // Add all events received during main loop to result
        result.exec_events = received_events;

        // Cleanup
        match ptrace_controller.stop() {
            Ok(remaining_events) => {
                // Add any events that weren't received via the channel
                for event in remaining_events {
                    // Check if we already have this event (by address and capture sequence)
                    let already_have = result.exec_events.iter().any(|e| {
                        e.addr == event.addr && e.capture_sequence == event.capture_sequence
                    });
                    if !already_have {
                        // Forward to external listener if channel still open
                        let _ = event_tx.send(event.clone());
                        result.exec_events.push(event);
                    }
                }
            }
            Err(e) => {
                let err_msg = format!("Error stopping ptrace controller: {}", e);
                error!("{}", err_msg);
                result.errors.push(err_msg);
            }
        }

        result
    }

    /// Returns the target process ID.
    pub fn target_pid(&self) -> i32 {
        self.target_pid
    }
}

impl Drop for RwxMonitor {
    fn drop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            let _ = self.stop();
        }
    }
}

/// Builder for RwxMonitor with fluent API
pub struct RwxMonitorBuilder {
    target_pid: i32,
}

impl RwxMonitorBuilder {
    /// Creates a new builder for the given target PID.
    pub fn new(target_pid: i32) -> Self {
        Self { target_pid }
    }

    /// Builds the RwxMonitor.
    pub fn build(self) -> RwxMonitor {
        RwxMonitor::new(self.target_pid)
    }
}
