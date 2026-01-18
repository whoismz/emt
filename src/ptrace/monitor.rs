//! RWX memory monitor for capturing dynamic code execution.

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
use super::controller::MemoryExecEvent;
use crate::error::{EmtError, Result};

pub use super::controller::MemoryExecEvent as ExecEvent;

/// Result collected when monitor stops.
#[derive(Debug, Default)]
pub struct MonitorResult {
    /// All captured memory execution events.
    pub exec_events: Vec<MemoryExecEvent>,
    /// Errors that occurred during monitoring.
    pub errors: Vec<String>,
}

/// RWX memory monitor.
///
/// Monitors a target process for RWX memory operations and captures
/// dynamic code before execution.
pub struct RwxMonitor {
    target_pid: i32,
    running: Arc<AtomicBool>,
    monitor_thread: Option<JoinHandle<MonitorResult>>,
    event_rx: Option<Receiver<MemoryExecEvent>>,
}

impl RwxMonitor {
    /// Creates a new monitor for the given target process.
    pub fn new(target_pid: i32) -> Self {
        Self {
            target_pid,
            running: Arc::new(AtomicBool::new(false)),
            monitor_thread: None,
            event_rx: None,
        }
    }

    /// Starts monitoring the target process.
    pub fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(EmtError::AlreadyRunning);
        }

        let pid = Pid::from_raw(self.target_pid);
        if let Err(err) = kill(pid, None) {
            if err != Errno::EPERM {
                return Err(EmtError::InvalidPid(self.target_pid));
            }
        }

        let (event_tx, event_rx) = mpsc::channel();
        self.event_rx = Some(event_rx);

        let target_pid = self.target_pid;
        let running = Arc::clone(&self.running);
        self.running.store(true, Ordering::SeqCst);

        let (init_tx, init_rx) = mpsc::channel();

        let handle =
            thread::spawn(move || Self::run_monitor(target_pid, running, event_tx, init_tx));

        match init_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {
                self.monitor_thread = Some(handle);
                info!("Monitor started for PID {}", self.target_pid);
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

    /// Stops monitoring and returns collected results.
    pub fn stop(&mut self) -> Result<MonitorResult> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(MonitorResult::default());
        }

        self.running.store(false, Ordering::SeqCst);

        let result = if let Some(handle) = self.monitor_thread.take() {
            match handle.join() {
                Ok(result) => result,
                Err(_) => return Err(EmtError::ThreadJoinError),
            }
        } else {
            MonitorResult::default()
        };

        self.event_rx = None;
        info!(
            "Monitor stopped. Captured {} events",
            result.exec_events.len()
        );
        Ok(result)
    }

    /// Returns whether the monitor is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Returns the target process ID.
    pub fn target_pid(&self) -> i32 {
        self.target_pid
    }

    /// Tries to receive the next event without blocking.
    pub fn try_recv_event(&self) -> Option<MemoryExecEvent> {
        self.event_rx.as_ref().and_then(|rx| rx.try_recv().ok())
    }

    /// Receives the next event with a timeout.
    pub fn recv_event_timeout(&self, timeout: Duration) -> Option<MemoryExecEvent> {
        self.event_rx
            .as_ref()
            .and_then(|rx| rx.recv_timeout(timeout).ok())
    }

    fn run_monitor(
        target_pid: i32,
        running: Arc<AtomicBool>,
        event_tx: Sender<MemoryExecEvent>,
        init_tx: Sender<Result<()>>,
    ) -> MonitorResult {
        let mut result = MonitorResult::default();
        let (ptrace_tx, ptrace_rx) = mpsc::channel();

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

        let _ = init_tx.send(Ok(()));

        let mut received_events: Vec<MemoryExecEvent> = Vec::new();

        while running.load(Ordering::SeqCst) {
            if let Ok(event) = ptrace_rx.try_recv() {
                debug!(
                    "Captured execution at 0x{:x}, {} bytes",
                    event.addr,
                    event.bytes.len()
                );
                let _ = event_tx.send(event.clone());
                received_events.push(event);
            }
            thread::sleep(Duration::from_millis(10));
        }

        result.exec_events = received_events;

        match ptrace_controller.stop() {
            Ok(remaining_events) => {
                for event in remaining_events {
                    let already_have = result.exec_events.iter().any(|e| {
                        e.addr == event.addr && e.capture_sequence == event.capture_sequence
                    });
                    if !already_have {
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
}

impl Drop for RwxMonitor {
    fn drop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            let _ = self.stop();
        }
    }
}

/// Builder for RwxMonitor.
pub struct RwxMonitorBuilder {
    target_pid: i32,
}

impl RwxMonitorBuilder {
    /// Creates a new builder for the given target PID.
    pub fn new(target_pid: i32) -> Self {
        Self { target_pid }
    }

    /// Builds the monitor.
    pub fn build(self) -> RwxMonitor {
        RwxMonitor::new(self.target_pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== MonitorResult Tests ====================

    #[test]
    fn test_monitor_result_default() {
        let result = MonitorResult::default();

        assert!(result.exec_events.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_monitor_result_with_events() {
        let mut result = MonitorResult::default();

        // Simulate adding events
        result.errors.push("test error".to_string());

        assert!(result.exec_events.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0], "test error");
    }

    // ==================== RwxMonitor Tests ====================

    #[test]
    fn test_rwx_monitor_new() {
        let monitor = RwxMonitor::new(1234);

        assert_eq!(monitor.target_pid, 1234);
        assert!(!monitor.running.load(Ordering::SeqCst));
        assert!(monitor.monitor_thread.is_none());
        assert!(monitor.event_rx.is_none());
    }

    #[test]
    fn test_rwx_monitor_target_pid() {
        let monitor = RwxMonitor::new(5678);

        assert_eq!(monitor.target_pid(), 5678);
    }

    #[test]
    fn test_rwx_monitor_is_running_initial() {
        let monitor = RwxMonitor::new(1234);

        assert!(!monitor.is_running());
    }

    #[test]
    fn test_rwx_monitor_stop_when_not_running() {
        let mut monitor = RwxMonitor::new(1234);

        // Stop should succeed and return empty result when not running
        let result = monitor.stop();
        assert!(result.is_ok());

        let monitor_result = result.unwrap();
        assert!(monitor_result.exec_events.is_empty());
        assert!(monitor_result.errors.is_empty());
    }

    #[test]
    fn test_rwx_monitor_try_recv_event_no_receiver() {
        let monitor = RwxMonitor::new(1234);

        // Should return None when no event_rx is set
        assert!(monitor.try_recv_event().is_none());
    }

    #[test]
    fn test_rwx_monitor_recv_event_timeout_no_receiver() {
        let monitor = RwxMonitor::new(1234);

        // Should return None when no event_rx is set
        assert!(
            monitor
                .recv_event_timeout(Duration::from_millis(10))
                .is_none()
        );
    }

    #[test]
    fn test_rwx_monitor_start_invalid_pid() {
        let mut monitor = RwxMonitor::new(-1);

        // Starting with invalid PID should fail
        let result = monitor.start();
        assert!(result.is_err());
    }

    #[test]
    fn test_rwx_monitor_start_nonexistent_pid() {
        // Use a very high PID that's unlikely to exist
        let mut monitor = RwxMonitor::new(999999999);

        let result = monitor.start();
        assert!(result.is_err());
    }

    // ==================== RwxMonitorBuilder Tests ====================

    #[test]
    fn test_rwx_monitor_builder_new() {
        let builder = RwxMonitorBuilder::new(1234);

        assert_eq!(builder.target_pid, 1234);
    }

    #[test]
    fn test_rwx_monitor_builder_build() {
        let builder = RwxMonitorBuilder::new(5678);
        let monitor = builder.build();

        assert_eq!(monitor.target_pid(), 5678);
        assert!(!monitor.is_running());
    }

    #[test]
    fn test_rwx_monitor_builder_chain() {
        let monitor = RwxMonitorBuilder::new(9999).build();

        assert_eq!(monitor.target_pid(), 9999);
    }

    // ==================== Running State Tests ====================

    #[test]
    fn test_rwx_monitor_running_flag() {
        let monitor = RwxMonitor::new(1234);

        // Initially not running
        assert!(!monitor.running.load(Ordering::SeqCst));

        // Manually set running flag (simulating start)
        monitor.running.store(true, Ordering::SeqCst);
        assert!(monitor.is_running());

        // Manually clear running flag (simulating stop)
        monitor.running.store(false, Ordering::SeqCst);
        assert!(!monitor.is_running());
    }

    // ==================== Drop Tests ====================

    #[test]
    fn test_rwx_monitor_drop_when_not_running() {
        let monitor = RwxMonitor::new(1234);
        // Drop should complete without panic
        drop(monitor);
    }

    #[test]
    fn test_rwx_monitor_drop_cleans_up() {
        let monitor = RwxMonitor::new(1234);
        let running = Arc::clone(&monitor.running);

        // Simulate running state
        running.store(true, Ordering::SeqCst);

        // Drop the monitor
        drop(monitor);

        // After drop, the running flag should be false
        // (In actual implementation, stop() is called which sets it to false)
    }
}
