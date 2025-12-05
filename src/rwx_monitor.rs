use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use log::{debug, error, info, warn};
use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;

use crate::bpf_runtime::BpfRuntime;
use crate::error::{EmtError, Result};
use crate::models::Page;
use crate::ptrace::PtraceController;

pub use crate::ptrace::controller::MemoryExecEvent;

/// Configuration for the RWX monitor
#[derive(Debug, Clone)]
pub struct RwxMonitorConfig {
    /// Path to the BPF object file. If None, uses the default compiled path.
    pub bpf_path: Option<PathBuf>,
    /// Whether to enable BPF-based detection (informational only)
    pub enable_bpf: bool,
    /// Whether to enable ptrace-based interception (required for full functionality)
    pub enable_ptrace: bool,
    /// Timeout for polling operations
    pub poll_timeout: Duration,
}

impl Default for RwxMonitorConfig {
    fn default() -> Self {
        Self {
            bpf_path: None,
            enable_bpf: true,
            enable_ptrace: true,
            poll_timeout: Duration::from_millis(100),
        }
    }
}

/// Callback type for memory execution events
#[allow(dead_code)]
pub type ExecEventCallback = Box<dyn Fn(&MemoryExecEvent) + Send + 'static>;

/// RWX Memory Monitor
///
/// Monitors a target process for RWX memory operations and captures
/// dynamic code before it executes.
pub struct RwxMonitor {
    /// Target process ID
    target_pid: i32,
    /// Configuration
    config: RwxMonitorConfig,
    /// Whether the monitor is running (shared with monitor thread)
    is_running: Arc<AtomicBool>,
    /// Flag to signal the monitoring thread to stop
    stop_flag: Arc<AtomicBool>,
    /// Handle for the main monitoring thread
    monitor_thread: Option<JoinHandle<MonitorResult>>,
    /// Channel to receive execution events
    event_rx: Option<Receiver<MemoryExecEvent>>,
    /// Channel sender for internal use
    event_tx: Option<Sender<MemoryExecEvent>>,
}

/// Result collected when monitor stops
#[derive(Debug, Default)]
pub struct MonitorResult {
    /// All captured memory execution events
    pub exec_events: Vec<MemoryExecEvent>,
    /// All tracked pages (from BPF)
    pub pages: Vec<Page>,
    /// Any errors that occurred
    pub errors: Vec<String>,
}

impl RwxMonitor {
    /// Creates a new RWX monitor for the given target process.
    pub fn new(target_pid: i32) -> Self {
        Self::with_config(target_pid, RwxMonitorConfig::default())
    }

    /// Creates a new RWX monitor with custom configuration.
    pub fn with_config(target_pid: i32, config: RwxMonitorConfig) -> Self {
        Self {
            target_pid,
            config,
            is_running: Arc::new(AtomicBool::new(false)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            monitor_thread: None,
            event_rx: None,
            event_tx: None,
        }
    }

    /// Starts the monitor for RWX memory.
    pub fn start(&mut self) -> Result<()> {
        if self.is_running.load(Ordering::SeqCst) {
            return Err(EmtError::AlreadyRunning);
        }

        // Verify target process exists
        let pid = Pid::from_raw(self.target_pid);
        if let Err(err) = kill(pid, None)
            && err != Errno::EPERM {
                return Err(EmtError::InvalidPid(self.target_pid));
            }

        // Create event channel
        let (event_tx, event_rx) = mpsc::channel();
        self.event_tx = Some(event_tx.clone());
        self.event_rx = Some(event_rx);

        // Reset stop flag
        self.stop_flag.store(false, Ordering::SeqCst);

        let target_pid = self.target_pid;
        let config = self.config.clone();
        let stop_flag = Arc::clone(&self.stop_flag);
        let is_running = Arc::clone(&self.is_running);

        // Synchronization channel for initialization
        let (init_tx, init_rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            let result = Self::run_monitor(target_pid, config, stop_flag, event_tx, init_tx);
            // Clear is_running when monitor thread exits (target exited or stopped)
            is_running.store(false, Ordering::SeqCst);
            result
        });

        // Wait for initialization result
        match init_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {
                self.is_running.store(true, Ordering::SeqCst);
                self.monitor_thread = Some(handle);
                info!("RWX monitor started for PID {}", self.target_pid);
                Ok(())
            }
            Ok(Err(e)) => {
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                self.stop_flag.store(true, Ordering::SeqCst);
                let _ = handle.join();
                Err(EmtError::Other("Monitor initialization timed out".into()))
            }
        }
    }

    /// Stops the RWX monitor and returns collected results.
    pub fn stop(&mut self) -> Result<MonitorResult> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Ok(MonitorResult::default());
        }

        // Signal stop
        self.stop_flag.store(true, Ordering::SeqCst);

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

        self.is_running.store(false, Ordering::SeqCst);
        self.event_rx = None;
        self.event_tx = None;

        info!(
            "RWX monitor stopped. Captured {} execution events",
            result.exec_events.len()
        );

        Ok(result)
    }

    /// Returns whether the monitor is currently running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
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
        config: RwxMonitorConfig,
        stop_flag: Arc<AtomicBool>,
        event_tx: Sender<MemoryExecEvent>,
        init_tx: Sender<Result<()>>,
    ) -> MonitorResult {
        let mut result = MonitorResult::default();

        // Internal channel for ptrace events
        let (ptrace_tx, ptrace_rx) = mpsc::channel();

        // Start ptrace controller if enabled
        let mut ptrace_controller = if config.enable_ptrace {
            let mut controller = PtraceController::new(target_pid);
            match controller.start(Some(ptrace_tx)) {
                Ok(()) => {
                    debug!("Ptrace controller started for PID {}", target_pid);
                    Some(controller)
                }
                Err(e) => {
                    let err_msg = format!("Failed to start ptrace controller: {}", e);
                    error!("{}", err_msg);
                    let _ = init_tx.send(Err(e));
                    result.errors.push(err_msg);
                    return result;
                }
            }
        } else {
            None
        };

        // Start BPF runtime if enabled (for informational events)
        let mut bpf_runtime = if config.enable_bpf {
            let bpf_path = config.bpf_path.unwrap_or_else(|| {
                // Use option_env! to avoid compile-time errors during static analysis
                option_env!("OUT_DIR")
                    .map(|dir| PathBuf::from(dir).join("memory_tracer.bpf.o"))
                    .unwrap_or_else(|| {
                        PathBuf::from("target/debug/build/emt/out/memory_tracer.bpf.o")
                    })
            });

            let (bpf_event_tx, _bpf_event_rx) = mpsc::channel();
            match BpfRuntime::new(bpf_event_tx, target_pid) {
                Ok(mut runtime) => {
                    if let Err(e) = runtime.start(bpf_path.to_str().unwrap_or_default()) {
                        warn!("Failed to start BPF runtime (continuing without): {}", e);
                        None
                    } else {
                        debug!("BPF runtime started for PID {}", target_pid);
                        Some(runtime)
                    }
                }
                Err(e) => {
                    warn!("Failed to create BPF runtime (continuing without): {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Signal successful initialization
        let _ = init_tx.send(Ok(()));

        // Main event loop
        while !stop_flag.load(Ordering::SeqCst) {
            // Check for ptrace events - only forward to channel, not stored in result
            // (to avoid duplicates when user calls both try_recv_event and stop)
            if let Ok(event) = ptrace_rx.try_recv() {
                debug!(
                    "Received execution event at 0x{:x}, {} bytes",
                    event.addr,
                    event.bytes.len()
                );

                // Forward to external listener only
                let _ = event_tx.send(event);
            }

            // Poll BPF for events (informational)
            if let Some(ref mut runtime) = bpf_runtime
                && let Err(e) = runtime.poll(config.poll_timeout) {
                    debug!("BPF poll error: {:?}", e);
                }

            // Small sleep to avoid busy-waiting
            thread::sleep(Duration::from_millis(10));
        }

        // Cleanup
        if let Some(mut controller) = ptrace_controller.take() {
            match controller.stop() {
                Ok(events) => {
                    // Add any remaining events
                    for event in events {
                        let _ = event_tx.send(event.clone());
                        result.exec_events.push(event);
                    }
                }
                Err(e) => {
                    let err_msg = format!("Error stopping ptrace controller: {}", e);
                    error!("{}", err_msg);
                    result.errors.push(err_msg);
                }
            }
        }

        if let Some(mut runtime) = bpf_runtime.take()
            && let Err(e) = runtime.stop() {
                let err_msg = format!("Error stopping BPF runtime: {}", e);
                warn!("{}", err_msg);
                result.errors.push(err_msg);
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
        if self.is_running.load(Ordering::SeqCst) {
            let _ = self.stop();
        }
    }
}

/// Builder for RwxMonitor with fluent API
pub struct RwxMonitorBuilder {
    target_pid: i32,
    config: RwxMonitorConfig,
}

impl RwxMonitorBuilder {
    /// Creates a new builder for the given target PID.
    pub fn new(target_pid: i32) -> Self {
        Self {
            target_pid,
            config: RwxMonitorConfig::default(),
        }
    }

    /// Sets the BPF object file path.
    pub fn bpf_path(mut self, path: PathBuf) -> Self {
        self.config.bpf_path = Some(path);
        self
    }

    /// Enables or disables BPF-based detection.
    pub fn enable_bpf(mut self, enable: bool) -> Self {
        self.config.enable_bpf = enable;
        self
    }

    /// Enables or disables ptrace-based interception.
    pub fn enable_ptrace(mut self, enable: bool) -> Self {
        self.config.enable_ptrace = enable;
        self
    }

    /// Sets the poll timeout duration.
    pub fn poll_timeout(mut self, timeout: Duration) -> Self {
        self.config.poll_timeout = timeout;
        self
    }

    /// Builds the RwxMonitor.
    pub fn build(self) -> RwxMonitor {
        RwxMonitor::with_config(self.target_pid, self.config)
    }
}
