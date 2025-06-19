use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use libbpf_rs::{ErrorKind, Link, MapCore, Object, ObjectBuilder, RingBuffer, RingBufferBuilder};

use crate::error::{EmtError, Result};
use crate::models::{Event, EventType};
use crate::utils::boot_time_seconds;

const MAX_SNAPSHOT_SIZE: usize = 4096;

/// Manages the BPF program lifecycle including loading, attaching, and processing memory events
pub struct BpfRuntime {
    bpf_object: Option<Object>,
    ring_buffer: Option<RingBuffer<'static>>,
    probe_links: Vec<Link>,
    event_tx: Sender<Event>,
    target_pid: i32,
    is_active: bool,
}

impl BpfRuntime {
    /// Creates a new BPF runtime instance
    pub fn new(event_tx: Sender<Event>, target_pid: i32) -> Result<Self> {
        Ok(Self {
            bpf_object: None,
            ring_buffer: None,
            probe_links: Vec::new(),
            event_tx,
            target_pid,
            is_active: false,
        })
    }

    /// Starts the BPF runtime by loading the object, attaching probes, and initializing the ring buffer
    pub fn start(&mut self, bpf_path: impl AsRef<Path>) -> Result<()> {
        if self.is_active {
            return Ok(());
        }

        let bpf_path = bpf_path.as_ref();
        if !bpf_path.exists() {
            return Err(EmtError::BpfNotFound(bpf_path.display().to_string()));
        }

        // Load BPF object
        let mut bpf_object = ObjectBuilder::default()
            .open_file(bpf_path)
            .map_err(|e| EmtError::OpenBpfError(format!("Failed to open BPF object file: {}", e)))?
            .load()
            .map_err(|e| EmtError::LoadBpfError(format!("Failed to load BPF object: {}", e)))?;

        // Attach probes and initialize the ring buffer
        self.attach_probes(&mut bpf_object)?;
        self.init_ring_buffer(&bpf_object)?;

        self.bpf_object = Some(bpf_object);
        self.is_active = true;
        Ok(())
    }

    /// Attaches BPF programs to tracepoints defined in the object
    fn attach_probes(&mut self, bpf_object: &mut Object) -> Result<()> {
        const TRACEPOINTS: &[(&str, &str, &str)] = &[
            ("trace_enter_mmap", "syscalls", "sys_enter_mmap"),
            ("trace_exit_mmap", "syscalls", "sys_exit_mmap"),
            ("trace_munmap", "syscalls", "sys_enter_munmap"),
            ("trace_enter_mprotect", "syscalls", "sys_enter_mprotect"),
            ("trace_exit_mprotect", "syscalls", "sys_exit_mprotect"),
        ];

        for prog in bpf_object.progs_mut() {
            let prog_name = prog.name().to_str().unwrap_or_default().to_string();

            if let Some((_, subsystem, tracepoint)) =
                TRACEPOINTS.iter().find(|(name, _, _)| *name == prog_name)
            {
                let link = prog
                    .attach_tracepoint(subsystem, tracepoint)
                    .map_err(|e| EmtError::AttachProbeFailed(prog_name.clone(), e))?;
                self.probe_links.push(link);
            }
        }
        Ok(())
    }

    /// Initializes the ring buffer and registers the callback for incoming events
    fn init_ring_buffer(&mut self, bpf_object: &Object) -> Result<()> {
        let events_map = bpf_object
            .maps()
            .find(|map| map.name() == "events")
            .ok_or_else(|| EmtError::MapError("Failed to find events map".into()))?;

        let event_tx = Arc::new(self.event_tx.clone());
        let target_pid = self.target_pid;

        let mut builder = RingBufferBuilder::new();

        builder
            .add(&events_map, move |data: &[u8]| {
                Self::handle_ringbuf_event(data, &event_tx, target_pid);
                0
            })
            .map_err(|e| EmtError::RingBufInit(format!("Failed to add callback: {}", e)))?;

        self.ring_buffer =
            Some(builder.build().map_err(|e| {
                EmtError::RingBufInit(format!("Failed to create ring buffer: {}", e))
            })?);

        Ok(())
    }

    /// Parses a raw ring buffer event and sends it if PID matches target
    fn handle_ringbuf_event(data: &[u8], event_tx: &Arc<Sender<Event>>, target_pid: i32) {
        use std::mem::size_of;

        if data.len() >= size_of::<RawMemoryEvent>() {
            let raw_event =
                unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawMemoryEvent) };

            if raw_event.pid as i32 == target_pid {
                let event = Event::from(raw_event);
                let _ = event_tx.send(event);
            }
        }
    }

    /// Polls the ring buffer for events with a timeout
    pub fn poll(&mut self, timeout: Duration) -> Result<()> {
        if !self.is_active {
            return Ok(());
        }

        let rb = self
            .ring_buffer
            .as_mut()
            .ok_or(EmtError::RingBufNotInitialized)?;

        loop {
            match rb.poll(timeout) {
                Ok(()) => break Ok(()),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => break Err(EmtError::Bpf(e)),
            }
        }
    }

    /// Stops the BPF runtime and cleans up resources
    pub fn stop(&mut self) -> Result<()> {
        self.is_active = false;
        self.ring_buffer.take();
        self.bpf_object.take();
        self.probe_links.clear();
        Ok(())
    }
}

impl Drop for BpfRuntime {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The raw memory event structure sent by the BPF program
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
struct RawMemoryEvent {
    addr: u64,
    length: u64,
    pid: u32,
    event_type: u32,
    timestamp: u64,
    content_size: u64,
    content: [u8; MAX_SNAPSHOT_SIZE],
}

/// Conversion from RawMemoryEvent to Event structure
impl From<RawMemoryEvent> for Event {
    fn from(raw: RawMemoryEvent) -> Self {
        let event_type = match raw.event_type {
            0 => EventType::Map,
            1 => EventType::Unmap,
            2 => EventType::Mprotect,
            _ => EventType::Map,
        };

        let content = if raw.content_size > 0 && raw.content_size <= MAX_SNAPSHOT_SIZE as u64 {
            let mut content_vec = Vec::with_capacity(raw.content_size as usize);
            content_vec.extend_from_slice(&raw.content[..raw.content_size as usize]);
            Some(content_vec)
        } else {
            None
        };

        let boot_time = boot_time_seconds();
        let timestamp = SystemTime::UNIX_EPOCH
            + Duration::from_secs(boot_time)
            + Duration::from_nanos(raw.timestamp);

        let timestamp_str: String = match DateTime::<Utc>::from(timestamp)
            .format("%Y-%m-%d %H:%M:%S%.3f")
            .to_string()
        {
            s => s,
        };

        Event {
            event_type,
            addr: raw.addr as usize,
            size: raw.length as usize,
            timestamp: timestamp,
            timestamp_str: timestamp_str,
            pid: raw.pid as i32,
            content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Event, EventType};
    use std::sync::mpsc;
    use std::time::Duration;

    fn create_test_sender() -> (Sender<Event>, mpsc::Receiver<Event>) {
        mpsc::channel()
    }

    #[test]
    fn test_bpf_runtime_creation() {
        let (tx, _rx) = create_test_sender();
        let runtime = BpfRuntime::new(tx, 1234).unwrap();

        assert_eq!(runtime.target_pid, 1234);
        assert!(!runtime.is_active);
        assert!(runtime.bpf_object.is_none());
        assert!(runtime.ring_buffer.is_none());
        assert!(runtime.probe_links.is_empty());
    }

    #[test]
    fn test_target_pid_stored_correctly() {
        let (tx, _rx) = create_test_sender();
        let runtime = BpfRuntime::new(tx, 5678).unwrap();

        assert_eq!(runtime.target_pid, 5678);
    }

    #[test]
    fn test_start_with_missing_file() {
        let (tx, _rx) = create_test_sender();
        let mut runtime = BpfRuntime::new(tx, 1234).unwrap();

        let result = runtime.start("/nonexistent/path/to/bpf.o");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("BPF program not found")
        );
        assert!(!runtime.is_active);
    }

    #[test]
    fn test_start_when_already_active() {
        let (tx, _rx) = create_test_sender();
        let mut runtime = BpfRuntime::new(tx, 1234).unwrap();

        runtime.is_active = true;

        let result = runtime.start("/some/path/to/bpf.o");
        assert!(result.is_ok());
        assert!(runtime.is_active);
    }

    #[test]
    fn test_stop_when_not_active() {
        let (tx, _rx) = create_test_sender();
        let mut runtime = BpfRuntime::new(tx, 1234).unwrap();

        assert!(!runtime.is_active);
        let result = runtime.stop();
        assert!(result.is_ok());
        assert!(!runtime.is_active);
    }

    #[test]
    fn test_stop_clears_state() {
        let (tx, _rx) = create_test_sender();
        let mut runtime = BpfRuntime::new(tx, 1234).unwrap();

        runtime.is_active = true;

        let result = runtime.stop();
        assert!(result.is_ok());
        assert!(!runtime.is_active);
        assert!(runtime.bpf_object.is_none());
        assert!(runtime.ring_buffer.is_none());
        assert!(runtime.probe_links.is_empty());
    }

    #[test]
    fn test_poll_when_not_active() {
        let (tx, _rx) = create_test_sender();
        let mut runtime = BpfRuntime::new(tx, 1234).unwrap();

        assert!(!runtime.is_active);
        let result = runtime.poll(Duration::from_millis(100));
        assert!(result.is_ok());
    }

    #[test]
    fn test_poll_without_ring_buffer() {
        let (tx, _rx) = create_test_sender();
        let mut runtime = BpfRuntime::new(tx, 1234).unwrap();

        runtime.is_active = true;

        let result = runtime.poll(Duration::from_millis(100));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Ring buffer not initialized")
        );
    }

    #[test]
    fn test_drop_calls_stop() {
        let (tx, _rx) = create_test_sender();
        let mut runtime = BpfRuntime::new(tx, 1234).unwrap();

        runtime.is_active = true;

        drop(runtime);
        assert!(true);
    }

    #[test]
    fn test_raw_memory_event_creation() {
        let raw_event = RawMemoryEvent {
            addr: 0x1000,
            length: 0x2000,
            pid: 1234,
            event_type: 0,
            timestamp: 1000000000,
            content_size: 4,
            content: [0; MAX_SNAPSHOT_SIZE],
        };

        assert_eq!(raw_event.addr, 0x1000);
        assert_eq!(raw_event.length, 0x2000);
        assert_eq!(raw_event.pid, 1234);
        assert_eq!(raw_event.event_type, 0);
        assert_eq!(raw_event.timestamp, 1000000000);
        assert_eq!(raw_event.content_size, 4);
    }

    #[test]
    fn test_event_conversion_map_type() {
        let mut content = [0u8; MAX_SNAPSHOT_SIZE];
        content[0] = 0x90;
        content[1] = 0x90;
        content[2] = 0x90;
        content[3] = 0x90;

        let raw_event = RawMemoryEvent {
            addr: 0x1000,
            length: 0x2000,
            pid: 1234,
            event_type: 0,
            timestamp: 1000000000,
            content_size: 4,
            content,
        };

        let event: Event = raw_event.into();

        assert!(matches!(event.event_type, EventType::Map));
        assert_eq!(event.addr, 0x1000);
        assert_eq!(event.size, 0x2000);
        assert_eq!(event.pid, 1234);
        assert!(event.content.is_some());
        assert_eq!(event.content.unwrap().len(), 4);
    }

    #[test]
    fn test_event_conversion_unmap_type() {
        let raw_event = RawMemoryEvent {
            addr: 0x1000,
            length: 0x2000,
            pid: 1234,
            event_type: 1,
            timestamp: 1000000000,
            content_size: 0,
            content: [0; MAX_SNAPSHOT_SIZE],
        };

        let event: Event = raw_event.into();

        assert!(matches!(event.event_type, EventType::Unmap));
        assert_eq!(event.addr, 0x1000);
        assert_eq!(event.size, 0x2000);
        assert_eq!(event.pid, 1234);
        assert!(event.content.is_none());
    }

    #[test]
    fn test_event_conversion_mprotect_type() {
        let raw_event = RawMemoryEvent {
            addr: 0x1000,
            length: 0x2000,
            pid: 1234,
            event_type: 2,
            timestamp: 1000000000,
            content_size: 0,
            content: [0; MAX_SNAPSHOT_SIZE],
        };

        let event: Event = raw_event.into();

        assert!(matches!(event.event_type, EventType::Mprotect));
        assert_eq!(event.addr, 0x1000);
        assert_eq!(event.size, 0x2000);
        assert_eq!(event.pid, 1234);
    }

    #[test]
    fn test_event_conversion_no_content() {
        let raw_event = RawMemoryEvent {
            addr: 0x1000,
            length: 0x2000,
            pid: 1234,
            event_type: 0,
            timestamp: 1000000000,
            content_size: 0,
            content: [0; MAX_SNAPSHOT_SIZE],
        };

        let event: Event = raw_event.into();

        assert!(event.content.is_none());
    }

    #[test]
    fn test_event_conversion_content_size_exceeds_max() {
        let raw_event = RawMemoryEvent {
            addr: 0x1000,
            length: 0x2000,
            pid: 1234,
            event_type: 0,
            timestamp: 1000000000,
            content_size: (MAX_SNAPSHOT_SIZE + 100) as u64,
            content: [0xFF; MAX_SNAPSHOT_SIZE],
        };

        let event: Event = raw_event.into();

        assert!(event.content.is_none());
    }

    #[test]
    fn test_event_conversion_partial_content() {
        let mut content = [0u8; MAX_SNAPSHOT_SIZE];
        content[0] = 0xDE;
        content[1] = 0xAD;
        content[2] = 0xBE;
        content[3] = 0xEF;

        let raw_event = RawMemoryEvent {
            addr: 0x1000,
            length: 0x2000,
            pid: 1234,
            event_type: 0,
            timestamp: 1000000000,
            content_size: 4,
            content,
        };

        let event: Event = raw_event.into();

        assert!(event.content.is_some());
        let content_vec = event.content.unwrap();
        assert_eq!(content_vec.len(), 4);
        assert_eq!(content_vec[0], 0xDE);
        assert_eq!(content_vec[1], 0xAD);
        assert_eq!(content_vec[2], 0xBE);
        assert_eq!(content_vec[3], 0xEF);
    }

    #[test]
    fn test_tracepoints_configuration() {
        const TRACEPOINTS: &[(&str, &str, &str)] = &[
            ("trace_enter_mmap", "syscalls", "sys_enter_mmap"),
            ("trace_exit_mmap", "syscalls", "sys_exit_mmap"),
            ("trace_munmap", "syscalls", "sys_enter_munmap"),
            ("trace_enter_mprotect", "syscalls", "sys_enter_mprotect"),
            ("trace_exit_mprotect", "syscalls", "sys_exit_mprotect"),
        ];

        assert_eq!(TRACEPOINTS.len(), 5);

        for (_, subsystem, _) in TRACEPOINTS {
            assert_eq!(*subsystem, "syscalls");
        }

        let names: Vec<&str> = TRACEPOINTS.iter().map(|(name, _, _)| *name).collect();
        assert!(names.contains(&"trace_enter_mmap"));
        assert!(names.contains(&"trace_exit_mmap"));
        assert!(names.contains(&"trace_munmap"));
        assert!(names.contains(&"trace_enter_mprotect"));
        assert!(names.contains(&"trace_exit_mprotect"));
    }

    #[test]
    fn test_handle_ringbuf_event_correct_pid() {
        let (tx, rx) = create_test_sender();
        let event_tx = Arc::new(tx);
        let target_pid = 1234;

        let raw_event = RawMemoryEvent {
            addr: 0x1000,
            length: 0x2000,
            pid: 1234,
            event_type: 0,
            timestamp: 1000000000,
            content_size: 0,
            content: [0; MAX_SNAPSHOT_SIZE],
        };

        let data = unsafe {
            std::slice::from_raw_parts(
                &raw_event as *const _ as *const u8,
                size_of::<RawMemoryEvent>(),
            )
        };

        BpfRuntime::handle_ringbuf_event(data, &event_tx, target_pid);

        let received_event = rx.try_recv().unwrap();
        assert_eq!(received_event.pid, 1234);
        assert_eq!(received_event.addr, 0x1000);
    }

    #[test]
    fn test_handle_ringbuf_event_wrong_pid() {
        let (tx, rx) = create_test_sender();
        let event_tx = Arc::new(tx);
        let target_pid = 1234;

        let raw_event = RawMemoryEvent {
            addr: 0x1000,
            length: 0x2000,
            pid: 5678,
            event_type: 0,
            timestamp: 1000000000,
            content_size: 0,
            content: [0; MAX_SNAPSHOT_SIZE],
        };

        let data = unsafe {
            std::slice::from_raw_parts(
                &raw_event as *const _ as *const u8,
                size_of::<RawMemoryEvent>(),
            )
        };

        BpfRuntime::handle_ringbuf_event(data, &event_tx, target_pid);

        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_handle_ringbuf_event_insufficient_data() {
        let (tx, rx) = create_test_sender();
        let event_tx = Arc::new(tx);
        let target_pid = 1234;
        let small_data = vec![0u8; 10];

        BpfRuntime::handle_ringbuf_event(&small_data, &event_tx, target_pid);

        assert!(rx.try_recv().is_err());
    }
}
