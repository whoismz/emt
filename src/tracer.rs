use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::Result;

use crate::bpf_runtime::BpfRuntime;
use crate::event_handler::EventHandler;
use crate::models::{Event, EventType, };

pub struct Tracer {
    target_pid: i32,
    running: bool,
    event_tx: Option<Sender<Event>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

const BPF_OBJECT: &[u8] = include_bytes!("../src/bpf/memory_tracer_ringbuf.bpf.o");

impl Tracer {
    pub fn new(target_pid: i32) -> Self {
        Self {
            target_pid,
            running: false,
            event_tx: None,
            thread_handle: None,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        let (event_tx, event_rx) = channel();
        self.event_tx = Some(event_tx.clone());

        let target_pid = self.target_pid;

        let thread_handle = thread::spawn(move || {
            if let Err(e) = Self::run(target_pid, event_tx, event_rx) {
                eprintln!("Tracer error: {:?}", e);
            }
        });

        self.thread_handle = Some(thread_handle);
        self.running = true;

        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        // notify tracer thread to stop
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(Event {
                event_type: EventType::Unmap,
                addr: 0,
                size: 0,
                timestamp: SystemTime::now(),
                pid: -1,
                content: None,
            });
        }

        // wait for thread to complete
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        self.running = false;
        self.event_tx = None;

        Ok(())
    }

    fn run(target_pid: i32, event_tx: Sender<Event>, event_rx: Receiver<Event>) -> Result<()> {
        let mut bpf_runtime = BpfRuntime::new(event_tx.clone(), target_pid)?;
        let mut handler = EventHandler::new(target_pid);
        
        let temp_dir = std::env::temp_dir();
        let bpf_path = temp_dir.join("memory_tracer_ringbuf.bpf.o");
        
        std::fs::write(&bpf_path, BPF_OBJECT)?;
        bpf_runtime.start(bpf_path.to_str().unwrap())?;

        // main loop for events from BPF
        let mut running = true;
        while running {
            // poll BPF events
            if let Err(e) = bpf_runtime.poll(Duration::from_millis(100)) {
                eprintln!("Error polling BPF events: {:?}", e);
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

        Ok(())
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
