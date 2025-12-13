# Ptrace-based Memory Monitor

A ptrace-based approach for monitoring and capturing RWX memory.

## Overview

This module intercepts memory syscalls and uses SIGSEGV-driven permission toggling to capture executable memory content before it runs.

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        W-X Cycle                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Target calls mmap(RWX)                                      │
│     └─► Monitor intercepts, grants RW only (strips X)           │
│                                                                 │
│  2. Target writes code to memory                                │
│     └─► Allowed (region is RW)                                  │
│                                                                 │
│  3. Target attempts to execute                                  │
│     └─► SIGSEGV! Monitor captures memory, switches to RX        │
│                                                                 │
│  4. Target attempts to write again                              │
│     └─► SIGSEGV! Monitor switches back to RW                    │
│                                                                 │
│  5. Repeat from step 2...                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| File | Description |
|------|-------------|
| `controller.rs` | Main `PtraceController`: attaches to process, intercepts syscalls, handles signals |
| `rwx_monitor.rs` | High-level `RwxMonitor` API with event channels and builder pattern |
| `remote_syscall.rs` | Injects syscalls (e.g., `mprotect`) into the traced process |
| `rwx_region.rs` | Tracks memory regions and their current W/X state |

## Usage

```rust
use emt::{RwxMonitorBuilder, MemoryExecEvent};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create and start the monitor
    let mut monitor = RwxMonitorBuilder::new(target_pid).build();
    monitor.start()?;

    // Receive events as they occur
    while monitor.is_running() {
        if let Some(event) = monitor.recv_event_timeout(Duration::from_millis(100)) {
            println!("Captured code at 0x{:x} ({} bytes)", event.addr, event.len);
            println!("Capture #{} for this region", event.capture_sequence);
            // event.bytes contains the full memory content
            // event.registers contains CPU state at capture time
        }
    }

    // Stop and collect any remaining events
    let result = monitor.stop()?;
    println!("Total captures: {}", result.exec_events.len());

    Ok(())
}
```

## Captured Event Data

Each `MemoryExecEvent` contains:

| Field | Description |
|-------|-------------|
| `addr` | Base address of the captured region |
| `len` | Size of the region in bytes |
| `bytes` | Full memory content at capture time |
| `registers` | Complete CPU register snapshot (x86_64) |
| `fault_addr` | Instruction pointer that triggered the fault |
| `timestamp` | When the capture occurred |
| `capture_sequence` | How many times this region has been captured |

## Examples

```bash
# Basic RWX monitoring
cargo run --example rwx_monitor

# W-X cycle test
cargo run --example rwx_cycle_test
```

## Requirements

- Linux with ptrace support
