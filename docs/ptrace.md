# Ptrace-based Tracing

This document describes an approach to dynamic code analysis that leverages the Linux [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html) system call interface in conjunction with controlled memory permission manipulation. The technique implements a Write-XOR-Execute (W^X) enforcement mechanism that intercepts RWX (Read-Write-Execute) memory allocations and uses deliberate permission-induced faults to capture executable code at the precise moment of execution transition.

![ptrace](./images/ptrace.svg)


## Background

Modern software protection mechanisms, malware, and Just-In-Time (JIT) compilers frequently utilize dynamically generated code—executable content created at runtime rather than being present in the original binary. Analyzing such code presents significant challenges:

1. **Temporal Unpredictability**: Code may be generated, executed, and discarded within microseconds
2. **Self-Modification**: Regions may undergo multiple write-execute cycles
3. **Anti-Analysis Techniques**: Malicious code may detect and evade traditional debugging

Traditional debugging approaches using hardware breakpoints or single-stepping introduce prohibitive overhead and are easily detected. This implementation presents an alternative approach based on permission-controlled memory trapping.

## Theoretical Foundation

### The W^X Principle

The **Write XOR Execute** principle states that a memory page should never be simultaneously writable and executable. This security property, when deliberately violated by target software, creates an opportunity for interception:

```
∀ page P: ¬(Writable(P) ∧ Executable(P))
```

When a process requests RWX permissions, our monitor enforces W^X by:

1. Stripping the execute permission on allocation → Region becomes RW
2. Detecting execution attempts via SIGSEGV
3. Toggling to RX permission and capturing the code
4. Detecting write attempts via SIGSEGV
5. Toggling back to RW (completing the cycle)

### State Machine Model

The monitored memory region exists in one of two mutually exclusive states:

```
                    ┌─────────────────────────────────────────┐
                    │         Region State Machine            │
                    └─────────────────────────────────────────┘

                               SIGSEGV (exec attempt)
                               ─────────────────────►
                      ┌──────────┐           ┌──────────────┐
                      │ WRITABLE │           │  EXECUTABLE  │
                      │   (RW)   │           │     (RX)     │
                      └──────────┘           └──────────────┘
                               ◄─────────────────────
                               SIGSEGV (write attempt)

     Entry: mmap(RWX) or mprotect(RWX) → Strip X → Start in WRITABLE state
```

**State Definitions:**

| State | Permissions | Semantics |
|-------|-------------|-----------|
| `WRITABLE` | `PROT_READ \| PROT_WRITE` | Process can write code; execution triggers fault |
| `EXECUTABLE` | `PROT_READ \| PROT_EXEC` | Process can execute code; writing triggers fault |

### Transition Analysis

Each state transition corresponds to a specific security-relevant event:

**W→X Transition (Write to Execute):**
- **Trigger**: SIGSEGV with `si_code = SEGV_ACCERR` where `fault_addr` is within a WRITABLE region
- **Semantics**: Target has finished writing and is attempting to execute
- **Action**: Capture memory contents, transition to EXECUTABLE state
- **Security Implication**: This captures the complete code just before first execution

**X→W Transition (Execute to Write):**
- **Trigger**: SIGSEGV with `si_code = SEGV_ACCERR` where `fault_addr` is within an EXECUTABLE region
- **Semantics**: Target is performing self-modification or code patching
- **Action**: Transition to WRITABLE state (no capture—code was captured on previous W→X)
- **Security Implication**: Indicates polymorphic or self-modifying behavior

## Implementation Architecture

### System Components

The implementation consists of four primary modules:

| Module | File | Responsibility |
|--------|------|----------------|
| **PtraceController** | `controller.rs` | Process attachment, syscall interception, signal handling |
| **RwxMonitor** | `rwx_monitor.rs` | High-level API, event channels, thread management |
| **RemoteSyscall** | `remote_syscall.rs` | Syscall injection into traced process |
| **RwxRegionTracker** | `rwx_region.rs` | Memory region state management |

### Detailed Operation Flow

#### Phase 1: Attachment and Initialization

```
Monitor                          Target Process
   │                                   │
   │─────────── PTRACE_ATTACH ────────►│
   │                                   │ (stops with SIGSTOP)
   │◄─────────── waitpid() ────────────│
   │                                   │
   │──────── PTRACE_SETOPTIONS ───────►│
   │      (PTRACE_O_TRACESYSGOOD)      │
   │                                   │
   │───────── PTRACE_SYSCALL ─────────►│
   │                                   │ (resumes, stops on syscalls)
```

The `PTRACE_O_TRACESYSGOOD` option sets bit 7 in the signal number for syscall-stops, allowing differentiation between actual signals and syscall traps.

#### Phase 2: Syscall Interception

For each syscall entry, the monitor examines the syscall number in `orig_rax`:

```c
// x86_64 syscall ABI for mmap:
// rax = 9 (SYS_mmap)
// rdi = addr (or NULL)
// rsi = length
// rdx = prot        ← We examine this
// r10 = flags
// r8  = fd
// r9  = offset

// x86_64 syscall ABI for mprotect:
// rax = 10 (SYS_mprotect)
// rdi = addr
// rsi = length
// rdx = prot        ← We examine this
```

**Interception Logic:**

```
if (prot & PROT_WRITE) && (prot & PROT_EXEC):
    # RWX detected, then modify syscall argument
    prot' = prot & ~PROT_EXEC    # Remove execute permission
    set rdx = prot'              # Modify in-flight syscall
    track_pending_syscall(syscall_nr, original_prot)
```

#### Phase 3: SIGSEGV-Driven Capture

When the target attempts to execute code in a WRITABLE region:

```
Target Process                    Monitor
      │                              │
      │        JMP [RWX_region]      │
      │                              │
      │                              │
      ├────────── SIGSEGV ──────────►│
      │        (SEGV_ACCERR)         │
      │                              │
      │                              │── Analyze fault:
      │                              │   - si_addr in tracked region?
      │                              │   - Region state == WRITABLE?
      │                              │
      │                              │── Capture memory:
      │                              │   process_vm_readv()
      │                              │
      │                              │── Inject mprotect(RX):
      │                              │   Remote syscall injection
      │                              │
      │◄──────── PTRACE_CONT ────────│
      │      (suppress SIGSEGV)      │
      │                              │
      │     [Execution continues]    │
```

### Remote Syscall Injection

A critical capability is executing syscalls within the target process context. This is necessary for `mprotect()` calls that change the target's memory permissions.

**Injection Mechanism:**

1. **Locate Executable Memory**: Find a valid code address (typically at RIP or return address on stack)
2. **Save Original State**: Preserve registers and instruction bytes at injection point
3. **Write Syscall Stub**: Inject `syscall; int3` (bytes: `0x0F 0x05 0xCC`)
4. **Configure Registers**: Set up syscall number and arguments per x86_64 ABI
5. **Execute**: `PTRACE_CONT` → syscall executes → `int3` generates SIGTRAP
6. **Harvest Result**: Read return value from `rax`
7. **Restore State**: Restore original instructions and registers

```
           Original Code                    Injected Code
        ┌────────────────┐              ┌────────────────┐
  RIP → │  mov rax, rbx  │        RIP → │  syscall       │ 0x0F 0x05
        │  add rax, 1    │              │  int3          │ 0xCC
        │  ...           │              │  [preserved]   │
        └────────────────┘              └────────────────┘

                           After SIGTRAP:
                        ┌────────────────┐
                  RIP → │  mov rax, rbx  │ ← Restored
                        │  add rax, 1    │
                        │  ...           │
                        └────────────────┘
```

### Memory Capture Mechanism

Memory content is captured using `process_vm_readv(2)`, which provides:

- **Efficiency**: Single syscall for arbitrary-length reads
- **Atomicity**: Consistent snapshot of memory region
- **Safety**: No modification of target address space

```c
struct iovec local_iov = {
    .iov_base = buffer,
    .iov_len = region_length
};
struct iovec remote_iov = {
    .iov_base = (void*)region_addr,
    .iov_len = region_length
};
process_vm_readv(target_pid, &local_iov, 1, &remote_iov, 1, 0);
```

## Captured Event Structure

Each execution capture produces a `MemoryExecEvent` containing:

| Field | Type | Description |
|-------|------|-------------|
| `addr` | `u64` | Base address of the captured memory region |
| `len` | `u64` | Length of the region in bytes |
| `bytes` | `Vec<u8>` | Complete memory contents at capture time |
| `registers` | `RegisterSnapshot` | Full CPU register state (all x86_64 GPRs) |
| `fault_addr` | `u64` | Specific instruction pointer that triggered the fault |
| `timestamp` | `SystemTime` | Wall-clock time of capture |
| `capture_sequence` | `u32` | Monotonic counter for this region's captures |

The `capture_sequence` field is particularly valuable for analyzing polymorphic code, where the same region may contain different code across multiple W→X transitions.

## API Reference

### Basic Usage

```rust
use emt::{RwxMonitorBuilder, MemoryExecEvent};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize monitor for target process
    let mut monitor = RwxMonitorBuilder::new(target_pid).build();
    
    // Attach and begin monitoring
    monitor.start()?;

    // Event processing loop
    while monitor.is_running() {
        if let Some(event) = monitor.recv_event_timeout(Duration::from_millis(100)) {
            analyze_captured_code(&event);
        }
    }

    // Graceful shutdown
    let result = monitor.stop()?;
    println!("Total captures: {}", result.exec_events.len());

    Ok(())
}

fn analyze_captured_code(event: &MemoryExecEvent) {
    println!("Captured execution at 0x{:016x}", event.addr);
    println!("  Region size: {} bytes", event.len);
    println!("  Capture #: {}", event.capture_sequence);
    println!("  RIP at fault: 0x{:016x}", event.fault_addr);
    
    // Disassemble captured bytes...
    // event.bytes contains the raw machine code
}
```

### Register Snapshot

The `RegisterSnapshot` provides complete CPU state at capture time:

```rust
pub struct RegisterSnapshot {
    // General-purpose registers
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64,  pub r9: u64,  pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    
    // Control registers
    pub rip: u64,
    pub eflags: u64,
    
    // Segment registers
    pub cs: u64, pub ss: u64,
    pub fs_base: u64, pub gs_base: u64,
}
```

## Examples

```bash
# Basic RWX monitoring
cargo run --example rwx_monitor -- --pid <target_pid>

# W-X cycle test
cargo run --example rwx_cycle_test
```
