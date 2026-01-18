//! Ptrace controller for RWX memory monitoring.

use std::collections::HashMap;
use std::io;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::SystemTime;

use libc::{
    PTRACE_DETACH, PTRACE_GETREGS, PTRACE_GETSIGINFO, PTRACE_O_TRACESYSGOOD, PTRACE_SETOPTIONS,
    PTRACE_SETREGS, PTRACE_SYSCALL, c_int, c_void, pid_t, siginfo_t, user_regs_struct,
};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

use super::region::{
    FaultType, PROT_EXEC, PROT_READ, PROT_WRITE, RegionSource, RegionTracker, TrackedRegion,
};
use super::remote_syscall::{RegisterSnapshot, RemoteSyscall};
use crate::error::{EmtError, Result};

const SEGV_ACCERR: i32 = 2;

mod syscall_nr {
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
}

/// Memory execution event captured when the target attempts to execute code.
#[derive(Debug, Clone)]
pub struct MemoryExecEvent {
    pub addr: u64,
    pub len: u64,
    pub bytes: Vec<u8>,
    pub registers: RegisterSnapshot,
    pub timestamp: SystemTime,
    pub fault_addr: u64,
    pub capture_sequence: u32,
}

impl MemoryExecEvent {
    pub fn new(
        addr: u64,
        len: u64,
        bytes: Vec<u8>,
        registers: RegisterSnapshot,
        fault_addr: u64,
        capture_sequence: u32,
    ) -> Self {
        Self {
            addr,
            len,
            bytes,
            registers,
            timestamp: SystemTime::now(),
            fault_addr,
            capture_sequence,
        }
    }
}

enum SigsegvResult {
    ExecutionCaptured(MemoryExecEvent),
    WriteHandled,
    NotOurs,
}

#[derive(Debug, Clone)]
struct PendingSyscall {
    nr: u64,
    len: u64,
    orig_prot: u64,
    modified: bool,
}

/// Ptrace-based RWX memory monitoring controller.
pub struct PtraceController {
    target_pid: pid_t,
    is_attached: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<Vec<MemoryExecEvent>>>,
    stop_flag: Arc<AtomicBool>,
}

impl PtraceController {
    pub fn new(target_pid: pid_t) -> Self {
        Self {
            target_pid,
            is_attached: Arc::new(AtomicBool::new(false)),
            thread_handle: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&mut self, event_tx: Option<Sender<MemoryExecEvent>>) -> Result<()> {
        if self.is_attached.load(Ordering::SeqCst) {
            return Err(EmtError::AlreadyRunning);
        }

        let pid = self.target_pid;
        let stop_flag = Arc::clone(&self.stop_flag);
        stop_flag.store(false, Ordering::SeqCst);

        let (init_tx, init_rx) = std::sync::mpsc::channel();
        let is_attached = Arc::new(AtomicBool::new(false));
        let is_attached_clone = Arc::clone(&is_attached);

        let handle = thread::spawn(move || {
            let mut events = Vec::new();
            let result = Self::run_monitor(
                pid,
                &stop_flag,
                event_tx,
                &mut events,
                init_tx,
                &is_attached_clone,
            );
            is_attached_clone.store(false, Ordering::SeqCst);
            if let Err(e) = result {
                log::debug!("Monitor exited: {:?}", e);
            }
            events
        });

        match init_rx.recv() {
            Ok(Ok(())) => {
                self.is_attached = is_attached;
                self.thread_handle = Some(handle);
                Ok(())
            }
            Ok(Err(e)) => {
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                let _ = handle.join();
                Err(EmtError::ThreadJoinError)
            }
        }
    }

    pub fn stop(&mut self) -> Result<Vec<MemoryExecEvent>> {
        if !self.is_attached.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }

        self.stop_flag.store(true, Ordering::SeqCst);

        let events = if let Some(handle) = self.thread_handle.take() {
            handle.join().map_err(|_| EmtError::ThreadJoinError)?
        } else {
            Vec::new()
        };

        self.is_attached.store(false, Ordering::SeqCst);
        Ok(events)
    }

    pub fn is_running(&self) -> bool {
        self.is_attached.load(Ordering::SeqCst)
    }

    fn run_monitor(
        pid: pid_t,
        stop_flag: &Arc<AtomicBool>,
        event_tx: Option<Sender<MemoryExecEvent>>,
        events: &mut Vec<MemoryExecEvent>,
        init_tx: std::sync::mpsc::Sender<Result<()>>,
        is_attached: &Arc<AtomicBool>,
    ) -> Result<()> {
        let nix_pid = Pid::from_raw(pid);

        if let Err(e) = ptrace::attach(nix_pid) {
            let msg = format!("Failed to attach to PID {}: {}", pid, e);
            let _ = init_tx.send(Err(EmtError::PtraceError(msg.clone())));
            return Err(EmtError::PtraceError(msg));
        }

        match waitpid(nix_pid, None) {
            Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => {}
            Ok(status) => {
                let msg = format!("Unexpected status after attach: {:?}", status);
                let _ = init_tx.send(Err(EmtError::PtraceError(msg.clone())));
                return Err(EmtError::PtraceError(msg));
            }
            Err(e) => {
                let msg = format!("waitpid failed after attach: {}", e);
                let _ = init_tx.send(Err(EmtError::PtraceError(msg.clone())));
                return Err(EmtError::PtraceError(msg));
            }
        }

        Self::set_options(pid)?;
        is_attached.store(true, Ordering::SeqCst);
        let _ = init_tx.send(Ok(()));
        Self::ptrace_syscall(pid, None)?;

        let mut tracker = RegionTracker::new();
        let mut pending_syscalls: HashMap<pid_t, PendingSyscall> = HashMap::new();
        let mut in_syscall = false;
        let remote = RemoteSyscall::new(pid);

        loop {
            if stop_flag.load(Ordering::SeqCst) {
                let _ = Self::ptrace_detach(pid);
                break;
            }

            let status = match waitpid(nix_pid, Some(WaitPidFlag::__WALL)) {
                Ok(status) => status,
                Err(nix::errno::Errno::ECHILD) => break,
                Err(e) => return Err(EmtError::PtraceError(format!("waitpid failed: {}", e))),
            };

            match status {
                WaitStatus::Exited(_, code) => {
                    log::debug!("Target exited with code {}", code);
                    break;
                }
                WaitStatus::Signaled(_, sig, _) => {
                    log::debug!("Target killed by signal {:?}", sig);
                    break;
                }
                WaitStatus::PtraceSyscall(_) => {
                    if in_syscall {
                        Self::handle_syscall_exit(
                            pid,
                            &remote,
                            &mut tracker,
                            &mut pending_syscalls,
                        )?;
                        in_syscall = false;
                    } else {
                        Self::handle_syscall_enter(
                            pid,
                            &remote,
                            &mut tracker,
                            &mut pending_syscalls,
                        )?;
                        in_syscall = true;
                    }
                    Self::ptrace_syscall(pid, None)?;
                }
                WaitStatus::Stopped(_, Signal::SIGSEGV) => {
                    match Self::handle_sigsegv(pid, &remote, &mut tracker)? {
                        SigsegvResult::ExecutionCaptured(event) => {
                            if let Some(ref tx) = event_tx {
                                let _ = tx.send(event.clone());
                            }
                            events.push(event);
                            Self::ptrace_syscall(pid, None)?;
                        }
                        SigsegvResult::WriteHandled => {
                            Self::ptrace_syscall(pid, None)?;
                        }
                        SigsegvResult::NotOurs => {
                            Self::ptrace_syscall(pid, Some(Signal::SIGSEGV))?;
                        }
                    }
                }
                WaitStatus::Stopped(_, sig) => {
                    Self::ptrace_syscall(pid, Some(sig))?;
                }
                _ => {
                    Self::ptrace_syscall(pid, None)?;
                }
            }
        }

        Ok(())
    }

    fn set_options(pid: pid_t) -> Result<()> {
        let ret = unsafe {
            libc::ptrace(
                PTRACE_SETOPTIONS,
                pid,
                std::ptr::null_mut::<c_void>(),
                PTRACE_O_TRACESYSGOOD as *mut c_void,
            )
        };
        if ret == -1 {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_SETOPTIONS failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn ptrace_syscall(pid: pid_t, sig: Option<Signal>) -> Result<()> {
        let sig_num = sig.map(|s| s as c_int).unwrap_or(0);
        let ret = unsafe {
            libc::ptrace(
                PTRACE_SYSCALL,
                pid,
                std::ptr::null_mut::<c_void>(),
                sig_num as *mut c_void,
            )
        };
        if ret == -1 {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_SYSCALL failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn ptrace_detach(pid: pid_t) -> Result<()> {
        let ret = unsafe {
            libc::ptrace(
                PTRACE_DETACH,
                pid,
                std::ptr::null_mut::<c_void>(),
                std::ptr::null_mut::<c_void>(),
            )
        };
        if ret == -1 {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_DETACH failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn get_regs(pid: pid_t) -> Result<user_regs_struct> {
        let mut regs: user_regs_struct = unsafe { mem::zeroed() };
        let ret = unsafe {
            libc::ptrace(
                PTRACE_GETREGS,
                pid,
                std::ptr::null_mut::<c_void>(),
                &mut regs as *mut _ as *mut c_void,
            )
        };
        if ret == -1 {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_GETREGS failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(regs)
    }

    fn set_regs(pid: pid_t, regs: &user_regs_struct) -> Result<()> {
        let ret = unsafe {
            libc::ptrace(
                PTRACE_SETREGS,
                pid,
                std::ptr::null_mut::<c_void>(),
                regs as *const _ as *const c_void,
            )
        };
        if ret == -1 {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_SETREGS failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn get_siginfo(pid: pid_t) -> Result<siginfo_t> {
        let mut siginfo: siginfo_t = unsafe { mem::zeroed() };
        let ret = unsafe {
            libc::ptrace(
                PTRACE_GETSIGINFO,
                pid,
                std::ptr::null_mut::<c_void>(),
                &mut siginfo as *mut _ as *mut c_void,
            )
        };
        if ret == -1 {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_GETSIGINFO failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(siginfo)
    }

    fn handle_syscall_enter(
        pid: pid_t,
        _remote: &RemoteSyscall,
        tracker: &mut RegionTracker,
        pending: &mut HashMap<pid_t, PendingSyscall>,
    ) -> Result<()> {
        let regs = Self::get_regs(pid)?;
        let syscall_nr = regs.orig_rax;

        match syscall_nr {
            syscall_nr::MMAP => {
                let len = regs.rsi;
                let prot = regs.rdx;

                if (prot & PROT_READ) != 0 && (prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0 {
                    log::debug!(
                        "Intercepted mmap with RWX: len=0x{:x}, prot=0x{:x}",
                        len,
                        prot
                    );

                    let mut new_regs = regs;
                    new_regs.rdx = prot & !PROT_EXEC;
                    Self::set_regs(pid, &new_regs)?;

                    pending.insert(
                        pid,
                        PendingSyscall {
                            nr: syscall_nr::MMAP,
                            len,
                            orig_prot: prot,
                            modified: true,
                        },
                    );
                }
            }
            syscall_nr::MPROTECT => {
                let addr = regs.rdi;
                let len = regs.rsi;
                let prot = regs.rdx;

                let has_write = (prot & PROT_WRITE) != 0;
                let has_exec = (prot & PROT_EXEC) != 0;

                if has_write && has_exec {
                    log::debug!(
                        "Intercepted mprotect with RWX: addr=0x{:x}, len=0x{:x}, prot=0x{:x}",
                        addr,
                        len,
                        prot
                    );

                    let mut new_regs = regs;
                    new_regs.rdx = prot & !PROT_EXEC;
                    Self::set_regs(pid, &new_regs)?;

                    if tracker.find(addr).is_none() {
                        let region = TrackedRegion::from_mprotect(addr, len, prot);
                        tracker.add(region);
                    }

                    pending.insert(
                        pid,
                        PendingSyscall {
                            nr: syscall_nr::MPROTECT,
                            len,
                            orig_prot: prot,
                            modified: true,
                        },
                    );
                }
            }
            syscall_nr::MUNMAP => {
                let addr = regs.rdi;
                let len = regs.rsi;
                tracker.remove_overlapping(addr, len);
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_syscall_exit(
        pid: pid_t,
        _remote: &RemoteSyscall,
        tracker: &mut RegionTracker,
        pending: &mut HashMap<pid_t, PendingSyscall>,
    ) -> Result<()> {
        let regs = Self::get_regs(pid)?;
        let retval = regs.rax as i64;

        if let Some(syscall) = pending.remove(&pid) {
            if !syscall.modified {
                return Ok(());
            }

            match syscall.nr {
                syscall_nr::MMAP => {
                    if retval >= 0 || (retval as u64) < 0xfffffffffffff000 {
                        let addr = retval as u64;
                        log::debug!("mmap returned addr=0x{:x}, tracking region", addr);

                        let region = TrackedRegion::new(
                            addr,
                            syscall.len,
                            syscall.orig_prot,
                            RegionSource::Mmap,
                        );
                        tracker.add(region);
                    }
                }
                syscall_nr::MPROTECT => {
                    if retval == 0 {
                        log::debug!("mprotect succeeded");
                    } else {
                        log::warn!("mprotect failed: {}", retval);
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn handle_sigsegv(
        pid: pid_t,
        remote: &RemoteSyscall,
        tracker: &mut RegionTracker,
    ) -> Result<SigsegvResult> {
        let siginfo = Self::get_siginfo(pid)?;

        if siginfo.si_code != SEGV_ACCERR {
            log::debug!(
                "SIGSEGV si_code {} (not SEGV_ACCERR), passing through",
                siginfo.si_code
            );
            return Ok(SigsegvResult::NotOurs);
        }

        let fault_addr = unsafe { siginfo.si_addr() as u64 };
        let current_regs = Self::get_regs(pid)?;
        let rip = current_regs.rip;

        log::debug!(
            "SEGV_ACCERR: fault_addr=0x{:x}, RIP=0x{:x}",
            fault_addr,
            rip
        );

        let region_addr = tracker
            .find(fault_addr)
            .map(|r| r.addr)
            .or_else(|| tracker.find(rip).map(|r| r.addr));

        let region_start = match region_addr {
            Some(addr) => addr,
            None => {
                log::debug!("Fault address 0x{:x} not in tracked regions", fault_addr);
                return Ok(SigsegvResult::NotOurs);
            }
        };

        let region = tracker.find_mut(region_start).unwrap();
        let region_addr = region.addr;
        let region_len = region.len;
        let fault_type = region.determine_fault_type();

        match fault_type {
            FaultType::ExecutionAttempt => {
                let capture_seq = region.exec_capture_count + 1;
                log::info!(
                    "W→X: Execution at 0x{:x} in region 0x{:x}-0x{:x} (capture #{})",
                    fault_addr,
                    region_addr,
                    region_addr + region_len,
                    capture_seq
                );

                let regs = remote.get_registers()?;
                let reg_snapshot = RegisterSnapshot::from(regs);
                let bytes = remote.read_memory(region_addr, region_len as usize)?;
                let new_prot = region.transition_to_executable();

                let event = MemoryExecEvent::new(
                    region_addr,
                    region_len,
                    bytes,
                    reg_snapshot,
                    fault_addr,
                    capture_seq,
                );

                let result = remote.inject_mprotect(region_addr, region_len, new_prot)?;
                if result.success {
                    log::debug!("Switched region 0x{:x} to RX", region_addr);
                } else {
                    log::error!("Failed to switch to RX: {}", result.retval);
                }

                Ok(SigsegvResult::ExecutionCaptured(event))
            }
            FaultType::WriteAttempt => {
                log::info!(
                    "X→W: Write at 0x{:x} in region 0x{:x}-0x{:x} (write #{})",
                    fault_addr,
                    region_addr,
                    region_addr + region_len,
                    region.write_fault_count + 1
                );

                let new_prot = region.transition_to_writable();
                let result = remote.inject_mprotect(region_addr, region_len, new_prot)?;
                if result.success {
                    log::debug!("Switched region 0x{:x} to RW", region_addr);
                } else {
                    log::error!("Failed to switch to RW: {}", result.retval);
                }

                Ok(SigsegvResult::WriteHandled)
            }
        }
    }
}

impl Drop for PtraceController {
    fn drop(&mut self) {
        if self.is_attached.load(Ordering::SeqCst) {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== MemoryExecEvent Tests ====================

    #[test]
    fn test_memory_exec_event_new() {
        let regs = RegisterSnapshot {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0x7fffffffd000,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0x401000,
            eflags: 0x202,
            cs: 0x33,
            ss: 0x2b,
            fs_base: 0,
            gs_base: 0,
        };

        let bytes = vec![0x90, 0x90, 0xc3]; // nop; nop; ret
        let event = MemoryExecEvent::new(
            0x1000, // addr
            0x1000, // len
            bytes.clone(),
            regs,
            0x1000, // fault_addr
            1,      // capture_sequence
        );

        assert_eq!(event.addr, 0x1000);
        assert_eq!(event.len, 0x1000);
        assert_eq!(event.bytes, bytes);
        assert_eq!(event.fault_addr, 0x1000);
        assert_eq!(event.capture_sequence, 1);
        assert_eq!(event.registers.rip, 0x401000);
    }

    #[test]
    fn test_memory_exec_event_capture_sequence() {
        let regs = RegisterSnapshot {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            eflags: 0,
            cs: 0,
            ss: 0,
            fs_base: 0,
            gs_base: 0,
        };

        // First capture
        let event1 = MemoryExecEvent::new(0x1000, 0x1000, vec![], regs.clone(), 0x1000, 1);
        assert_eq!(event1.capture_sequence, 1);

        // Second capture (W-X cycle)
        let event2 = MemoryExecEvent::new(0x1000, 0x1000, vec![], regs.clone(), 0x1000, 2);
        assert_eq!(event2.capture_sequence, 2);

        // Third capture
        let event3 = MemoryExecEvent::new(0x1000, 0x1000, vec![], regs, 0x1000, 3);
        assert_eq!(event3.capture_sequence, 3);
    }

    #[test]
    fn test_memory_exec_event_clone() {
        let regs = RegisterSnapshot {
            rax: 0x42,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0x400000,
            eflags: 0,
            cs: 0,
            ss: 0,
            fs_base: 0,
            gs_base: 0,
        };

        let bytes = vec![0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]; // mov eax, 1; ret
        let event = MemoryExecEvent::new(0x2000, 0x1000, bytes, regs, 0x2000, 1);

        let cloned = event.clone();

        assert_eq!(cloned.addr, event.addr);
        assert_eq!(cloned.len, event.len);
        assert_eq!(cloned.bytes, event.bytes);
        assert_eq!(cloned.fault_addr, event.fault_addr);
        assert_eq!(cloned.capture_sequence, event.capture_sequence);
        assert_eq!(cloned.registers.rax, 0x42);
        assert_eq!(cloned.registers.rip, 0x400000);
    }

    // ==================== PtraceController Tests ====================

    #[test]
    fn test_ptrace_controller_new() {
        let controller = PtraceController::new(1234);

        assert_eq!(controller.target_pid, 1234);
        assert!(!controller.is_attached.load(Ordering::SeqCst));
        assert!(controller.thread_handle.is_none());
        assert!(!controller.stop_flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_ptrace_controller_is_running_initial() {
        let controller = PtraceController::new(1234);

        assert!(!controller.is_running());
    }

    #[test]
    fn test_ptrace_controller_stop_when_not_attached() {
        let mut controller = PtraceController::new(1234);

        // Stop should succeed even when not attached
        let result = controller.stop();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // ==================== SigsegvResult Tests ====================

    #[test]
    fn test_sigsegv_result_variants() {
        let regs = RegisterSnapshot {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            eflags: 0,
            cs: 0,
            ss: 0,
            fs_base: 0,
            gs_base: 0,
        };

        let event = MemoryExecEvent::new(0x1000, 0x1000, vec![], regs, 0x1000, 1);

        // Test that we can create each variant
        let exec_captured = SigsegvResult::ExecutionCaptured(event);
        let write_handled = SigsegvResult::WriteHandled;
        let not_ours = SigsegvResult::NotOurs;

        // Pattern matching works
        match exec_captured {
            SigsegvResult::ExecutionCaptured(e) => assert_eq!(e.addr, 0x1000),
            _ => panic!("Expected ExecutionCaptured"),
        }

        match write_handled {
            SigsegvResult::WriteHandled => {}
            _ => panic!("Expected WriteHandled"),
        }

        match not_ours {
            SigsegvResult::NotOurs => {}
            _ => panic!("Expected NotOurs"),
        }
    }

    // ==================== PendingSyscall Tests ====================

    #[test]
    fn test_pending_syscall_creation() {
        let pending = PendingSyscall {
            nr: syscall_nr::MMAP,
            len: 0x1000,
            orig_prot: 0x7, // RWX
            modified: true,
        };

        assert_eq!(pending.nr, 9); // MMAP syscall number
        assert_eq!(pending.len, 0x1000);
        assert_eq!(pending.orig_prot, 0x7);
        assert!(pending.modified);
    }

    #[test]
    fn test_pending_syscall_mprotect() {
        let pending = PendingSyscall {
            nr: syscall_nr::MPROTECT,
            len: 0x2000,
            orig_prot: 0x5, // R-X
            modified: false,
        };

        assert_eq!(pending.nr, 10); // MPROTECT syscall number
        assert_eq!(pending.len, 0x2000);
        assert_eq!(pending.orig_prot, 0x5);
        assert!(!pending.modified);
    }

    #[test]
    fn test_pending_syscall_clone() {
        let pending = PendingSyscall {
            nr: syscall_nr::MMAP,
            len: 0x4000,
            orig_prot: 0x7,
            modified: true,
        };

        let cloned = pending.clone();

        assert_eq!(cloned.nr, pending.nr);
        assert_eq!(cloned.len, pending.len);
        assert_eq!(cloned.orig_prot, pending.orig_prot);
        assert_eq!(cloned.modified, pending.modified);
    }

    // ==================== Syscall Number Constants Tests ====================

    #[test]
    fn test_syscall_numbers() {
        // Verify syscall numbers match Linux x86_64 ABI
        assert_eq!(syscall_nr::MMAP, 9);
        assert_eq!(syscall_nr::MPROTECT, 10);
        assert_eq!(syscall_nr::MUNMAP, 11);
    }

    // ==================== SEGV_ACCERR Constant Test ====================

    #[test]
    fn test_segv_accerr_constant() {
        // SEGV_ACCERR should be 2 per POSIX/Linux
        assert_eq!(SEGV_ACCERR, 2);
    }
}
