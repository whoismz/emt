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
