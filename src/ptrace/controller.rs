//! Main ptrace controller for RWX memory monitoring.

use std::collections::HashMap;
use std::io;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::SystemTime;

use libc::{
    PTRACE_CONT, PTRACE_DETACH, PTRACE_GETREGS, PTRACE_GETSIGINFO, PTRACE_O_TRACESYSGOOD,
    PTRACE_SETOPTIONS, PTRACE_SETREGS, PTRACE_SYSCALL, c_int, c_void, pid_t, siginfo_t,
    user_regs_struct,
};

const SEGV_ACCERR: i32 = 2; // seems not in libc crate
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

use super::remote_syscall::{RegisterSnapshot, RemoteSyscall};
use super::rwx_region::{PROT_EXEC, PROT_WRITE, RegionSource, RwxRegion, RwxRegionTracker};
use crate::error::{EmtError, Result};

/// x86_64 syscall numbers
mod syscall_nr {
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
}

/// Represents a memory execution event captured when the target attempts
/// to execute code in a region where we stripped execute permission.
#[derive(Debug, Clone)]
pub struct MemoryExecEvent {
    /// Address of the faulting region
    pub addr: u64,
    /// Length of the region in bytes
    pub len: u64,
    /// Full memory content of the region at the time of execution attempt
    pub bytes: Vec<u8>,
    /// Register snapshot at the time of the fault
    pub registers: RegisterSnapshot,
    /// Timestamp when the event was captured
    pub timestamp: SystemTime,
    /// The instruction pointer that triggered the fault
    pub fault_addr: u64,
}

impl MemoryExecEvent {
    /// Creates a new MemoryExecEvent
    pub fn new(
        addr: u64,
        len: u64,
        bytes: Vec<u8>,
        registers: RegisterSnapshot,
        fault_addr: u64,
    ) -> Self {
        Self {
            addr,
            len,
            bytes,
            registers,
            timestamp: SystemTime::now(),
            fault_addr,
        }
    }
}

/// State during syscall interception (between enter and exit)
#[derive(Debug, Clone)]
struct PendingSyscall {
    /// Syscall number
    nr: u64,
    /// For mmap: length argument
    len: u64,
    /// Original protection flags before we modified them
    orig_prot: u64,
    /// Whether we modified the syscall
    modified: bool,
}

/// Controller for ptrace-based RWX memory monitoring.
pub struct PtraceController {
    /// Target process ID
    target_pid: pid_t,
    /// Whether the controller is attached and running
    is_attached: Arc<AtomicBool>,
    /// Thread handle for the monitoring thread
    thread_handle: Option<JoinHandle<Vec<MemoryExecEvent>>>,
    /// Flag to signal the monitoring thread to stop
    stop_flag: Arc<AtomicBool>,
}

impl PtraceController {
    /// Creates a new PtraceController for the given target PID.
    pub fn new(target_pid: pid_t) -> Self {
        Self {
            target_pid,
            is_attached: Arc::new(AtomicBool::new(false)),
            thread_handle: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Attaches to the target process and starts monitoring.
    pub fn start(&mut self, event_tx: Option<Sender<MemoryExecEvent>>) -> Result<()> {
        if self.is_attached.load(Ordering::SeqCst) {
            return Err(EmtError::AlreadyRunning);
        }

        let pid = self.target_pid;
        let stop_flag = Arc::clone(&self.stop_flag);
        stop_flag.store(false, Ordering::SeqCst);

        // Channel to receive initialization result
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

            // Clear attached flag when monitor exits (target exited or error)
            is_attached_clone.store(false, Ordering::SeqCst);

            if let Err(e) = result {
                log::debug!("Monitor exited with error: {:?}", e);
            }

            events
        });

        // Wait for initialization
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

    /// Stops monitoring and detaches from the target process.
    /// Returns all captured MemoryExecEvent.
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

    /// Returns whether the controller is currently attached and running
    pub fn is_running(&self) -> bool {
        self.is_attached.load(Ordering::SeqCst)
    }

    /// Main monitoring loop
    fn run_monitor(
        pid: pid_t,
        stop_flag: &Arc<AtomicBool>,
        event_tx: Option<Sender<MemoryExecEvent>>,
        events: &mut Vec<MemoryExecEvent>,
        init_tx: std::sync::mpsc::Sender<Result<()>>,
        is_attached: &Arc<AtomicBool>,
    ) -> Result<()> {
        let nix_pid = Pid::from_raw(pid);

        // Attach to target process
        if let Err(e) = ptrace::attach(nix_pid) {
            let msg = format!("Failed to attach to PID {}: {}", pid, e);
            let _ = init_tx.send(Err(EmtError::PtraceError(msg.clone())));
            return Err(EmtError::PtraceError(msg));
        }

        // Wait for the process to stop after attach
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

        // Set ptrace options to distinguish syscall stops from signal stops
        Self::set_options(pid)?;

        // Signal successful initialization
        is_attached.store(true, Ordering::SeqCst);
        let _ = init_tx.send(Ok(()));

        // Continue with syscall tracing
        Self::ptrace_syscall(pid, None)?;

        let mut tracker = RwxRegionTracker::new();
        let mut pending_syscalls: HashMap<pid_t, PendingSyscall> = HashMap::new();
        let mut in_syscall = false;
        let remote = RemoteSyscall::new(pid);

        loop {
            if stop_flag.load(Ordering::SeqCst) {
                let _ = Self::ptrace_detach(pid);
                break;
            }

            // Wait for next event with timeout-ish behavior using WNOHANG
            let status = match waitpid(nix_pid, Some(WaitPidFlag::__WALL)) {
                Ok(status) => status,
                Err(nix::errno::Errno::ECHILD) => {
                    // Process exited
                    break;
                }
                Err(e) => {
                    return Err(EmtError::PtraceError(format!("waitpid failed: {}", e)));
                }
            };

            match status {
                WaitStatus::Exited(_, code) => {
                    log::debug!("Target process exited with code {}", code);
                    break;
                }

                WaitStatus::Signaled(_, sig, _) => {
                    log::debug!("Target process killed by signal {:?}", sig);
                    break;
                }

                WaitStatus::PtraceSyscall(_) => {
                    // Syscall stop - alternates between enter and exit
                    if in_syscall {
                        // Syscall exit
                        Self::handle_syscall_exit(
                            pid,
                            &remote,
                            &mut tracker,
                            &mut pending_syscalls,
                        )?;
                        in_syscall = false;
                    } else {
                        // Syscall enter
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
                    // Check if this is a SEGV_ACCERR from our modified region
                    if let Some(event) = Self::handle_sigsegv(pid, &remote, &mut tracker)? {
                        if let Some(ref tx) = event_tx {
                            let _ = tx.send(event.clone());
                        }
                        events.push(event);

                        // Resume without delivering the signal (we handled it)
                        Self::ptrace_syscall(pid, None)?;
                    } else {
                        // Not our fault, deliver the signal
                        Self::ptrace_syscall(pid, Some(Signal::SIGSEGV))?;
                    }
                }

                WaitStatus::Stopped(_, sig) => {
                    // Other signal - deliver it
                    Self::ptrace_syscall(pid, Some(sig))?;
                }

                _ => {
                    // Other status, continue
                    Self::ptrace_syscall(pid, None)?;
                }
            }
        }

        Ok(())
    }

    /// Sets ptrace options for syscall tracing
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

    /// Continues the traced process with PTRACE_SYSCALL
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

    /// Continues the traced process with PTRACE_CONT
    #[allow(dead_code)]
    fn ptrace_cont(pid: pid_t, sig: Option<Signal>) -> Result<()> {
        let sig_num = sig.map(|s| s as c_int).unwrap_or(0);

        let ret = unsafe {
            libc::ptrace(
                PTRACE_CONT,
                pid,
                std::ptr::null_mut::<c_void>(),
                sig_num as *mut c_void,
            )
        };

        if ret == -1 {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_CONT failed: {}",
                io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    /// Detaches from the traced process
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

    /// Gets registers from the traced process
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

    /// Sets registers in the traced process
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

    /// Gets signal information
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

    /// Handles syscall entry - checks for mmap/mprotect with RWX and modifies to RW
    fn handle_syscall_enter(
        pid: pid_t,
        _remote: &RemoteSyscall,
        tracker: &mut RwxRegionTracker,
        pending: &mut HashMap<pid_t, PendingSyscall>,
    ) -> Result<()> {
        let regs = Self::get_regs(pid)?;

        // orig_rax contains the syscall number
        let syscall_nr = regs.orig_rax;

        match syscall_nr {
            syscall_nr::MMAP => {
                // mmap(addr, length, prot, flags, fd, offset)
                // rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=offset
                let len = regs.rsi;
                let prot = regs.rdx;

                // Check if RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
                if (prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0 {
                    log::debug!(
                        "Intercepted mmap with RWX: len=0x{:x}, prot=0x{:x}",
                        len,
                        prot
                    );

                    // Modify prot to remove EXEC
                    let mut new_regs = regs;
                    new_regs.rdx = prot & !PROT_EXEC;
                    Self::set_regs(pid, &new_regs)?;

                    // Track this pending syscall
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
                // mprotect(addr, len, prot)
                // rdi=addr, rsi=len, rdx=prot
                let addr = regs.rdi;
                let len = regs.rsi;
                let prot = regs.rdx;

                // Check if adding EXEC to a region (RW → RWX or R → RX with W)
                if (prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0 {
                    log::debug!(
                        "Intercepted mprotect with RWX: addr=0x{:x}, len=0x{:x}, prot=0x{:x}",
                        addr,
                        len,
                        prot
                    );

                    // Modify prot to remove EXEC
                    let mut new_regs = regs;
                    new_regs.rdx = prot & !PROT_EXEC;
                    Self::set_regs(pid, &new_regs)?;

                    // For mprotect, we already know the address
                    let region = RwxRegion::from_mprotect(addr, len, prot);
                    tracker.add(region);

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
                // munmap(addr, len)
                let addr = regs.rdi;
                let len = regs.rsi;

                // Remove any tracked regions that overlap
                tracker.remove_overlapping(addr, len);
            }

            _ => {}
        }

        Ok(())
    }

    /// Handles syscall exit - records the actual mmap address
    fn handle_syscall_exit(
        pid: pid_t,
        _remote: &RemoteSyscall,
        tracker: &mut RwxRegionTracker,
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
                    // Check if mmap succeeded
                    if retval >= 0 || (retval as u64) < 0xfffffffffffff000 {
                        let addr = retval as u64;
                        log::debug!(
                            "mmap returned addr=0x{:x}, tracking RW region (EXEC stripped)",
                            addr
                        );

                        // Now we have the actual address, create the region
                        let region = RwxRegion::new(
                            addr,
                            syscall.len,
                            syscall.orig_prot,
                            RegionSource::Mmap,
                        );
                        tracker.add(region);
                    }
                }

                syscall_nr::MPROTECT => {
                    // Check if mprotect succeeded
                    if retval == 0 {
                        log::debug!("mprotect succeeded, region now RW (EXEC stripped)");
                    } else {
                        log::warn!("mprotect failed with error {}", retval);
                    }
                }

                _ => {}
            }
        }

        Ok(())
    }

    /// Handles SIGSEGV - checks if it's from our modified region and handles it
    fn handle_sigsegv(
        pid: pid_t,
        remote: &RemoteSyscall,
        tracker: &mut RwxRegionTracker,
    ) -> Result<Option<MemoryExecEvent>> {
        let siginfo = Self::get_siginfo(pid)?;

        // Check if this is SEGV_ACCERR (permission denied, not unmapped page)
        let si_code = siginfo.si_code;
        if si_code != SEGV_ACCERR {
            log::debug!(
                "SIGSEGV with si_code {} (not SEGV_ACCERR), passing through",
                si_code
            );
            return Ok(None);
        }

        // Get the faulting address
        let fault_addr = unsafe { siginfo.si_addr() as u64 };
        log::debug!("SEGV_ACCERR at fault_addr=0x{:x}", fault_addr);

        // Check if this address is in one of our tracked regions
        let region_info = if let Some(region) = tracker.find_waiting_region(fault_addr) {
            Some((region.addr, region.len, region.exec_restore_prot()))
        } else {
            // Also check RIP - the fault might be triggered by executing at RIP
            let regs = Self::get_regs(pid)?;
            if let Some(region) = tracker.find_waiting_region(regs.rip) {
                Some((region.addr, region.len, region.exec_restore_prot()))
            } else {
                None
            }
        };

        let (region_addr, region_len, restore_prot) = match region_info {
            Some(info) => info,
            None => {
                log::debug!("Fault address not in tracked regions, passing through");
                return Ok(None);
            }
        };

        log::info!(
            "Execution attempt detected at 0x{:x} in tracked region 0x{:x}-0x{:x}",
            fault_addr,
            region_addr,
            region_addr + region_len
        );

        // Get register snapshot
        let regs = remote.get_registers()?;
        let reg_snapshot = RegisterSnapshot::from(regs);

        // Dump memory content using process_vm_readv
        let bytes = remote.read_memory(region_addr, region_len as usize)?;

        // Create the event
        let event = MemoryExecEvent::new(region_addr, region_len, bytes, reg_snapshot, fault_addr);

        // Inject mprotect to restore execute permission (RX)
        let result = remote.inject_mprotect(region_addr, region_len, restore_prot)?;
        if result.success {
            log::debug!(
                "Restored execute permission on region 0x{:x}-0x{:x}",
                region_addr,
                region_addr + region_len
            );

            // Mark the region as handled
            if let Some(region) = tracker.find_waiting_region_mut(fault_addr) {
                region.mark_execution_handled();
            } else if let Some(region) = tracker.find_waiting_region_mut(regs.rip) {
                region.mark_execution_handled();
            }
        } else {
            log::error!(
                "Failed to restore execute permission: retval={}",
                result.retval
            );
        }

        Ok(Some(event))
    }
}

impl Drop for PtraceController {
    fn drop(&mut self) {
        if self.is_attached.load(Ordering::SeqCst) {
            let _ = self.stop();
        }
    }
}
