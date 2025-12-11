//! Remote syscall injection into a traced process.

use std::io;
use std::mem;

use libc::{
    PTRACE_CONT, PTRACE_GETREGS, PTRACE_PEEKTEXT, PTRACE_POKETEXT, PTRACE_SETREGS, c_void, pid_t,
    user_regs_struct,
};
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;

use crate::error::{EmtError, Result};

/// x86_64 syscall instruction (0x0f 0x05) followed by int3 (0xcc) for trap after syscall
const SYSCALL_INT3_INSN: [u8; 3] = [0x0f, 0x05, 0xcc];

/// x86_64 syscall numbers
pub mod syscall_nr {
    pub const MPROTECT: u64 = 10;
    pub const MMAP: u64 = 9;
    pub const MUNMAP: u64 = 11;
}

/// Result of a remote syscall execution
#[derive(Debug, Clone)]
pub struct SyscallResult {
    /// Return value (from rax)
    pub retval: i64,
    /// Whether the syscall succeeded (retval >= 0 or not an error)
    pub success: bool,
}

impl SyscallResult {
    /// Creates a new syscall result
    pub fn new(retval: i64) -> Self {
        let success = !(-4095..0).contains(&retval);
        Self { retval, success }
    }

    /// Returns the result as a pointer (for mmap-like syscalls)
    pub fn as_ptr(&self) -> u64 {
        self.retval as u64
    }
}

/// Handles remote syscall injection into a traced process.
#[derive(Debug)]
pub struct RemoteSyscall {
    pid: Pid,
}

impl RemoteSyscall {
    /// Creates a new remote syscall handler for the given PID.
    pub fn new(pid: pid_t) -> Self {
        Self {
            pid: Pid::from_raw(pid),
        }
    }

    /// Gets the current register state of the traced process.
    pub fn get_registers(&self) -> Result<user_regs_struct> {
        let mut regs: user_regs_struct = unsafe { mem::zeroed() };

        let ret = unsafe {
            libc::ptrace(
                PTRACE_GETREGS,
                self.pid.as_raw(),
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

    /// Sets the register state of the traced process.
    pub fn set_registers(&self, regs: &user_regs_struct) -> Result<()> {
        let ret = unsafe {
            libc::ptrace(
                PTRACE_SETREGS,
                self.pid.as_raw(),
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

    /// Reads a word (8 bytes on x86_64) from the traced process's memory.
    pub fn peek_text(&self, addr: u64) -> Result<u64> {
        // Clear errno before call since -1 can be a valid return value
        unsafe { *libc::__errno_location() = 0 };

        let ret = unsafe {
            libc::ptrace(
                PTRACE_PEEKTEXT,
                self.pid.as_raw(),
                addr as *mut c_void,
                std::ptr::null_mut::<c_void>(),
            )
        };

        let errno = io::Error::last_os_error();
        if ret == -1 && errno.raw_os_error() != Some(0) {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_PEEKTEXT at 0x{:x} failed: {}",
                addr, errno
            )));
        }

        Ok(ret as u64)
    }

    /// Writes a word (8 bytes on x86_64) to the traced process's memory.
    pub fn poke_text(&self, addr: u64, data: u64) -> Result<()> {
        let ret = unsafe {
            libc::ptrace(
                PTRACE_POKETEXT,
                self.pid.as_raw(),
                addr as *mut c_void,
                data as *mut c_void,
            )
        };

        if ret == -1 {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_POKETEXT at 0x{:x} failed: {}",
                addr,
                io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    /// Continues the process with PTRACE_CONT and waits for it to stop.
    fn ptrace_cont_and_wait(&self) -> Result<WaitStatus> {
        let ret = unsafe {
            libc::ptrace(
                PTRACE_CONT,
                self.pid.as_raw(),
                std::ptr::null_mut::<c_void>(),
                std::ptr::null_mut::<c_void>(),
            )
        };

        if ret == -1 {
            return Err(EmtError::PtraceError(format!(
                "PTRACE_CONT failed: {}",
                io::Error::last_os_error()
            )));
        }

        // Wait for the process to stop
        waitpid(self.pid, None).map_err(|e| EmtError::PtraceError(format!("waitpid failed: {}", e)))
    }

    /// Finds an executable code location to inject syscall instructions.
    fn find_executable_location(&self, regs: &user_regs_struct) -> Result<u64> {
        // Helper to check if an address looks like valid code
        let is_valid_code_addr = |addr: u64| -> bool {
            // Must be in user space range
            addr > 0x10000 && addr < 0x700000000000
        };

        // 1: Try RIP itself if it looks like it's in code section
        // This works for write faults where RIP is in libc/main, not in the faulting region
        if is_valid_code_addr(regs.rip) {
            // Verify we can read from this address
            if self.peek_text(regs.rip).is_ok() {
                log::debug!("Using RIP 0x{:x} for syscall injection", regs.rip);
                return Ok(regs.rip);
            }
        }

        // 2: Try the return address at RSP
        if let Ok(ret_addr) = self.peek_text(regs.rsp) {
            if is_valid_code_addr(ret_addr) && self.peek_text(ret_addr).is_ok() {
                log::debug!(
                    "Using return address 0x{:x} from stack for syscall injection",
                    ret_addr
                );
                return Ok(ret_addr);
            }
        }

        Err(EmtError::PtraceError(
            "Could not find executable location for syscall injection".to_string(),
        ))
    }

    /// Injects and executes a syscall with the given arguments.
    ///
    /// This works by:
    /// 1. Finding an executable code location (return address on stack)
    /// 2. Saving original instruction at that location
    /// 3. Writing "syscall; int3" there
    /// 4. Setting up registers for the syscall with RIP pointing to our injected code
    /// 5. Using PTRACE_CONT to let the process run
    /// 6. The syscall executes, then hits int3 which generates SIGTRAP
    /// 7. Reading the result from rax
    /// 8. Restoring original state
    pub fn inject_syscall(
        &self,
        syscall_nr: u64, // syscall number
        arg1: u64,       // rdi
        arg2: u64,       // rsi
        arg3: u64,       // rdx
        arg4: u64,       // r10
        arg5: u64,       // r8
        arg6: u64,       // r9
    ) -> Result<SyscallResult> {
        // Save original registers
        let orig_regs = self.get_registers()?;

        // Find an executable location to inject our syscall
        let inject_addr = self.find_executable_location(&orig_regs)?;

        // Save original instruction at the injection location (8 bytes on x86_64)
        let orig_insn = self.peek_text(inject_addr)?;

        // Write "syscall; int3" (0x0f 0x05 0xcc) at the injection location
        // This executes the syscall and then traps, allowing us to catch the result
        let insn_bytes = orig_insn.to_le_bytes();
        let mut new_bytes = insn_bytes;
        new_bytes[0] = SYSCALL_INT3_INSN[0]; // 0x0f
        new_bytes[1] = SYSCALL_INT3_INSN[1]; // 0x05
        new_bytes[2] = SYSCALL_INT3_INSN[2]; // 0xcc (int3)
        let new_insn_word = u64::from_le_bytes(new_bytes);

        self.poke_text(inject_addr, new_insn_word)?;

        // Set up registers for syscall
        let mut syscall_regs = orig_regs;
        syscall_regs.rax = syscall_nr;
        syscall_regs.rdi = arg1;
        syscall_regs.rsi = arg2;
        syscall_regs.rdx = arg3;
        syscall_regs.r10 = arg4;
        syscall_regs.r8 = arg5;
        syscall_regs.r9 = arg6;

        // Set RIP to our injected code location
        syscall_regs.rip = inject_addr;

        self.set_registers(&syscall_regs)?;

        log::debug!(
            "Executing injected syscall {} at 0x{:x} (orig RIP was 0x{:x})",
            syscall_nr,
            inject_addr,
            orig_regs.rip
        );

        // Continue the process - it will execute syscall then hit int3
        let status = self.ptrace_cont_and_wait()?;

        // We expect SIGTRAP from the int3 instruction
        match status {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                // This is what we expect - int3 was hit after syscall completed
                log::debug!("Got SIGTRAP as expected after syscall injection");
            }
            WaitStatus::Stopped(_, sig) => {
                // Got a different signal - restore and report
                let _ = self.poke_text(inject_addr, orig_insn);
                let _ = self.set_registers(&orig_regs);
                return Err(EmtError::PtraceError(format!(
                    "Unexpected signal {} after syscall injection (expected SIGTRAP)",
                    sig
                )));
            }
            other => {
                let _ = self.poke_text(inject_addr, orig_insn);
                let _ = self.set_registers(&orig_regs);
                return Err(EmtError::PtraceError(format!(
                    "Unexpected wait status after syscall injection: {:?}",
                    other
                )));
            }
        }

        // Read the result from rax (syscall return value)
        let result_regs = self.get_registers()?;
        let retval = result_regs.rax as i64;

        log::debug!(
            "Syscall {} completed with retval={} (0x{:x})",
            syscall_nr,
            retval,
            retval as u64
        );

        // Restore original instruction at injection location
        self.poke_text(inject_addr, orig_insn)?;

        // Restore original registers (including RIP back to original location)
        self.set_registers(&orig_regs)?;

        Ok(SyscallResult::new(retval))
    }

    /// Method to inject mprotect syscall.
    pub fn inject_mprotect(&self, addr: u64, len: u64, prot: u64) -> Result<SyscallResult> {
        self.inject_syscall(syscall_nr::MPROTECT, addr, len, prot, 0, 0, 0)
    }

    /// Reads memory from the traced process using process_vm_readv.
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; len];

        let local_iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: len,
        };

        let remote_iov = libc::iovec {
            iov_base: addr as *mut c_void,
            iov_len: len,
        };

        let nread = unsafe {
            libc::process_vm_readv(
                self.pid.as_raw(),
                &local_iov as *const libc::iovec,
                1,
                &remote_iov as *const libc::iovec,
                1,
                0,
            )
        };

        if nread == -1 {
            return Err(EmtError::PtraceError(format!(
                "process_vm_readv at 0x{:x} len {} failed: {}",
                addr,
                len,
                io::Error::last_os_error()
            )));
        }

        if (nread as usize) < len {
            buffer.truncate(nread as usize);
        }

        Ok(buffer)
    }
}

/// Creates a register snapshot for inclusion in events.
#[derive(Debug, Clone)]
pub struct RegisterSnapshot {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

impl From<user_regs_struct> for RegisterSnapshot {
    fn from(regs: user_regs_struct) -> Self {
        Self {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rbp: regs.rbp,
            rsp: regs.rsp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            eflags: regs.eflags,
            cs: regs.cs,
            ss: regs.ss,
            fs_base: regs.fs_base,
            gs_base: regs.gs_base,
        }
    }
}

impl RegisterSnapshot {
    /// Format registers as a string for logging/debugging
    pub fn format(&self) -> String {
        format!(
            "RIP: 0x{:016x}  RSP: 0x{:016x}  RBP: 0x{:016x}\n\
             RAX: 0x{:016x}  RBX: 0x{:016x}  RCX: 0x{:016x}\n\
             RDX: 0x{:016x}  RSI: 0x{:016x}  RDI: 0x{:016x}\n\
             R8:  0x{:016x}  R9:  0x{:016x}  R10: 0x{:016x}\n\
             R11: 0x{:016x}  R12: 0x{:016x}  R13: 0x{:016x}\n\
             R14: 0x{:016x}  R15: 0x{:016x}  EFLAGS: 0x{:08x}",
            self.rip,
            self.rsp,
            self.rbp,
            self.rax,
            self.rbx,
            self.rcx,
            self.rdx,
            self.rsi,
            self.rdi,
            self.r8,
            self.r9,
            self.r10,
            self.r11,
            self.r12,
            self.r13,
            self.r14,
            self.r15,
            self.eflags
        )
    }
}
