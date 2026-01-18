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

const SYSCALL_INT3_INSN: [u8; 3] = [0x0f, 0x05, 0xcc];

pub mod syscall_nr {
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
}

#[derive(Debug, Clone)]
pub struct SyscallResult {
    pub retval: i64,
    pub success: bool,
}

impl SyscallResult {
    pub fn new(retval: i64) -> Self {
        let success = !(-4095..0).contains(&retval);
        Self { retval, success }
    }

    pub fn as_ptr(&self) -> u64 {
        self.retval as u64
    }
}

#[derive(Debug)]
pub struct RemoteSyscall {
    pid: Pid,
}

impl RemoteSyscall {
    pub fn new(pid: pid_t) -> Self {
        Self {
            pid: Pid::from_raw(pid),
        }
    }

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

    pub fn peek_text(&self, addr: u64) -> Result<u64> {
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
        waitpid(self.pid, None).map_err(|e| EmtError::PtraceError(format!("waitpid failed: {}", e)))
    }

    fn find_executable_location(&self, regs: &user_regs_struct) -> Result<u64> {
        let is_valid_code_addr = |addr: u64| -> bool { addr > 0x10000 && addr < 0x700000000000 };

        if is_valid_code_addr(regs.rip) && self.peek_text(regs.rip).is_ok() {
            log::debug!("Using RIP 0x{:x} for syscall injection", regs.rip);
            return Ok(regs.rip);
        }

        if let Ok(ret_addr) = self.peek_text(regs.rsp) {
            if is_valid_code_addr(ret_addr) && self.peek_text(ret_addr).is_ok() {
                log::debug!(
                    "Using return address 0x{:x} for syscall injection",
                    ret_addr
                );
                return Ok(ret_addr);
            }
        }

        Err(EmtError::PtraceError(
            "Could not find executable location for syscall injection".to_string(),
        ))
    }

    pub fn inject_syscall(
        &self,
        syscall_nr: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        arg6: u64,
    ) -> Result<SyscallResult> {
        let orig_regs = self.get_registers()?;
        let inject_addr = self.find_executable_location(&orig_regs)?;
        let orig_insn = self.peek_text(inject_addr)?;

        let insn_bytes = orig_insn.to_le_bytes();
        let mut new_bytes = insn_bytes;
        new_bytes[0] = SYSCALL_INT3_INSN[0];
        new_bytes[1] = SYSCALL_INT3_INSN[1];
        new_bytes[2] = SYSCALL_INT3_INSN[2];
        let new_insn_word = u64::from_le_bytes(new_bytes);

        self.poke_text(inject_addr, new_insn_word)?;

        let mut syscall_regs = orig_regs;
        syscall_regs.rax = syscall_nr;
        syscall_regs.rdi = arg1;
        syscall_regs.rsi = arg2;
        syscall_regs.rdx = arg3;
        syscall_regs.r10 = arg4;
        syscall_regs.r8 = arg5;
        syscall_regs.r9 = arg6;
        syscall_regs.rip = inject_addr;

        self.set_registers(&syscall_regs)?;

        log::debug!(
            "Executing injected syscall {} at 0x{:x}",
            syscall_nr,
            inject_addr
        );

        let status = self.ptrace_cont_and_wait()?;

        match status {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                log::debug!("Got SIGTRAP after syscall injection");
            }
            WaitStatus::Stopped(_, sig) => {
                let _ = self.poke_text(inject_addr, orig_insn);
                let _ = self.set_registers(&orig_regs);
                return Err(EmtError::PtraceError(format!(
                    "Unexpected signal {} after syscall injection",
                    sig
                )));
            }
            other => {
                let _ = self.poke_text(inject_addr, orig_insn);
                let _ = self.set_registers(&orig_regs);
                return Err(EmtError::PtraceError(format!(
                    "Unexpected wait status: {:?}",
                    other
                )));
            }
        }

        let result_regs = self.get_registers()?;
        let retval = result_regs.rax as i64;

        log::debug!(
            "Syscall {} returned {} (0x{:x})",
            syscall_nr,
            retval,
            retval as u64
        );

        self.poke_text(inject_addr, orig_insn)?;
        self.set_registers(&orig_regs)?;

        Ok(SyscallResult::new(retval))
    }

    pub fn inject_mprotect(&self, addr: u64, len: u64, prot: u64) -> Result<SyscallResult> {
        self.inject_syscall(syscall_nr::MPROTECT, addr, len, prot, 0, 0, 0)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== SyscallResult Tests ====================

    #[test]
    fn test_syscall_result_success() {
        // Successful return values (0 and positive)
        let result = SyscallResult::new(0);
        assert!(result.success);
        assert_eq!(result.retval, 0);

        let result = SyscallResult::new(42);
        assert!(result.success);
        assert_eq!(result.retval, 42);

        // Large positive value (like mmap return address)
        let result = SyscallResult::new(0x7f0000000000_i64);
        assert!(result.success);
    }

    #[test]
    fn test_syscall_result_error() {
        // Error return values (-1 to -4095 are errors in Linux)
        let result = SyscallResult::new(-1); // EPERM
        assert!(!result.success);

        let result = SyscallResult::new(-2); // ENOENT
        assert!(!result.success);

        let result = SyscallResult::new(-12); // ENOMEM
        assert!(!result.success);

        let result = SyscallResult::new(-4095); // Max error value
        assert!(!result.success);
    }

    #[test]
    fn test_syscall_result_boundary() {
        // -4096 is NOT an error (it's a valid high address)
        let result = SyscallResult::new(-4096);
        assert!(result.success);

        // -4095 IS an error
        let result = SyscallResult::new(-4095);
        assert!(!result.success);

        // 0 is success
        let result = SyscallResult::new(0);
        assert!(result.success);
    }

    #[test]
    fn test_syscall_result_as_ptr() {
        let result = SyscallResult::new(0x7f1234560000_i64);
        assert_eq!(result.as_ptr(), 0x7f1234560000_u64);

        // Negative value interpreted as unsigned
        let result = SyscallResult::new(-1);
        assert_eq!(result.as_ptr(), u64::MAX);
    }

    // ==================== RegisterSnapshot Tests ====================

    #[test]
    fn test_register_snapshot_from_user_regs() {
        let mut regs: user_regs_struct = unsafe { mem::zeroed() };
        regs.rax = 0x1111;
        regs.rbx = 0x2222;
        regs.rcx = 0x3333;
        regs.rdx = 0x4444;
        regs.rsi = 0x5555;
        regs.rdi = 0x6666;
        regs.rbp = 0x7777;
        regs.rsp = 0x8888;
        regs.r8 = 0x9999;
        regs.r9 = 0xAAAA;
        regs.r10 = 0xBBBB;
        regs.r11 = 0xCCCC;
        regs.r12 = 0xDDDD;
        regs.r13 = 0xEEEE;
        regs.r14 = 0xFFFF;
        regs.r15 = 0x1234;
        regs.rip = 0x400000;
        regs.eflags = 0x202;
        regs.cs = 0x33;
        regs.ss = 0x2B;
        regs.fs_base = 0x7f0000000000;
        regs.gs_base = 0x0;

        let snapshot = RegisterSnapshot::from(regs);

        assert_eq!(snapshot.rax, 0x1111);
        assert_eq!(snapshot.rbx, 0x2222);
        assert_eq!(snapshot.rcx, 0x3333);
        assert_eq!(snapshot.rdx, 0x4444);
        assert_eq!(snapshot.rsi, 0x5555);
        assert_eq!(snapshot.rdi, 0x6666);
        assert_eq!(snapshot.rbp, 0x7777);
        assert_eq!(snapshot.rsp, 0x8888);
        assert_eq!(snapshot.r8, 0x9999);
        assert_eq!(snapshot.r9, 0xAAAA);
        assert_eq!(snapshot.r10, 0xBBBB);
        assert_eq!(snapshot.r11, 0xCCCC);
        assert_eq!(snapshot.r12, 0xDDDD);
        assert_eq!(snapshot.r13, 0xEEEE);
        assert_eq!(snapshot.r14, 0xFFFF);
        assert_eq!(snapshot.r15, 0x1234);
        assert_eq!(snapshot.rip, 0x400000);
        assert_eq!(snapshot.eflags, 0x202);
        assert_eq!(snapshot.cs, 0x33);
        assert_eq!(snapshot.ss, 0x2B);
        assert_eq!(snapshot.fs_base, 0x7f0000000000);
        assert_eq!(snapshot.gs_base, 0x0);
    }

    #[test]
    fn test_register_snapshot_format() {
        let snapshot = RegisterSnapshot {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0x7fffffffe000,
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
            ss: 0x2B,
            fs_base: 0,
            gs_base: 0,
        };

        let formatted = snapshot.format();

        assert!(formatted.contains("RIP: 0x0000000000401000"));
        assert!(formatted.contains("RSP: 0x00007fffffffd000"));
        assert!(formatted.contains("RBP: 0x00007fffffffe000"));
        assert!(formatted.contains("EFLAGS: 0x00000202"));
    }

    #[test]
    fn test_register_snapshot_clone() {
        let snapshot = RegisterSnapshot {
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

        let cloned = snapshot.clone();
        assert_eq!(cloned.rax, 0x42);
        assert_eq!(cloned.rip, 0x400000);
    }

    // ==================== RemoteSyscall Tests ====================

    #[test]
    fn test_remote_syscall_new() {
        let remote = RemoteSyscall::new(1234);
        assert_eq!(remote.pid, Pid::from_raw(1234));
    }

    // ==================== syscall_nr Constants Tests ====================

    #[test]
    fn test_syscall_numbers() {
        // Verify syscall numbers match Linux x86_64 ABI
        assert_eq!(syscall_nr::MMAP, 9);
        assert_eq!(syscall_nr::MPROTECT, 10);
        assert_eq!(syscall_nr::MUNMAP, 11);
    }
}
