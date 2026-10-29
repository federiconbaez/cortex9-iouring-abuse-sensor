//! Blindness measurement. Models a syscall-hooking security monitor (the
//! architecture Falco and seccomp-based tools use) with a seccomp-BPF filter
//! that intercepts the classic file/socket syscalls, returning a sentinel errno
//! so we can count exactly which operations the monitor *saw*.
//!
//! We then run the identical 12-attack corpus twice, in two forked children that
//! both install the same filter:
//!   - classic backend: every attack issues the hooked syscall  -> intercepted
//!   - io_uring backend: attacks ride io_uring_enter(2), which the filter does
//!     not hook -> the monitor sees nothing.
//!
//! This is a real, unprivileged, reproducible demonstration of the Curing-class
//! gap (ARMO, 2025): a syscall-layer monitor is structurally blind to io_uring.

use crate::corpus::execute_attacks;
use crate::ops::Backend;
use crate::uring::Ring;

/// Sentinel errno the seccomp filter returns for hooked syscalls (ENOTRECOVERABLE).
pub const SENTINEL: i32 = 131;

#[derive(Clone, Copy, Debug)]
pub struct Blindness {
    pub classic_intercepted: usize,
    pub uring_intercepted: usize,
    pub total: usize,
}

/// Count how many of the 12 attacks a syscall-layer monitor intercepts, for
/// each backend, by running them under a seccomp filter in forked children.
pub fn measure() -> anyhow::Result<Blindness> {
    let classic_intercepted = run_child(false)?;
    let uring_intercepted = run_child(true)?;
    Ok(Blindness {
        classic_intercepted,
        uring_intercepted,
        total: 12,
    })
}

/// Fork a child that installs the seccomp filter, runs the 12 attacks on the
/// chosen backend, and exits with the number of intercepted ops. Returns that
/// count. Keeping it in a child means the irreversible seccomp install never
/// touches the parent process.
fn run_child(use_uring: bool) -> anyhow::Result<usize> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        anyhow::bail!("fork failed: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        // ---- child ----
        let code = child_body(use_uring).unwrap_or(255);
        unsafe { libc::_exit(code as libc::c_int) };
    }
    // ---- parent ----
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code == 255 {
            anyhow::bail!("blindness child failed to run attacks");
        }
        Ok(code as usize)
    } else {
        anyhow::bail!("blindness child did not exit normally (status {status})");
    }
}

fn child_body(use_uring: bool) -> anyhow::Result<u8> {
    install_filter()?;
    let intercepted = if use_uring {
        let mut ring = Ring::new(16)?;
        let mut be = Backend::IoUring(&mut ring);
        count_intercepted(&mut be)?
    } else {
        let mut be = Backend::Syscall;
        count_intercepted(&mut be)?
    };
    Ok(intercepted as u8)
}

fn count_intercepted(be: &mut Backend) -> anyhow::Result<usize> {
    let events = execute_attacks(be)?;
    Ok(events
        .iter()
        .filter(|e| e.errno() == Some(SENTINEL))
        .count())
}

// --- classic (cBPF) seccomp filter assembly ---

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

// x86_64 / aarch64 syscall numbers for the hooked set.
#[cfg(target_arch = "x86_64")]
const HOOKED: [u32; 6] = [257, 437, 42, 1, 18, 275]; // openat, openat2, connect, write, pwrite64, splice
#[cfg(target_arch = "aarch64")]
const HOOKED: [u32; 6] = [56, 437, 203, 64, 68, 76]; // openat, openat2, connect, write, pwrite64, splice

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

fn install_filter() -> anyhow::Result<()> {
    // Layout (indices):
    // 0 LD arch
    // 1 JEQ arch -> jf jumps to KILL
    // 2 LD nr
    // 3..8 JEQ hooked[i] -> jt jumps to ERRNO
    // 9 RET ALLOW
    // 10 RET ERRNO(sentinel)
    // 11 RET KILL
    let errno_idx = 10u8;
    let kill_idx = 11u8;
    let mut prog: Vec<SockFilter> = Vec::new();
    prog.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    }); // arch @4
    prog.push(SockFilter {
        code: BPF_JEQ_K,
        jt: 0,
        jf: kill_idx - 1 - 1, // from idx1 to kill_idx
        k: AUDIT_ARCH,
    });
    prog.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    }); // nr @0
    for (i, nr) in HOOKED.iter().enumerate() {
        let idx = 3u8 + i as u8;
        prog.push(SockFilter {
            code: BPF_JEQ_K,
            jt: errno_idx - idx - 1,
            jf: 0,
            k: *nr,
        });
    }
    prog.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    prog.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ERRNO | (SENTINEL as u32 & 0xffff),
    });
    prog.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            anyhow::bail!(
                "PR_SET_NO_NEW_PRIVS failed: {}",
                std::io::Error::last_os_error()
            );
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            &fprog as *const _ as libc::c_ulong,
            0,
            0,
        ) != 0
        {
            anyhow::bail!("PR_SET_SECCOMP failed: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}
