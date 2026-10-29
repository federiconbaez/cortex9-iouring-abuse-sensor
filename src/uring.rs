//! Minimal raw io_uring engine built directly on the `io_uring_setup(2)` and
//! `io_uring_enter(2)` syscalls plus the mmap'd SQ/CQ rings. No liburing.
//!
//! Only the subset of ops the harness needs is implemented, each submitted one
//! at a time and completed synchronously. The point of the crate is *detection*
//! of abuse, not a high-performance ring, so single-shot submit/complete keeps
//! the layout auditable.
//!
//! Layout constants mirror `/usr/include/linux/io_uring.h` (uapi). Verified
//! against the header present on the build box (kernel 6.12 uapi).

use std::io;
use std::os::unix::io::RawFd;

// syscall numbers (x86_64). Guarded so a non-x86_64 build fails loudly rather
// than silently using the wrong number.
#[cfg(target_arch = "x86_64")]
const SYS_IO_URING_SETUP: libc::c_long = 425;
#[cfg(target_arch = "x86_64")]
const SYS_IO_URING_ENTER: libc::c_long = 426;
#[cfg(target_arch = "aarch64")]
const SYS_IO_URING_SETUP: libc::c_long = 425;
#[cfg(target_arch = "aarch64")]
const SYS_IO_URING_ENTER: libc::c_long = 426;

// opcodes
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_WRITE: u8 = 23;
pub const IORING_OP_CONNECT: u8 = 16;
pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_CLOSE: u8 = 19;
pub const IORING_OP_SPLICE: u8 = 30;
pub const IORING_OP_RENAMEAT: u8 = 35;
pub const IORING_OP_UNLINKAT: u8 = 36;
pub const IORING_OP_LINK_TIMEOUT: u8 = 15;

/// SQE flag: this SQE is linked to the next one.
pub const IOSQE_IO_LINK: u8 = 1 << 2;

const IORING_ENTER_GETEVENTS: u32 = 1;

const IORING_OFF_SQ_RING: i64 = 0;
const IORING_OFF_SQES: i64 = 0x1000_0000;

#[repr(C)]
#[derive(Default)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct IoCqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
}

/// 64-byte SQE. Fields we don't set stay zero.
#[repr(C)]
#[derive(Clone, Copy)]
struct IoUringSqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,  // union: off / addr2 / splice_off_in-for-out
    addr: u64, // union: addr / splice_off_in
    len: u32,
    op_flags: u32, // union: rw_flags / open_flags / splice_flags ...
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32, // union: splice_fd_in / file_index
    addr3: u64,
    __pad2: u64,
}

impl Default for IoUringSqe {
    fn default() -> Self {
        // SAFETY: all-zero is a valid (NOP-like) SQE.
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoUringCqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

/// A submission for the single-shot engine.
#[derive(Clone, Copy, Default)]
pub struct Sqe {
    pub opcode: u8,
    pub flags: u8,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub splice_fd_in: i32,
    pub user_data: u64,
}

pub struct Ring {
    ring_fd: RawFd,
    sq_ptr: *mut libc::c_void,
    sq_len: usize,
    sqes_ptr: *mut IoUringSqe,
    sqes_len: usize,
    sq_tail: *mut u32,
    sq_ring_mask: u32,
    sq_array: *mut u32,
    cq_head: *mut u32,
    cq_tail: *mut u32,
    cq_ring_mask: u32,
    cqes: *mut IoUringCqe,
}

impl Ring {
    /// Create a ring with `entries` slots. Returns the real `-errno` wrapped in
    /// `io::Error` if `io_uring_setup` is unavailable — never a silent fallback.
    pub fn new(entries: u32) -> io::Result<Ring> {
        let mut p = IoUringParams::default();
        let ret = unsafe {
            libc::syscall(
                SYS_IO_URING_SETUP,
                entries as libc::c_long,
                &mut p as *mut _ as libc::c_long,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        let ring_fd = ret as RawFd;

        let sq_ring_sz = (p.sq_off.array + p.sq_entries * 4) as usize;
        let cq_ring_sz = (p.cq_off.cqes + p.cq_entries * 16) as usize;
        let sq_len = sq_ring_sz.max(cq_ring_sz);

        let sq_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                sq_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                IORING_OFF_SQ_RING,
            )
        };
        if sq_ptr == libc::MAP_FAILED {
            let e = io::Error::last_os_error();
            unsafe { libc::close(ring_fd) };
            return Err(e);
        }

        let sqes_len = p.sq_entries as usize * std::mem::size_of::<IoUringSqe>();
        let sqes_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                sqes_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                IORING_OFF_SQES,
            )
        } as *mut IoUringSqe;
        if sqes_ptr as *mut libc::c_void == libc::MAP_FAILED {
            let e = io::Error::last_os_error();
            unsafe {
                libc::munmap(sq_ptr, sq_len);
                libc::close(ring_fd);
            }
            return Err(e);
        }

        let base = sq_ptr as *mut u8;
        unsafe {
            Ok(Ring {
                ring_fd,
                sq_ptr,
                sq_len,
                sqes_ptr,
                sqes_len,
                sq_tail: base.add(p.sq_off.tail as usize) as *mut u32,
                sq_ring_mask: *(base.add(p.sq_off.ring_mask as usize) as *mut u32),
                sq_array: base.add(p.sq_off.array as usize) as *mut u32,
                cq_head: base.add(p.cq_off.head as usize) as *mut u32,
                cq_tail: base.add(p.cq_off.tail as usize) as *mut u32,
                cq_ring_mask: *(base.add(p.cq_off.ring_mask as usize) as *mut u32),
                cqes: base.add(p.cq_off.cqes as usize) as *mut IoUringCqe,
            })
        }
    }

    /// Submit one SQE and block for its completion. Returns the raw `res`
    /// (>=0 on success, negative `-errno` on failure), exactly as the kernel
    /// reported it — this is the signal the harness records.
    pub fn submit_wait(&mut self, s: Sqe) -> io::Result<i32> {
        let done = self.submit_batch(&[s])?;
        Ok(done[0].1)
    }

    /// Submit a batch of SQEs (which may be linked via [`Sqe::flags`] =
    /// `IOSQE_IO_LINK`) and block until all `n` have completed. Returns the
    /// `(user_data, res)` of each completion. The caller sets `user_data` to
    /// identify completions, which may arrive in any order.
    pub fn submit_batch(&mut self, batch: &[Sqe]) -> io::Result<Vec<(u64, i32)>> {
        let n = batch.len();
        assert!(n >= 1);
        unsafe {
            let mut tail = std::ptr::read_volatile(self.sq_tail);
            for s in batch {
                let index = (tail & self.sq_ring_mask) as usize;
                let sqe = self.sqes_ptr.add(index);
                std::ptr::write(sqe, IoUringSqe::default());
                (*sqe).opcode = s.opcode;
                (*sqe).flags = s.flags;
                (*sqe).fd = s.fd;
                (*sqe).off = s.off;
                (*sqe).addr = s.addr;
                (*sqe).len = s.len;
                (*sqe).op_flags = s.op_flags;
                (*sqe).splice_fd_in = s.splice_fd_in;
                (*sqe).user_data = if s.user_data != 0 {
                    s.user_data
                } else {
                    0x5155
                };
                *self.sq_array.add(index) = index as u32;
                tail = tail.wrapping_add(1);
            }
            std::ptr::write_volatile(self.sq_tail, tail);

            let r = libc::syscall(
                SYS_IO_URING_ENTER,
                self.ring_fd as libc::c_long,
                n as libc::c_long,
                n as libc::c_long,
                IORING_ENTER_GETEVENTS as libc::c_long,
                0 as libc::c_long,
                0 as libc::c_long,
            );
            if r < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut out = Vec::with_capacity(n);
            let mut head = std::ptr::read_volatile(self.cq_head);
            // Spin-drain until we have n completions (they are ready after the
            // GETEVENTS enter; a linked timeout can yield its own completion).
            while out.len() < n {
                let ctail = std::ptr::read_volatile(self.cq_tail);
                while head != ctail && out.len() < n {
                    let cqe = self.cqes.add((head & self.cq_ring_mask) as usize);
                    out.push(((*cqe).user_data, (*cqe).res));
                    head = head.wrapping_add(1);
                }
                std::ptr::write_volatile(self.cq_head, head);
                if out.len() < n {
                    // Wait for the remaining completions (e.g. the link timeout).
                    let rr = libc::syscall(
                        SYS_IO_URING_ENTER,
                        self.ring_fd as libc::c_long,
                        0 as libc::c_long,
                        (n - out.len()) as libc::c_long,
                        IORING_ENTER_GETEVENTS as libc::c_long,
                        0 as libc::c_long,
                        0 as libc::c_long,
                    );
                    if rr < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            Ok(out)
        }
    }

    pub fn ring_fd(&self) -> RawFd {
        self.ring_fd
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.sqes_ptr as *mut libc::c_void, self.sqes_len);
            libc::munmap(self.sq_ptr, self.sq_len);
            libc::close(self.ring_fd);
        }
    }
}

/// True if `io_uring_setup` works at all on this host.
pub fn available() -> bool {
    Ring::new(4).is_ok()
}
