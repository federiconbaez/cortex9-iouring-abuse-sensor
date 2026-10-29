//! Execute a file/network operation either through io_uring or through the
//! equivalent classic syscall, and report the kernel result. Both paths do the
//! *same observable thing* to the kernel VFS/socket layer; they differ only in
//! how the request is issued. That difference is exactly what blinds a
//! syscall-hooking monitor.

use crate::event::{Event, OpKind, Origin};
use crate::uring::{self, Ring, Sqe};
use std::ffi::CString;
use std::io;

pub enum Backend<'a> {
    IoUring(&'a mut Ring),
    Syscall,
}

impl Backend<'_> {
    fn origin(&self) -> Origin {
        match self {
            Backend::IoUring(_) => Origin::IoUring,
            Backend::Syscall => Origin::Syscall,
        }
    }
}

const AT_FDCWD: i32 = -100;

/// Open `path` read-only, read up to 64 bytes, then close. Returns the open
/// result (fd or -errno) as the event `res`.
pub fn open_read(be: &mut Backend, label: &str, path: &str) -> io::Result<Event> {
    let origin = be.origin();
    let cpath = CString::new(path).unwrap();
    let res = match be {
        Backend::IoUring(ring) => {
            let r = ring.submit_wait(Sqe {
                opcode: uring::IORING_OP_OPENAT,
                fd: AT_FDCWD,
                addr: cpath.as_ptr() as u64,
                len: 0,
                op_flags: libc::O_RDONLY as u32,
                ..Default::default()
            })?;
            if r >= 0 {
                let fd = r;
                let mut buf = [0u8; 64];
                let _ = ring.submit_wait(Sqe {
                    opcode: uring::IORING_OP_READ,
                    fd,
                    addr: buf.as_mut_ptr() as u64,
                    len: buf.len() as u32,
                    off: u64::MAX, // -1: use current offset
                    ..Default::default()
                })?;
                let _ = ring.submit_wait(Sqe {
                    opcode: uring::IORING_OP_CLOSE,
                    fd,
                    ..Default::default()
                })?;
            }
            r
        }
        Backend::Syscall => unsafe {
            let fd = libc::open(cpath.as_ptr(), libc::O_RDONLY);
            if fd >= 0 {
                let mut buf = [0u8; 64];
                let _ = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
                libc::close(fd);
                fd
            } else {
                -io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            }
        },
    };
    Ok(Event {
        origin,
        op: OpKind::Open,
        path: Some(path.to_string()),
        remote: None,
        res,
        label: label.to_string(),
    })
}

/// Create/open `path` for write and write `data`. Open result is the event res.
pub fn write_file(be: &mut Backend, label: &str, path: &str, data: &[u8]) -> io::Result<Event> {
    let origin = be.origin();
    let cpath = CString::new(path).unwrap();
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC;
    let res = match be {
        Backend::IoUring(ring) => {
            let r = ring.submit_wait(Sqe {
                opcode: uring::IORING_OP_OPENAT,
                fd: AT_FDCWD,
                addr: cpath.as_ptr() as u64,
                len: 0o600,
                op_flags: flags as u32,
                ..Default::default()
            })?;
            if r >= 0 {
                let fd = r;
                let _ = ring.submit_wait(Sqe {
                    opcode: uring::IORING_OP_WRITE,
                    fd,
                    addr: data.as_ptr() as u64,
                    len: data.len() as u32,
                    off: 0,
                    ..Default::default()
                })?;
                let _ = ring.submit_wait(Sqe {
                    opcode: uring::IORING_OP_CLOSE,
                    fd,
                    ..Default::default()
                })?;
            }
            r
        }
        Backend::Syscall => unsafe {
            let fd = libc::open(cpath.as_ptr(), flags, 0o600);
            if fd >= 0 {
                let _ = libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
                libc::close(fd);
                fd
            } else {
                -io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            }
        },
    };
    Ok(Event {
        origin,
        op: OpKind::Write,
        path: Some(path.to_string()),
        remote: None,
        res,
        label: label.to_string(),
    })
}

/// TCP connect to ip:port. Non-blocking-ish: we create the socket then issue
/// the connect. The connect result (0 / -errno) is the event res.
pub fn connect(be: &mut Backend, label: &str, ip: &str, port: u16) -> io::Result<Event> {
    let origin = be.origin();
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // 2s send timeout so a black-holed C2 address can't hang the harness.
    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
    }
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = ipv4_to_be(ip);
    let addrlen = std::mem::size_of::<libc::sockaddr_in>() as u32;

    let res = match be {
        Backend::IoUring(ring) => {
            // Link a 1s relative timeout so a black-holed C2 address can't hang
            // the harness: the connect is cancelled (-ECANCELED / -ETIME) but the
            // attempted remote endpoint is still recorded as the event.
            #[repr(C)]
            struct KTimespec {
                tv_sec: i64,
                tv_nsec: i64,
            }
            let ts = KTimespec {
                tv_sec: 1,
                tv_nsec: 0,
            };
            let done = ring.submit_batch(&[
                Sqe {
                    opcode: uring::IORING_OP_CONNECT,
                    flags: uring::IOSQE_IO_LINK,
                    fd: sock,
                    addr: &addr as *const _ as u64,
                    off: addrlen as u64,
                    user_data: 1,
                    ..Default::default()
                },
                Sqe {
                    opcode: uring::IORING_OP_LINK_TIMEOUT,
                    addr: &ts as *const _ as u64,
                    len: 1,
                    user_data: 2,
                    ..Default::default()
                },
            ])?;
            done.iter()
                .find(|(u, _)| *u == 1)
                .map(|(_, r)| *r)
                .unwrap_or(-libc::EIO)
        }
        Backend::Syscall => unsafe {
            let r = libc::connect(sock, &addr as *const _ as *const libc::sockaddr, addrlen);
            if r == 0 {
                0
            } else {
                -io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            }
        },
    };
    unsafe { libc::close(sock) };
    Ok(Event {
        origin,
        op: OpKind::Connect,
        path: None,
        remote: Some(format!("{ip}:{port}")),
        res,
        label: label.to_string(),
    })
}

/// Exfiltrate `src` through a pipe using splice (io_uring) / splice(2)
/// (classic). Models data movement that never shows up as read()/write().
/// The splice result (bytes moved, or -errno) is the event res.
pub fn splice_exfil(be: &mut Backend, label: &str, src: &str) -> io::Result<Event> {
    let origin = be.origin();
    let cpath = CString::new(src).unwrap();
    // Open the source through the SAME backend as the splice, so that under the
    // io_uring backend the whole exfil (open + move) stays off the syscall path.
    let in_fd = match be {
        Backend::IoUring(ring) => ring.submit_wait(Sqe {
            opcode: uring::IORING_OP_OPENAT,
            fd: AT_FDCWD,
            addr: cpath.as_ptr() as u64,
            op_flags: libc::O_RDONLY as u32,
            ..Default::default()
        })?,
        Backend::Syscall => unsafe {
            let fd = libc::open(cpath.as_ptr(), libc::O_RDONLY);
            if fd >= 0 {
                fd
            } else {
                -io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            }
        },
    };
    if in_fd < 0 {
        // The open attempt itself is the event (e.g. EACCES on /etc/shadow).
        return Ok(Event {
            origin,
            op: OpKind::Splice,
            path: Some(src.to_string()),
            remote: None,
            res: in_fd,
            label: label.to_string(),
        });
    }
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        unsafe { libc::close(in_fd) };
        return Err(io::Error::last_os_error());
    }
    let res = match be {
        Backend::IoUring(ring) => ring.submit_wait(Sqe {
            opcode: uring::IORING_OP_SPLICE,
            fd: fds[1],          // fd_out = pipe write end
            splice_fd_in: in_fd, // fd_in
            off: u64::MAX,       // off_out = -1
            addr: u64::MAX,      // splice_off_in = -1
            len: 4096,
            ..Default::default()
        })?,
        Backend::Syscall => unsafe {
            let r = libc::splice(
                in_fd,
                std::ptr::null_mut(),
                fds[1],
                std::ptr::null_mut(),
                4096,
                0,
            );
            if r >= 0 {
                r as i32
            } else {
                -io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            }
        },
    };
    unsafe {
        libc::close(in_fd);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    Ok(Event {
        origin,
        op: OpKind::Splice,
        path: Some(src.to_string()),
        remote: None,
        res,
        label: label.to_string(),
    })
}

fn ipv4_to_be(ip: &str) -> u32 {
    let mut octets = [0u8; 4];
    for (i, part) in ip.split('.').enumerate().take(4) {
        octets[i] = part.parse().unwrap_or(0);
    }
    u32::from_ne_bytes(octets)
}
