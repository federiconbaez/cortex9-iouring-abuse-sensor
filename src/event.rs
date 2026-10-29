//! The event vocabulary the sensor reasons about. A real BPF-LSM / fentry
//! sensor emits one of these per security hook (e.g. `security_file_permission`,
//! `security_socket_connect`); on the build box, where BPF cannot be loaded
//! (see README), the harness emits the *same* descriptors directly from the
//! operations it actually executes, so the policy engine is exercised on real
//! io_uring / syscall traffic rather than a hand-written fixture.

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    IoUring,
    Syscall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    Open,
    Read,
    Write,
    Connect,
    Splice,
    Rename,
    Unlink,
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub origin: Origin,
    pub op: OpKind,
    /// Filesystem target of the operation, if any.
    pub path: Option<String>,
    /// Remote endpoint "ip:port" for Connect, if any.
    pub remote: Option<String>,
    /// Raw kernel result: >=0 success, negative -errno. Recorded for honesty
    /// (many attack ops fail with EACCES on an unprivileged box; the *attempt*
    /// is still a genuine io_uring submission the sensor would observe).
    pub res: i32,
    /// Human label for reporting.
    pub label: String,
}

impl Event {
    pub fn errno(&self) -> Option<i32> {
        if self.res < 0 {
            Some(-self.res)
        } else {
            None
        }
    }
}
