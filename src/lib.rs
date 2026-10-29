//! iouring-abuse-sensor: detect io_uring-based abuse (Curing-class) that
//! syscall-hooking EDRs miss.
//!
//! The crate has three honest pieces:
//!  1. [`uring`] / [`ops`]: a tiny raw io_uring engine and the file/socket ops,
//!     with a matching classic-syscall backend.
//!  2. [`blindness`]: a seccomp-based model of a syscall-hooking monitor, proving
//!     on the local box that io_uring bypasses it.
//!  3. [`policy`] + [`corpus`]: an origin-independent detection policy and the
//!     12-attack / 50-workload acceptance corpus.
//!
//! The real in-kernel sensor (kprobe on `security_file_permission`, see
//! `bpf/`) cannot be loaded on a box with `unprivileged_bpf_disabled=2`; it is
//! exercised in CI and must fail loudly if the load is not permitted.

pub mod blindness;
pub mod corpus;
pub mod event;
pub mod ops;
pub mod policy;
pub mod uring;
