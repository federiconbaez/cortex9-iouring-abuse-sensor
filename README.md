# iouring-abuse-sensor

Detect **io_uring-based abuse (Curing-class)** — the file reads, persistence
writes and C2 egress that a rootkit can perform entirely through io_uring,
without ever issuing the system calls a syscall-hooking EDR watches.

The project ships three honest pieces:

1. **A userspace harness** that executes a fixed corpus of attacks and
   legitimate workloads twice — once through a tiny raw io_uring engine, once
   through the equivalent classic syscalls.
2. **A blindness measurement** that models a syscall-hooking monitor with a
   seccomp filter and shows, on an unprivileged box, that it catches every
   classic attack and **none** of the io_uring variants.
3. **An origin-independent detection policy** plus a real **in-kernel sensor**
   (a kprobe on `security_file_permission`, the VFS choke point every file
   access passes through) that is loaded and exercised **in CI** — and fails
   loudly where BPF cannot be loaded.

## Why

ARMO's *Curing* research (Apr 2025) showed that Falco, Microsoft Defender and
other syscall-hooking tools are structurally blind to io_uring, and recommends
two robust fixes: KRSI/LSM-BPF hooks, or *"a Kprobe that reliably executes each
time a file is accessed"*. This repo takes the second, most portable option:
`security_file_permission` is called on every read/write regardless of whether
the request arrived via `read(2)` or via `io_uring_enter(2)`.

Source read for the threat model and detection guidance:
<https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/>.
The io_uring SQE layout and opcodes used by the engine were taken from the
kernel uapi header `/usr/include/linux/io_uring.h` on the build host. The
*Curing* PoC repo itself was **not** fetched; its behaviour is described only as
summarised by the ARMO blog above.

## What is measured, and where

| Claim | Where it runs | How |
|---|---|---|
| A syscall-layer monitor is blind to io_uring | **local box**, unprivileged | seccomp model, `blindness` |
| The policy flags attacks, not legit traffic | **local box** | `corpus` over real io_uring ops |
| The kernel sensor actually sees io_uring file access a read-hook misses | **CI / VM**, root | `enforce.yml` loads the BPF kprobe |
| In-kernel CPU overhead p99 < 3% | **not measured here** | requires a VM load bench (declared gap) |

### Reproduce (box)

```
cargo run --release -- blindness
# Syscall-layer monitor (seccomp model) interception over 12 attacks:
#   classic syscalls : 12/12
#   io_uring         : 0/12

cargo run --release -- corpus
# Detection: 12/12 attacks flagged
# False positives: 0/50 legit workloads (FPR 0.00%)
# ACCEPTANCE: PASS

./scripts/measure.sh            # blindness + detection + FPR + policy cost
```

Measured on the build host (kernel 6.12.94, `unprivileged_bpf_disabled=2`):

- **Detection: 12 / 12** io_uring attacks flagged.
- **False positives: 0 / 50** legit io_uring workloads (FPR 0.00%, threshold ≤2%).
- **Blindness: classic 12/12 intercepted, io_uring 0/12** by the seccomp model.
- **Policy cost: ~83 ns / event** (200 000-iteration microbenchmark); this is
  the userspace classifier cost, *not* the in-kernel sensor overhead.

Command for every number above: `./scripts/measure.sh` (or `cargo run --release
-- measure --iters 200000`).

### The attack corpus (12)

Six sensitive reads (`/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`,
`/root/.ssh/id_rsa`, `/proc/1/maps`, `/etc/ssl/private/…`), one splice-based
exfil of `/etc/shadow`, four persistence writes (`/etc/cron.d`,
`/etc/ld.so.preload`, `/root/.ssh/authorized_keys`, a systemd unit), and one C2
connect to TEST-NET-1 (`192.0.2.1`, RFC 5737). On an unprivileged box most of
these return `EACCES`/`ECANCELED`; the **io_uring submission is real either
way**, and that attempt is exactly what the sensor keys on. The 50 legit
workloads are app-owned file reads/writes, splices, loopback connects to a real
local listener, and reads of benign system files (`/etc/passwd`, `/etc/hosts`,
`/proc/self/status`, …) that a naive "any `/etc` read" rule would mis-flag.

## How the kernel sensor is proven (CI)

`enforce.yml` installs clang + libbpf, builds `bpf/sensor.bpf.o`, loads it with
**sudo**, attaches a kprobe to `security_file_permission` and one to
`__x64_sys_read`, then forks a child that performs an io_uring open+read of a
readable file. It asserts that the sensor counter (file-permission) incremented
for that PID while the read-syscall counter stayed at zero — the Curing gap,
demonstrated with a real `bpf(BPF_PROG_LOAD)`. If any step is refused by the
kernel the job exits non-zero; **there is no silent skip.** `ci.yml` covers fmt,
clippy, the test suite, and the box-measurable acceptance numbers.

## Honest limitations / declared gaps

- **In-kernel overhead (p99 < 3% CPU) is not measured.** It needs a loaded BPF
  program under a `fio`-class stress bench in a VM; the box cannot load BPF
  (`unprivileged_bpf_disabled=2`, no `/dev/kvm`). No fabricated number is given.
- **The box detection score grades the policy decision**, fed the real op
  descriptors produced by executing the io_uring corpus. The claim that the
  *kernel* sensor captures those events independent of issue path is what
  `enforce.yml` tests in CI, not the box run.
- **The "syscall monitor" is a seccomp model, not Falco itself.** Falco was not
  run here; seccomp is a faithful stand-in for the syscall-interposition
  architecture the ARMO blog shows Falco relies on.
- **`copy_file_range` has no io_uring opcode**, so the exfil scenario uses
  `IORING_OP_SPLICE` (a real io_uring data-movement op) instead.
- **The sensor is kprobe-based.** KRSI / BPF-LSM (`security_file_permission` as
  an `lsm/` program) is the production-grade choice recommended by ARMO, but it
  needs `lsm=bpf` active and is less portable across runners; a kprobe on the
  same function is the portable demonstration here.
- **Not a complete EDR.** No process hiding, no rootkit, no new bypass; this is
  a detector and a measurement, per the project scope.

## Layout

```
src/uring.rs      raw io_uring engine (io_uring_setup/enter + mmap'd rings)
src/ops.rs        file/socket ops, io_uring and classic-syscall backends
src/event.rs      the event vocabulary the sensor reasons about
src/policy.rs     origin-independent detection rules (+ unit tests)
src/corpus.rs     12 attacks + 50 legit workloads, scored
src/blindness.rs  seccomp model of a syscall-hooking monitor
bpf/sensor.bpf.c  kprobe sensor (security_file_permission vs __x64_sys_read)
bpf/loader.c      libbpf loader + in-CI visibility proof
rules/default.json the shipped policy
```

## License

Apache-2.0. The BPF object declares a GPL license string because kprobe
programs require it at load time; the project source is Apache-2.0.
