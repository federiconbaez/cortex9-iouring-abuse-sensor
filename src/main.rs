use anyhow::Result;
use clap::{Parser, Subcommand};
use iouring_abuse_sensor::{blindness, corpus, event, ops, policy, uring};
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "iouring-abuse-sensor",
    about = "Detect io_uring abuse (Curing-class) that syscall-hooking EDRs miss"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report whether io_uring_setup(2) works on this host (exit 1 if not).
    CheckUring,
    /// Measure how many attacks a syscall-layer monitor intercepts per backend.
    Blindness {
        #[arg(long)]
        json: bool,
    },
    /// Run the acceptance corpus and enforce the thresholds (exit 1 on miss).
    Corpus {
        #[arg(long)]
        json: bool,
    },
    /// Full reproducible measurement: blindness + detection + FPR + policy cost.
    Measure {
        /// Iterations for the policy-latency microbenchmark.
        #[arg(long, default_value_t = 50_000)]
        iters: u64,
        #[arg(long)]
        json: bool,
    },
    /// Issue a single io_uring openat+read of a target (for the in-kernel sensor
    /// test in CI). Prints the raw io_uring result.
    ///
    /// With `--ready-fd N` the process synchronises with the BPF loader so the
    /// measured window contains ONLY the io_uring read: it blocks SIGUSR1, writes
    /// one byte to fd N ("startup done"), waits for SIGUSR1 ("counters zeroed,
    /// go"), and only then performs the io_uring open+read. No read(2) is issued
    /// after the go signal, so a read-syscall hook must observe zero.
    AttackOnce {
        #[arg(long)]
        target: String,
        #[arg(long)]
        ready_fd: Option<i32>,
    },
}

const DETECT_MIN: usize = 11;
const FPR_MAX: f64 = 0.02;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::CheckUring => {
            if uring::available() {
                println!("io_uring_setup: OK");
                Ok(())
            } else {
                eprintln!("io_uring_setup: UNAVAILABLE");
                std::process::exit(1);
            }
        }
        Cmd::Blindness { json } => {
            let b = blindness::measure()?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "syscall_monitor_intercepted": {
                            "classic": b.classic_intercepted,
                            "io_uring": b.uring_intercepted,
                            "total": b.total,
                        }
                    })
                );
            } else {
                println!(
                    "Syscall-layer monitor (seccomp model) interception over {} attacks:",
                    b.total
                );
                println!("  classic syscalls : {}/{}", b.classic_intercepted, b.total);
                println!("  io_uring         : {}/{}", b.uring_intercepted, b.total);
            }
            Ok(())
        }
        Cmd::Corpus { json } => {
            let rules = policy::Rules::default();
            let r = corpus::run(&rules)?;
            report_corpus(&r, json);
            enforce(&r)
        }
        Cmd::Measure { iters, json } => {
            let rules = policy::Rules::default();
            let r = corpus::run(&rules)?;
            let b = blindness::measure()?;
            let pol = policy_latency(&rules, iters);
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "detection": { "detected": r.attacks_detected(), "total": r.attacks_total() },
                        "false_positives": r.false_positives(),
                        "legit_total": r.legit_total(),
                        "fpr": r.fpr(),
                        "blindness": {
                            "classic_intercepted": b.classic_intercepted,
                            "io_uring_intercepted": b.uring_intercepted,
                            "total": b.total,
                        },
                        "policy_ns_per_event": pol,
                        "kernel_overhead_pct_p99": serde_json::Value::Null,
                    })
                );
            } else {
                report_corpus(&r, false);
                println!(
                    "Blindness: syscall-monitor intercepts classic {}/{}, io_uring {}/{}",
                    b.classic_intercepted, b.total, b.uring_intercepted, b.total
                );
                println!("Policy cost: {pol:.0} ns/event ({iters} iters)");
                println!(
                    "Kernel sensor overhead (p99 CPU): NOT MEASURED on this box \
                     (bpf load disabled); see enforce.yml / VM."
                );
            }
            enforce(&r)
        }
        Cmd::AttackOnce { target, ready_fd } => {
            if let Some(fd) = ready_fd {
                barrier_wait(fd)?;
            }
            let mut ring =
                uring::Ring::new(8).map_err(|e| anyhow::anyhow!("io_uring_setup failed: {e}"))?;
            let mut be = ops::Backend::IoUring(&mut ring);
            let ev = ops::open_read(&mut be, "attack-once", &target)?;
            println!(
                "io_uring openat({target}) res={} errno={:?}",
                ev.res,
                ev.errno()
            );
            Ok(())
        }
    }
}

fn report_corpus(r: &corpus::CorpusResult, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "detection": { "detected": r.attacks_detected(), "total": r.attacks_total() },
                "false_positives": r.false_positives(),
                "legit_total": r.legit_total(),
                "fpr": r.fpr(),
            })
        );
    } else {
        println!(
            "Detection: {}/{} attacks flagged",
            r.attacks_detected(),
            r.attacks_total()
        );
        println!(
            "False positives: {}/{} legit workloads (FPR {:.2}%)",
            r.false_positives(),
            r.legit_total(),
            r.fpr() * 100.0
        );
    }
}

fn enforce(r: &corpus::CorpusResult) -> Result<()> {
    let mut ok = true;
    if r.attacks_detected() < DETECT_MIN {
        eprintln!(
            "FAIL: detection {}/{} < {}",
            r.attacks_detected(),
            r.attacks_total(),
            DETECT_MIN
        );
        ok = false;
    }
    if r.fpr() > FPR_MAX {
        eprintln!(
            "FAIL: FPR {:.2}% > {:.2}%",
            r.fpr() * 100.0,
            FPR_MAX * 100.0
        );
        ok = false;
    }
    if ok {
        println!("ACCEPTANCE: PASS");
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn policy_latency(rules: &policy::Rules, iters: u64) -> f64 {
    let ev = event::Event {
        origin: event::Origin::IoUring,
        op: event::OpKind::Open,
        path: Some("/etc/shadow".to_string()),
        remote: None,
        res: -13,
        label: "bench".to_string(),
    };
    // warmup
    for _ in 0..1000 {
        std::hint::black_box(policy::classify(rules, &ev));
    }
    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(policy::classify(rules, &ev));
    }
    let el = t.elapsed();
    el.as_nanos() as f64 / iters as f64
}

/// Synchronisation barrier for the CI blindness proof. Blocks SIGUSR1, signals
/// readiness on `ready_fd`, then waits for SIGUSR1 before returning. After this
/// returns the caller issues only io_uring ops, so no read(2) happens in the
/// measured window.
fn barrier_wait(ready_fd: i32) -> Result<()> {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            anyhow::bail!("sigprocmask: {}", std::io::Error::last_os_error());
        }
        let one = [1u8];
        if libc::write(ready_fd, one.as_ptr() as *const libc::c_void, 1) != 1 {
            anyhow::bail!("barrier ready write: {}", std::io::Error::last_os_error());
        }
        let mut sig: libc::c_int = 0;
        if libc::sigwait(&set, &mut sig) != 0 {
            anyhow::bail!("sigwait: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}
