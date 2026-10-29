//! The acceptance corpus: a fixed set of io_uring abuse scenarios (Curing-class)
//! and a larger set of legitimate io_uring workloads, all executed for real on
//! the host, turned into [`Event`]s, and scored against the policy.

use crate::event::Event;
use crate::ops::{self, Backend};
use crate::policy::{classify, Rules, Verdict};
use crate::uring::Ring;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

pub struct Scored {
    pub ev: Event,
    pub expected_malicious: bool,
}

pub struct CorpusResult {
    pub attacks: Vec<(Scored, Verdict)>,
    pub legit: Vec<(Scored, Verdict)>,
}

impl CorpusResult {
    pub fn attacks_detected(&self) -> usize {
        self.attacks
            .iter()
            .filter(|(_, v)| *v == Verdict::Malicious)
            .count()
    }
    pub fn attacks_total(&self) -> usize {
        self.attacks.len()
    }
    pub fn false_positives(&self) -> usize {
        self.legit
            .iter()
            .filter(|(_, v)| *v == Verdict::Malicious)
            .count()
    }
    pub fn legit_total(&self) -> usize {
        self.legit.len()
    }
    pub fn fpr(&self) -> f64 {
        if self.legit.is_empty() {
            0.0
        } else {
            self.false_positives() as f64 / self.legit.len() as f64
        }
    }
}

/// Execute the 12 Curing-class attacks through `be` and return the resulting
/// events (one per scenario). Used both by the scored corpus (io_uring backend)
/// and by the blindness measurement (either backend).
pub fn execute_attacks(be: &mut Backend) -> anyhow::Result<Vec<Event>> {
    let mut out = Vec::new();
    let payload = b"* * * * * root /tmp/.x\n";

    for (label, path) in [
        ("read-shadow", "/etc/shadow"),
        ("read-gshadow", "/etc/gshadow"),
        ("read-sudoers", "/etc/sudoers"),
        ("read-root-sshkey", "/root/.ssh/id_rsa"),
        ("read-proc1-maps", "/proc/1/maps"),
        ("read-ssl-private", "/etc/ssl/private/server.key"),
    ] {
        out.push(ops::open_read(be, label, path)?);
    }

    out.push(ops::splice_exfil(be, "splice-exfil-shadow", "/etc/shadow")?);

    for (label, path) in [
        ("write-cron", "/etc/cron.d/cx9"),
        ("write-ldpreload", "/etc/ld.so.preload"),
        ("write-root-authkeys", "/root/.ssh/authorized_keys"),
        ("write-systemd-unit", "/etc/systemd/system/cx9.service"),
    ] {
        out.push(ops::write_file(be, label, path, payload)?);
    }

    out.push(ops::connect(be, "connect-c2", "192.0.2.1", 443)?);

    Ok(out)
}

/// Run the 12 io_uring attacks + 50 legit io_uring workloads and classify them.
pub fn run(rules: &Rules) -> anyhow::Result<CorpusResult> {
    let sandbox = make_sandbox()?;
    let echo_port = spawn_echo_server()?;
    let mut ring = Ring::new(16)
        .map_err(|e| anyhow::anyhow!("io_uring_setup failed ({e}); cannot run corpus"))?;

    let attacks: Vec<(Scored, Verdict)> = {
        let mut be = Backend::IoUring(&mut ring);
        execute_attacks(&mut be)?
            .into_iter()
            .map(|ev| {
                let v = classify(rules, &ev).verdict;
                (
                    Scored {
                        ev,
                        expected_malicious: true,
                    },
                    v,
                )
            })
            .collect()
    };

    let legit = run_legit(&mut ring, rules, &sandbox, echo_port)?;
    let _ = std::fs::remove_dir_all(&sandbox);
    Ok(CorpusResult { attacks, legit })
}

fn run_legit(
    ring: &mut Ring,
    rules: &Rules,
    sandbox: &Path,
    echo_port: u16,
) -> anyhow::Result<Vec<(Scored, Verdict)>> {
    let mut out = Vec::new();
    let push = |out: &mut Vec<(Scored, Verdict)>, ev: Event| {
        let v = classify(rules, &ev).verdict;
        out.push((
            Scored {
                ev,
                expected_malicious: false,
            },
            v,
        ));
    };

    for i in 0..20 {
        let path = sandbox
            .join(format!("data_{i}.bin"))
            .to_string_lossy()
            .to_string();
        let mut be = Backend::IoUring(ring);
        let ev = ops::open_read(&mut be, &format!("app-read-{i}"), &path)?;
        push(&mut out, ev);
    }
    for i in 0..10 {
        let path = sandbox
            .join(format!("out_{i}.log"))
            .to_string_lossy()
            .to_string();
        let mut be = Backend::IoUring(ring);
        let ev = ops::write_file(&mut be, &format!("app-write-{i}"), &path, b"log line\n")?;
        push(&mut out, ev);
    }
    for i in 0..5 {
        let path = sandbox
            .join(format!("data_{i}.bin"))
            .to_string_lossy()
            .to_string();
        let mut be = Backend::IoUring(ring);
        let ev = ops::splice_exfil(&mut be, &format!("app-splice-{i}"), &path)?;
        push(&mut out, ev);
    }
    for i in 0..10 {
        let mut be = Backend::IoUring(ring);
        let ev = ops::connect(
            &mut be,
            &format!("loopback-connect-{i}"),
            "127.0.0.1",
            echo_port,
        )?;
        push(&mut out, ev);
    }
    for (i, path) in [
        "/etc/passwd",
        "/etc/hostname",
        "/etc/os-release",
        "/etc/hosts",
        "/proc/self/status",
    ]
    .iter()
    .enumerate()
    {
        let mut be = Backend::IoUring(ring);
        let ev = ops::open_read(&mut be, &format!("sys-read-{i}"), path)?;
        push(&mut out, ev);
    }
    Ok(out)
}

fn make_sandbox() -> anyhow::Result<PathBuf> {
    let base = std::env::temp_dir().join(format!("iuas-corpus-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    for i in 0..20 {
        std::fs::write(base.join(format!("data_{i}.bin")), format!("payload {i}\n"))?;
    }
    Ok(base)
}

fn spawn_echo_server() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut s = stream;
            let mut buf = [0u8; 16];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"ok");
        }
    });
    let _ = TcpStream::connect(("127.0.0.1", port));
    Ok(port)
}
