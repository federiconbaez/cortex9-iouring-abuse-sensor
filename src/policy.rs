//! Detection policy. Classifies an [`Event`] as malicious or benign using a set
//! of rules that key on the *effect* of the operation (which file, which remote
//! endpoint), independent of whether it arrived via io_uring or a classic
//! syscall. That origin-independence is the whole point: a sensor sitting at the
//! LSM / VFS layer sees the effect regardless of issue path.

use crate::event::{Event, OpKind};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rules {
    /// Reading any of these path prefixes is credential/secret theft.
    pub sensitive_read_prefixes: Vec<String>,
    /// Writing/renaming/unlinking under these prefixes is persistence/tamper.
    pub persistence_write_prefixes: Vec<String>,
    /// Connects whose destination IP is NOT inside one of these CIDRs are
    /// treated as egress to an external endpoint (possible C2).
    pub allowed_connect_cidrs: Vec<String>,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            sensitive_read_prefixes: [
                "/etc/shadow",
                "/etc/gshadow",
                "/etc/sudoers",
                "/etc/ssl/private",
                "/root/.ssh/",
                "/proc/1/",
                "/proc/kcore",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            persistence_write_prefixes: [
                "/etc/cron.d/",
                "/etc/crontab",
                "/etc/systemd/system/",
                "/etc/ld.so.preload",
                "/root/.ssh/authorized_keys",
                "/etc/sudoers.d/",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            allowed_connect_cidrs: [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

impl Rules {
    pub fn from_json(s: &str) -> anyhow::Result<Rules> {
        Ok(serde_json::from_str(s)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Malicious,
    Benign,
}

#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub reason: String,
}

pub fn classify(rules: &Rules, ev: &Event) -> Decision {
    match ev.op {
        OpKind::Open | OpKind::Read | OpKind::Splice => {
            if let Some(p) = &ev.path {
                for pre in &rules.sensitive_read_prefixes {
                    if p.starts_with(pre) {
                        return Decision {
                            verdict: Verdict::Malicious,
                            reason: format!("sensitive read: {p} matches {pre}"),
                        };
                    }
                }
            }
        }
        OpKind::Write | OpKind::Rename | OpKind::Unlink => {
            if let Some(p) = &ev.path {
                for pre in &rules.persistence_write_prefixes {
                    if p.starts_with(pre) {
                        return Decision {
                            verdict: Verdict::Malicious,
                            reason: format!("persistence write: {p} matches {pre}"),
                        };
                    }
                }
            }
        }
        OpKind::Connect => {
            if let Some(r) = &ev.remote {
                if let Some(ip) = r.rsplit_once(':').map(|(a, _)| a) {
                    if let Some(v) = ipv4(ip) {
                        let allowed = rules
                            .allowed_connect_cidrs
                            .iter()
                            .any(|c| cidr_contains(c, v));
                        if !allowed {
                            return Decision {
                                verdict: Verdict::Malicious,
                                reason: format!("egress to external endpoint {r}"),
                            };
                        }
                    }
                }
            }
        }
    }
    Decision {
        verdict: Verdict::Benign,
        reason: "no rule matched".to_string(),
    }
}

fn ipv4(s: &str) -> Option<u32> {
    let mut o = [0u8; 4];
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for (i, p) in parts.iter().enumerate() {
        o[i] = p.parse().ok()?;
    }
    Some(u32::from_be_bytes(o))
}

fn cidr_contains(cidr: &str, ip: u32) -> bool {
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => (n, b),
        None => (cidr, "32"),
    };
    let net = match ipv4(net) {
        Some(v) => v,
        None => return false,
    };
    let bits: u32 = bits.parse().unwrap_or(32);
    if bits == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - bits);
    (net & mask) == (ip & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, OpKind, Origin};

    fn ev(op: OpKind, path: Option<&str>, remote: Option<&str>) -> Event {
        Event {
            origin: Origin::IoUring,
            op,
            path: path.map(|s| s.to_string()),
            remote: remote.map(|s| s.to_string()),
            res: 0,
            label: "t".into(),
        }
    }

    #[test]
    fn flags_sensitive_read() {
        let r = Rules::default();
        assert_eq!(
            classify(&r, &ev(OpKind::Open, Some("/etc/shadow"), None)).verdict,
            Verdict::Malicious
        );
        assert_eq!(
            classify(&r, &ev(OpKind::Splice, Some("/etc/shadow"), None)).verdict,
            Verdict::Malicious
        );
    }

    #[test]
    fn allows_benign_read() {
        let r = Rules::default();
        for p in ["/etc/passwd", "/etc/hostname", "/proc/self/status"] {
            assert_eq!(
                classify(&r, &ev(OpKind::Open, Some(p), None)).verdict,
                Verdict::Benign,
                "{p} should be benign"
            );
        }
    }

    #[test]
    fn flags_persistence_write_not_tmp() {
        let r = Rules::default();
        assert_eq!(
            classify(&r, &ev(OpKind::Write, Some("/etc/cron.d/x"), None)).verdict,
            Verdict::Malicious
        );
        assert_eq!(
            classify(&r, &ev(OpKind::Write, Some("/tmp/x.log"), None)).verdict,
            Verdict::Benign
        );
    }

    #[test]
    fn flags_external_connect_only() {
        let r = Rules::default();
        assert_eq!(
            classify(&r, &ev(OpKind::Connect, None, Some("192.0.2.1:443"))).verdict,
            Verdict::Malicious
        );
        assert_eq!(
            classify(&r, &ev(OpKind::Connect, None, Some("127.0.0.1:8080"))).verdict,
            Verdict::Benign
        );
        assert_eq!(
            classify(&r, &ev(OpKind::Connect, None, Some("10.1.2.3:80"))).verdict,
            Verdict::Benign
        );
    }

    #[test]
    fn cidr_math() {
        assert!(cidr_contains("127.0.0.0/8", ipv4("127.5.5.5").unwrap()));
        assert!(!cidr_contains("127.0.0.0/8", ipv4("128.0.0.1").unwrap()));
        assert!(cidr_contains(
            "172.16.0.0/12",
            ipv4("172.31.255.1").unwrap()
        ));
        assert!(!cidr_contains("172.16.0.0/12", ipv4("172.32.0.1").unwrap()));
    }

    #[test]
    fn rules_json_roundtrip() {
        let r = Rules::default();
        let j = serde_json::to_string(&r).unwrap();
        let back = Rules::from_json(&j).unwrap();
        assert_eq!(back.sensitive_read_prefixes, r.sensitive_read_prefixes);
    }
}
