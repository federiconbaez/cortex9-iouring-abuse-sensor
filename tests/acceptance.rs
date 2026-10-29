//! End-to-end acceptance tests. These exercise the real io_uring engine; if
//! io_uring is unavailable they FAIL (never skip), per the build rules.

use iouring_abuse_sensor::{blindness, corpus, policy, uring};

#[test]
fn io_uring_must_be_available() {
    assert!(
        uring::available(),
        "io_uring_setup(2) unavailable; this suite requires io_uring (no silent skip)"
    );
}

#[test]
fn corpus_meets_acceptance_thresholds() {
    let rules = policy::Rules::default();
    let r = corpus::run(&rules).expect("corpus run");
    assert_eq!(r.attacks_total(), 12, "expected 12 attacks");
    assert_eq!(r.legit_total(), 50, "expected 50 legit workloads");
    assert!(
        r.attacks_detected() >= 11,
        "detection {}/12 below threshold 11",
        r.attacks_detected()
    );
    assert!(
        r.fpr() <= 0.02,
        "FPR {:.3} above threshold 0.02 ({} FPs)",
        r.fpr(),
        r.false_positives()
    );
}

#[test]
fn syscall_monitor_is_blind_to_io_uring() {
    let b = blindness::measure().expect("blindness run");
    assert_eq!(b.total, 12);
    assert_eq!(
        b.classic_intercepted, 12,
        "a syscall monitor must catch all classic attacks"
    );
    assert_eq!(
        b.uring_intercepted, 0,
        "a syscall monitor must be blind to the io_uring variants (got {})",
        b.uring_intercepted
    );
}
