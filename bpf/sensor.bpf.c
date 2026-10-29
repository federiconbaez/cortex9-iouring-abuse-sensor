// SPDX-License-Identifier: Apache-2.0
//
// Minimal anti-Curing kernel sensor. Two kprobes:
//   * security_file_permission — the VFS/LSM choke point every file read/write
//     passes through, whether issued by a classic syscall OR by io_uring.
//   * __x64_sys_read — the classic entry a syscall-hooking monitor watches.
//
// Both increment a per-index counter, but only for the target PID the loader
// installs, so the measurement is attributable to the triggered attack and not
// to unrelated system activity. An io_uring read therefore bumps counter[0]
// (the sensor sees it) but leaves counter[1] at zero (a read-syscall hook is
// blind) — the Curing-class gap, demonstrated with a real load.
//
// This program is loaded only in CI / a VM with CAP_BPF. On a box with
// unprivileged_bpf_disabled=2 it cannot and must not pretend to load.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL"; // kprobes require a GPL-compatible
// program license at load time; the *project* is Apache-2.0 (see repo LICENSE).

// index 0: security_file_permission, index 1: __x64_sys_read
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

// single-slot config: the PID (tgid) to attribute events to.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

static __always_inline int for_target(void)
{
    __u32 k = 0;
    __u32 *want = bpf_map_lookup_elem(&target_pid, &k);
    if (!want)
        return 0;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    return tgid == *want;
}

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("kprobe/security_file_permission")
int BPF_KPROBE(on_file_permission)
{
    if (for_target())
        bump(0);
    return 0;
}

SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(on_sys_read)
{
    if (for_target())
        bump(1);
    return 0;
}
