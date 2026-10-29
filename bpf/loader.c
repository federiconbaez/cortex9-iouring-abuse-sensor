// SPDX-License-Identifier: Apache-2.0
//
// libbpf loader + in-CI measurement for the anti-Curing sensor.
//
// Steps:
//   1. open sensor.bpf.o, set the target PID to a child we will fork,
//   2. load + attach both kprobes (hard failure if the kernel refuses),
//   3. in the child, exec `iouring-abuse-sensor attack-once --target <file>`
//      which performs an io_uring open+read of a readable file,
//   4. read the counters and assert the sensor saw the access (counter[0] >= 1)
//      while the read-syscall hook did not (counter[1] == 0).
//
// Any failure (open/load/attach/trigger/assert) exits non-zero. There is no
// silent skip: a kernel that cannot load the program fails the job loudly.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int counters_fd = -1;

static long long get_counter(unsigned int idx)
{
    unsigned int key = idx;
    long long val = 0;
    if (bpf_map_lookup_elem(counters_fd, &key, &val) != 0)
        return -1;
    return val;
}

int main(int argc, char **argv)
{
    const char *obj_path = argc > 1 ? argv[1] : "sensor.bpf.o";
    const char *sensor_bin = argc > 2 ? argv[2] : "./iouring-abuse-sensor";
    const char *target_file = argc > 3 ? argv[3] : "/etc/os-release";

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "ENFORCE_FAIL: open %s failed\n", obj_path);
        return 2;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ENFORCE_FAIL: BPF_PROG_LOAD/verifier refused (%s)\n",
                strerror(errno));
        return 3;
    }

    counters_fd = bpf_object__find_map_fd_by_name(obj, "counters");
    int target_fd = bpf_object__find_map_fd_by_name(obj, "target_pid");
    if (counters_fd < 0 || target_fd < 0) {
        fprintf(stderr, "ENFORCE_FAIL: maps not found\n");
        return 4;
    }

    struct bpf_program *p_perm =
        bpf_object__find_program_by_name(obj, "on_file_permission");
    struct bpf_program *p_read =
        bpf_object__find_program_by_name(obj, "on_sys_read");
    if (!p_perm || !p_read) {
        fprintf(stderr, "ENFORCE_FAIL: programs not found\n");
        return 5;
    }

    struct bpf_link *l_perm = bpf_program__attach(p_perm);
    if (libbpf_get_error(l_perm)) {
        fprintf(stderr,
                "ENFORCE_FAIL: attach kprobe security_file_permission (%s)\n",
                strerror(errno));
        return 6;
    }
    struct bpf_link *l_read = bpf_program__attach(p_read);
    if (libbpf_get_error(l_read)) {
        fprintf(stderr, "ENFORCE_FAIL: attach kprobe __x64_sys_read (%s)\n",
                strerror(errno));
        return 7;
    }

    // Fork the trigger. Set target PID to the child *before* it runs.
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 8;
    }
    if (child == 0) {
        // Child: become the attack. The parent already filtered on our PID.
        // Small delay so the parent can install the PID filter.
        usleep(100000);
        execl(sensor_bin, sensor_bin, "attack-once", "--target", target_file,
              (char *)NULL);
        perror("execl");
        _exit(127);
    }

    unsigned int key = 0;
    unsigned int pid = (unsigned int)child;
    if (bpf_map_update_elem(target_fd, &key, &pid, BPF_ANY) != 0) {
        fprintf(stderr, "ENFORCE_FAIL: set target pid\n");
        return 9;
    }

    int status = 0;
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "ENFORCE_FAIL: trigger child failed (status %d)\n",
                status);
        return 10;
    }

    long long sensor_hits = get_counter(0);
    long long read_hits = get_counter(1);
    printf("sensor(security_file_permission) hits for pid %u: %lld\n", pid,
           sensor_hits);
    printf("read-syscall-hook hits for pid %u: %lld\n", pid, read_hits);

    if (sensor_hits < 1) {
        fprintf(stderr,
                "ENFORCE_FAIL: sensor did not observe the io_uring file access "
                "(got %lld)\n",
                sensor_hits);
        return 11;
    }
    printf("ENFORCE_OK: sensor caught io_uring access the read-syscall hook saw "
           "%lld times\n",
           read_hits);
    return 0;
}
