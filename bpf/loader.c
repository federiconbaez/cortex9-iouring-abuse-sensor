// SPDX-License-Identifier: Apache-2.0
//
// libbpf loader + in-CI measurement for the anti-Curing sensor.
//
// Steps:
//   1. open sensor.bpf.o, load + attach both kprobes (hard failure if refused),
//   2. fork a child that execs `iouring-abuse-sensor attack-once --ready-fd R
//      --target <file>`, which synchronises on a barrier,
//   3. once the child signals it is past startup, install the PID filter, ZERO
//      both counters, and release the child (SIGUSR1) so the measured window
//      contains only the io_uring open+read,
//   4. assert the sensor saw the access (counter[0] >= 1) AND the read-syscall
//      hook did not (counter[1] == 0).
//
// Any failure exits non-zero. No silent skip: a kernel that cannot load the
// program fails the job loudly.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
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

static int zero_counter(unsigned int idx)
{
    unsigned int key = idx;
    long long zero = 0;
    return bpf_map_update_elem(counters_fd, &key, &zero, BPF_ANY);
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
    if (libbpf_get_error(bpf_program__attach(p_perm))) {
        fprintf(stderr,
                "ENFORCE_FAIL: attach kprobe security_file_permission (%s)\n",
                strerror(errno));
        return 6;
    }
    if (libbpf_get_error(bpf_program__attach(p_read))) {
        fprintf(stderr, "ENFORCE_FAIL: attach kprobe __x64_sys_read (%s)\n",
                strerror(errno));
        return 7;
    }

    // Barrier pipe: child writes one byte when past startup.
    int pfd[2];
    if (pipe(pfd) != 0) {
        perror("pipe");
        return 8;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 8;
    }
    if (child == 0) {
        close(pfd[0]); // child keeps the write end
        char fdbuf[16];
        snprintf(fdbuf, sizeof(fdbuf), "%d", pfd[1]);
        execl(sensor_bin, sensor_bin, "attack-once", "--ready-fd", fdbuf,
              "--target", target_file, (char *)NULL);
        perror("execl");
        _exit(127);
    }
    close(pfd[1]); // parent keeps the read end

    // Attribute events to the child before it runs the measured op.
    unsigned int key = 0;
    unsigned int pid = (unsigned int)child;
    if (bpf_map_update_elem(target_fd, &key, &pid, BPF_ANY) != 0) {
        fprintf(stderr, "ENFORCE_FAIL: set target pid\n");
        return 9;
    }

    // Wait for the child's "startup done" byte, then zero the counters so the
    // measured window is exactly the upcoming io_uring read.
    char b = 0;
    if (read(pfd[0], &b, 1) != 1) {
        fprintf(stderr, "ENFORCE_FAIL: barrier ready read\n");
        return 10;
    }
    if (zero_counter(0) != 0 || zero_counter(1) != 0) {
        fprintf(stderr, "ENFORCE_FAIL: zero counters\n");
        return 11;
    }
    // Release the child.
    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        return 12;
    }

    int status = 0;
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "ENFORCE_FAIL: trigger child failed (status %d)\n",
                status);
        return 13;
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
        return 14;
    }
    if (read_hits != 0) {
        fprintf(stderr,
                "ENFORCE_FAIL: read-syscall hook unexpectedly fired %lld times "
                "in the measured window\n",
                read_hits);
        return 15;
    }
    printf("ENFORCE_OK: sensor caught the io_uring read; read-syscall hook was "
           "blind (0 hits)\n");
    return 0;
}
