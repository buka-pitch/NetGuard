// SPDX-License-Identifier: GPL-2.0
// Phase 2: eBPF-based TCP connection monitor.
// Requires kernel with CONFIG_DEBUG_INFO_BTF=y (kernel 5.2+).
// Generate vmlinux.h: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct conn_event {
    __u32 pid;
    __u32 uid;
    __u8  comm[16];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 256);
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct conn_event event = {};
    struct inet_sock *inet = (struct inet_sock *)sk;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    event.saddr = BPF_CORE_READ(inet, inet_saddr);
    event.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event.sport = BPF_CORE_READ(inet, inet_sport);
    event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event.timestamp_ns = bpf_ktime_get_ns();

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
