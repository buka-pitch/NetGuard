package capture

// Phase 2: eBPF capture backend.
// This will implement the same event output as Poller but via
// eBPF kprobe on tcp_connect + perf ring buffer.
//
// Requirements:
//   - Linux kernel 5.2+ with CONFIG_DEBUG_INFO_BTF=y
//   - cilium/ebpf and bpf2go tool
//   - Generate vmlinux.h: bpftool btf dump file /sys/kernel/btf/vmlinux format c
//
// Steps to enable:
//  1. go install github.com/cilium/ebpf/cmd/bpf2go@latest
//  2. cd internal/ebpf && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//  3. cd ../.. && go generate ./internal/ebpf/
//  4. Replace NewPoller with NewEBPFCapture in main.go
//
type EBPFCapture struct {
    eventChan chan<- ConnectionEvent
}

func NewEBPFCapture() *EBPFCapture {
    return &EBPFCapture{}
}

func (e *EBPFCapture) Start(events chan<- ConnectionEvent) {
    // TODO: implement eBPF loader + perf ring buffer consumer
    // See cilium/ebpf documentation:
    // https://github.com/cilium/ebpf
}
