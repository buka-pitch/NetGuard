# Netmon — Implementation Plan (Historical)

This project started with an eBPF-based vision (see git history), but pivoted to `/proc/net` polling because the target kernel (7.0.10-1-aegis-offensive) lacks CONFIG_DEBUG_INFO_BTF required for CO-RE eBPF programs.

See [PLAN.md](PLAN.md) for the current architecture and [ARCHITECTURE.md](ARCHITECTURE.md) for the Suricata integration design.
