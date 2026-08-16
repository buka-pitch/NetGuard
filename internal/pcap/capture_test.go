package pcap

import (
	"strings"
	"testing"
)

func TestBuildFilter_SingleHostPort(t *testing.T) {
	f := BuildFilter([]HostPort{{Host: "1.1.1.1", Port: 80}})
	if !strings.Contains(f, "1.1.1.1") || !strings.Contains(f, "80") {
		t.Errorf("expected host+port filter, got %q", f)
	}
}

func TestBuildFilter_SingleHostOnly(t *testing.T) {
	f := BuildFilter([]HostPort{{Host: "1.1.1.1"}})
	if f != "host 1.1.1.1" {
		t.Errorf("expected 'host 1.1.1.1', got %q", f)
	}
}

func TestBuildFilter_MultipleHosts(t *testing.T) {
	f := BuildFilter([]HostPort{
		{Host: "1.1.1.1", Port: 80},
		{Host: "93.184.216.34", Port: 443},
	})
	if !strings.Contains(f, "1.1.1.1") || !strings.Contains(f, "93.184.216.34") {
		t.Errorf("expected both hosts in filter, got %q", f)
	}
	if !strings.Contains(f, "or") {
		t.Errorf("expected 'or' in multi-host filter, got %q", f)
	}
}

func TestBuildFilter_SameHostMultiplePorts(t *testing.T) {
	f := BuildFilter([]HostPort{
		{Host: "1.1.1.1", Port: 80},
		{Host: "1.1.1.1", Port: 443},
	})
	if !strings.Contains(f, "(port 80 or port 443)") {
		t.Errorf("expected combined port filter, got %q", f)
	}
}

func TestBuildFilter_Empty(t *testing.T) {
	f := BuildFilter(nil)
	if f != "ip" {
		t.Errorf("expected 'ip' for empty, got %q", f)
	}
}

func TestBuildFilter_ManyHosts(t *testing.T) {
	targets := make([]HostPort, 15)
	for i := 0; i < 15; i++ {
		targets[i] = HostPort{Host: "10.0.0.1", Port: i + 1}
	}
	_ = BuildFilter(targets)
}

func TestBuildFilter_IPv6(t *testing.T) {
	f := BuildFilter([]HostPort{{Host: "2a00:1450:400e:801::200e", Port: 443}})
	if !strings.Contains(f, "[2a00:1450:400e:801::200e]") {
		t.Errorf("expected bracketed IPv6 in port filter, got %q", f)
	}
}

func TestBuildFilter_IPv6HostOnly(t *testing.T) {
	f := BuildFilter([]HostPort{{Host: "2a00:1450:400e:801::200e"}})
	if !strings.Contains(f, "2a00:1450:400e:801::200e") {
		t.Errorf("expected IPv6 in host filter, got %q", f)
	}
	if strings.Contains(f, "[") {
		t.Errorf("expected no brackets for host-only IPv6 filter, got %q", f)
	}
}

func TestBuildFilter_MixedIPv4IPv6(t *testing.T) {
	f := BuildFilter([]HostPort{
		{Host: "1.1.1.1", Port: 80},
		{Host: "2a00:1450:400e:801::200e", Port: 443},
	})
	if !strings.Contains(f, "[2a00:1450:400e:801::200e]") {
		t.Errorf("expected bracketed IPv6 in mixed filter, got %q", f)
	}
	if !strings.Contains(f, "1.1.1.1") {
		t.Errorf("expected IPv4 host in mixed filter, got %q", f)
	}
}

func TestIsIPv6(t *testing.T) {
	if isIPv6("1.1.1.1") {
		t.Error("1.1.1.1 should not be IPv6")
	}
	if !isIPv6("::1") {
		t.Error("::1 should be IPv6")
	}
	if !isIPv6("2a00:1450:400e:801::200e") {
		t.Error("2a00:1450:400e:801::200e should be IPv6")
	}
}
