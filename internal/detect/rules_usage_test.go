package detect

import (
	"net"
	"os"
	"testing"
	"time"

	"netmon/internal/capture"
	"netmon/internal/store"
)

func TestCustomRuleMatcherSetsRuleID(t *testing.T) {
	f, err := os.CreateTemp("", "netmon-rule-id-*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	st, err := store.New(f.Name(), 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	rs := NewRuleStore(st.DB())
	id, err := rs.Add("curl outbound", SevHigh, RuleConditions{ProcessName: "curl"})
	if err != nil {
		t.Fatal(err)
	}

	matcher := NewCustomRuleMatcher(rs)
	ev := capture.ConnectionEvent{
		Type: capture.EventNew,
		Connection: capture.Connection{
			PID:        4242,
			Comm:       "curl",
			RemoteAddr: net.ParseIP("93.184.216.34"),
			RemotePort: 443,
			Protocol:   "tcp",
			State:      "SYN_SENT",
			CreatedAt:  time.Now().UnixMilli(),
		},
	}

	alert := matcher.Eval(ev, NewEngine())
	if alert == nil {
		t.Fatal("expected custom rule alert")
	}
	if alert.RuleID != id {
		t.Fatalf("expected rule id %d, got %d", id, alert.RuleID)
	}
}
