package detect

import "testing"

func TestValidateRuleConditions(t *testing.T) {
	tests := []struct {
		name string
		c    RuleConditions
		ok   bool
	}{
		{
			name: "valid",
			c: RuleConditions{
				ProcessName: "curl",
				IPRange:     "10.0.0.0/8",
				PortRange:   "80, 8000-9000",
				MinInterval: 500,
				MaxInterval: 5000,
				MinSamples:  6,
				EntropyMax:  3.2,
			},
			ok: true,
		},
		{
			name: "negative interval",
			c:    RuleConditions{MinInterval: -1},
		},
		{
			name: "bad cidr",
			c:    RuleConditions{IPRange: "10.0.0.0/33"},
		},
		{
			name: "bad port token",
			c:    RuleConditions{PortRange: "80,not-a-port"},
		},
		{
			name: "empty port segment",
			c:    RuleConditions{PortRange: "80,"},
		},
		{
			name: "reversed port range",
			c:    RuleConditions{PortRange: "9000-8000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleConditions(tt.c)
			if tt.ok && err != nil {
				t.Fatalf("expected valid conditions, got %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestBeaconConditionsMetMinSamples(t *testing.T) {
	timestamps := []int64{1000, 2000, 3000, 4000, 5000, 6000}

	ok, mean, samples := BeaconConditionsMet(RuleConditions{MinSamples: 6}, timestamps)
	if !ok {
		t.Fatal("expected min_samples-only rule to match at 6 samples")
	}
	if samples != 6 {
		t.Fatalf("expected 6 samples, got %d", samples)
	}
	if mean != 1000 {
		t.Fatalf("expected 1000ms mean interval, got %.0f", mean)
	}

	ok, _, _ = BeaconConditionsMet(RuleConditions{MinSamples: 7}, timestamps)
	if ok {
		t.Fatal("expected 7-sample rule to stay pending with only 6 samples")
	}
}
