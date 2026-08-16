package suricata

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func ReadConfig() (*ConfigForm, error) {
	return ReadConfigAt(defaultConfigPath())
}

func ReadConfigAt(path string) (*ConfigForm, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultConfig(), nil
		}
		return nil, err
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	cfg := defaultConfig()
	if raw == nil {
		return cfg, nil
	}

	if vars, ok := raw["vars"].(map[string]interface{}); ok {
		if ag, ok := vars["address-groups"].(map[string]interface{}); ok {
			if hn, ok := ag["HOME_NET"].(string); ok {
				cfg.HomeNet = splitNetList(hn)
			} else if hnList, ok := ag["HOME_NET"].([]interface{}); ok {
				for _, v := range hnList {
					cfg.HomeNet = append(cfg.HomeNet, fmt.Sprint(v))
				}
			}
		}
	}

	if afpkt, ok := raw["af-packet"].([]interface{}); ok {
		ifaces := make([]string, 0, len(afpkt))
		for _, entry := range afpkt {
			if m, ok := entry.(map[string]interface{}); ok {
				if iface, ok := m["interface"].(string); ok && iface != "" && iface != "default" {
					ifaces = append(ifaces, iface)
				}
			}
		}
		if len(ifaces) > 0 {
			cfg.Interface = strings.Join(ifaces, ", ")
		}
	}

	if rp, ok := raw["default-rule-path"].(string); ok {
		cfg.RulePath = rp
	}

	if rfs, ok := raw["rule-files"].([]interface{}); ok {
		for _, rf := range rfs {
			cfg.RuleFiles = append(cfg.RuleFiles, fmt.Sprint(rf))
		}
	}

	if eve, ok := raw["outputs"].(map[string]interface{}); ok {
		if ee, ok := eve["eve-log"].(map[string]interface{}); ok {
			if ci, ok := ee["community-id"].(bool); ok {
				cfg.CommunityID = ci
			}
		}
	}

	return cfg, nil
}

func WriteConfig(cfg *ConfigForm) error {
	return WriteConfigAt(defaultConfigPath(), cfg)
}

func WriteConfigAt(path string, cfg *ConfigForm) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			data = []byte("")
		} else {
			return err
		}
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if raw == nil {
		raw = make(map[string]interface{})
	}

	vars := ensureMap(raw, "vars")
	ag := ensureMap(vars, "address-groups")
	if len(cfg.HomeNet) == 1 {
		ag["HOME_NET"] = cfg.HomeNet[0]
	} else {
		ag["HOME_NET"] = cfg.HomeNet
	}

	ifaces := strings.Split(cfg.Interface, ",")
	afpkt := make([]interface{}, 0, len(ifaces))
	for _, iface := range ifaces {
		iface = strings.TrimSpace(iface)
		if iface != "" {
			afpkt = append(afpkt, map[string]interface{}{"interface": iface})
		}
	}
	if len(afpkt) > 0 {
		raw["af-packet"] = afpkt
	}

	raw["default-rule-path"] = cfg.RulePath

	if len(cfg.RuleFiles) > 0 {
		rfs := make([]interface{}, len(cfg.RuleFiles))
		for i, rf := range cfg.RuleFiles {
			rfs[i] = rf
		}
		raw["rule-files"] = rfs
	}

	if eve, ok := raw["outputs"].(map[string]interface{}); ok {
		if ee, ok := eve["eve-log"].(map[string]interface{}); ok {
			ee["community-id"] = cfg.CommunityID
		}
	}

	out, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}

	if err := os.WriteFile(path, out, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

func ensureMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	v := make(map[string]interface{})
	m[key] = v
	return v
}

func defaultConfig() *ConfigForm {
	return &ConfigForm{
		HomeNet:     []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"},
		Interface:   GetDefaultInterface(),
		RulePath:    defaultRulePath(),
		RuleFiles:   []string{"suricata.rules"},
		CommunityID: true,
	}
}

func splitNetList(s string) []string {
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
