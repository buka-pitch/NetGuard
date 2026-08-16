package suricata

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ListRules() ([]RuleFile, error) {
	rulePath := defaultRulePath()
	entries, err := os.ReadDir(rulePath)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %s: %w", rulePath, err)
	}

	cfg, err := ReadConfig()
	if err != nil {
		return nil, err
	}
	enabledMap := make(map[string]bool)
	for _, rf := range cfg.RuleFiles {
		enabledMap[rf] = true
	}

	var rules []RuleFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		count := countRules(filepath.Join(rulePath, e.Name()))
		rules = append(rules, RuleFile{
			Name:    e.Name(),
			Path:    filepath.Join(rulePath, e.Name()),
			Enabled: enabledMap[e.Name()],
			Count:   count,
		})
	}

	return rules, nil
}

func ToggleRule(name string, enable bool) error {
	cfg, err := ReadConfig()
	if err != nil {
		return err
	}

	if enable {
		found := false
		for _, rf := range cfg.RuleFiles {
			if rf == name {
				found = true
				break
			}
		}
		if !found {
			cfg.RuleFiles = append(cfg.RuleFiles, name)
		}
	} else {
		var kept []string
		for _, rf := range cfg.RuleFiles {
			if rf != name {
				kept = append(kept, rf)
			}
		}
		cfg.RuleFiles = kept
	}

	return WriteConfig(cfg)
}

func UploadRule(name string, content []byte) error {
	rulePath := defaultRulePath()
	dst := filepath.Join(rulePath, name)

	if err := os.WriteFile(dst, content, 0644); err != nil {
		return fmt.Errorf("write rule file: %w", err)
	}

	return ToggleRule(name, true)
}

func countRules(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "alert ") || strings.HasPrefix(line, "drop ") ||
			strings.HasPrefix(line, "reject ") || strings.HasPrefix(line, "pass ") {
			count++
		}
	}
	return count
}
