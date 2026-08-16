package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// writeSetupFile writes a token to a 0600 file, creating parent directories
// as needed. Used for both setup and password-reset tokens.
func writeSetupFile(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	return os.WriteFile(path, []byte(token), 0600)
}

// readSetupFile reads the setup token from disk.
func readSetupFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("setup token not found (already consumed?)")
		}
		return "", err
	}
	return string(b), nil
}

func deleteFile(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
