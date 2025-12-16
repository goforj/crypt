package crypt

import (
	"errors"
	"os"
	"strings"
)

// GenerateKeyToEnv mimics Laravel's key:generate.
// It generates a new APP_KEY and writes it to the provided .env path.
// Other keys are preserved; APP_KEY is replaced/added.
// @group Key management
// @behavior mutates-filesystem
//
// Example: generate and write APP_KEY to a temp .env
//
//	tmp := filepath.Join(os.TempDir(), ".env")
//	key, err := crypt.GenerateKeyToEnv(tmp)
//	godump.Dump(err, key)
//
//	// #error <nil>
//	// #string "base64:..."
func GenerateKeyToEnv(envPath string) (string, error) {
	key, err := GenerateAppKey()
	if err != nil {
		return "", err
	}
	if err := writeEnvKeys(envPath, key, ""); err != nil {
		return "", err
	}
	return key, nil
}

// RotateKeyInEnv mimics Laravel's key:rotate.
// It moves the current APP_KEY into APP_PREVIOUS_KEYS (prepended) and writes a new APP_KEY.
// @group Key management
// @behavior mutates-filesystem
//
// Example: rotate APP_KEY and prepend old key to APP_PREVIOUS_KEYS
//
//	tmp := filepath.Join(os.TempDir(), ".env")
//	oldKey, _ := crypt.GenerateAppKey()
//	_ = os.WriteFile(tmp, []byte("APP_KEY="+oldKey+"\n"), 0o644)
//	newKey, err := crypt.RotateKeyInEnv(tmp)
//	godump.Dump(err == nil, newKey != "")
//
//	// #bool true
//	// #bool true
func RotateKeyInEnv(envPath string) (string, error) {
	current, previous, err := readEnvKeys(envPath)
	if err != nil {
		return "", err
	}
	if current == "" {
		return "", errors.New("APP_KEY not found; cannot rotate")
	}

	newKey, err := GenerateAppKey()
	if err != nil {
		return "", err
	}

	updatedPrev := prependUnique(current, previous)
	if err := writeEnvKeys(envPath, newKey, updatedPrev); err != nil {
		return "", err
	}
	return newKey, nil
}

func prependUnique(current string, previous string) string {
	if previous == "" {
		return current
	}
	parts := splitAndTrim(previous)
	if len(parts) == 0 || parts[0] != current {
		parts = append([]string{current}, parts...)
	}
	return strings.Join(parts, ",")
}

func splitAndTrim(val string) []string {
	if val == "" {
		return nil
	}
	segs := strings.Split(val, ",")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func readEnvKeys(envPath string) (current string, previous string, err error) {
	lines, err := readEnvLines(envPath)
	if err != nil {
		return "", "", err
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "APP_KEY=") {
			current = strings.TrimPrefix(line, "APP_KEY=")
			continue
		}
		if strings.HasPrefix(line, "APP_PREVIOUS_KEYS=") {
			previous = strings.TrimPrefix(line, "APP_PREVIOUS_KEYS=")
			continue
		}
	}
	return current, previous, nil
}

func writeEnvKeys(envPath, newKey, previous string) error {
	lines, err := readEnvLines(envPath)
	if err != nil {
		return err
	}

	lines = upsertEnv(lines, "APP_KEY", newKey)
	if previous != "" {
		lines = upsertEnv(lines, "APP_PREVIOUS_KEYS", previous)
	} else {
		lines = removeEnv(lines, "APP_PREVIOUS_KEYS")
	}

	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(envPath, []byte(content), 0o644)
}

func readEnvLines(envPath string) ([]string, error) {
	data, err := os.ReadFile(envPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines, nil
}

func upsertEnv(lines []string, key, value string) []string {
	prefix := key + "="
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			lines[i] = prefix + value
			replaced = true
		}
	}
	if !replaced {
		lines = append(lines, prefix+value)
	}
	return lines
}

func removeEnv(lines []string, key string) []string {
	prefix := key + "="
	out := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			continue
		}
		out = append(out, line)
	}
	return out
}
