package config

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${VAR} with the environment value, erroring on an unset var.
func expandEnv(s string) (string, error) {
	var missing string
	out := envRef.ReplaceAllStringFunc(s, func(m string) string {
		name := envRef.FindStringSubmatch(m)[1]
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = name
		}
		return v
	})
	if missing != "" {
		return "", fmt.Errorf("environment variable %q is not set", missing)
	}
	return out, nil
}

// resolveSecrets fills each identity's Password from password / password_file /
// password_command (in that precedence), with ${ENV} expansion on inline values.
// Errors never include the secret value.
func (c *Config) resolveSecrets() error {
	for i := range c.Identities {
		id := &c.Identities[i]
		switch {
		case id.Password != "":
			pw, err := expandEnv(id.Password)
			if err != nil {
				return fmt.Errorf("identity %q password: %w", id.Name, err)
			}
			id.Password = pw
		case id.PasswordFile != "":
			b, err := os.ReadFile(id.PasswordFile)
			if err != nil {
				return fmt.Errorf("identity %q password_file: %w", id.Name, err)
			}
			id.Password = strings.TrimRight(string(b), "\r\n")
		case id.PasswordCommand != "":
			// password_command is an operator-authored shell command (like isync's
			// passwordeval or a git credential helper) so it can run keychain/pass/vault
			// pipelines. The config author is the operator, so `sh -c` is the intended
			// mechanism here, not an injection surface. Do NOT "fix" this to exec without
			// a shell; that would break real password_command values.
			out, err := exec.Command("sh", "-c", id.PasswordCommand).Output() //nolint:gosec // operator-authored command by design
			if err != nil {
				return fmt.Errorf("identity %q password_command failed", id.Name)
			}
			id.Password = strings.TrimRight(string(out), "\r\n")
		}
	}
	return nil
}
