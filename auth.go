package gosmtp

import (
	"errors"
	"fmt"
	"net/smtp"
)

// buildAuth returns the smtp.Auth implementation matching cfg, or nil when authentication is disabled.
func buildAuth(cfg Config) (smtp.Auth, error) {
	if cfg.AuthType == AuthNone {
		return nil, nil
	}
	if cfg.Username == "" && cfg.Password == "" {
		if cfg.AuthType != AuthAuto {
			return nil, fmt.Errorf("gosmtp: AuthType %q requires Username or Password", cfg.AuthType)
		}
		return nil, nil
	}

	authType := cfg.AuthType
	if authType == AuthAuto {
		authType = AuthPlain
	}

	switch authType {
	case AuthPlain:
		return smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host), nil
	case AuthCRAMMD5:
		return smtp.CRAMMD5Auth(cfg.Username, cfg.Password), nil
	case AuthLogin:
		return &loginAuth{
			username: cfg.Username,
			password: cfg.Password,
			host:     cfg.Host,
		}, nil
	default:
		return nil, fmt.Errorf("gosmtp: unsupported AuthType %q", authType)
	}
}

// loginAuth implements the SMTP AUTH LOGIN mechanism.
type loginAuth struct {
	username string
	password string
	host     string
	step     int
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server == nil {
		return "", nil, errors.New("gosmtp: nil server info")
	}
	if !server.TLS && !isLocalhost(server.Name) {
		return "", nil, errors.New("gosmtp: unencrypted connection for AUTH LOGIN")
	}
	if server.Name != a.host {
		return "", nil, fmt.Errorf("gosmtp: wrong host name %q (expected %q)", server.Name, a.host)
	}
	a.step = 0
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	prompt := string(fromServer)
	switch a.step {
	case 0:
		a.step++
		if containsFold(prompt, "password") {
			return []byte(a.password), nil
		}
		return []byte(a.username), nil
	case 1:
		a.step++
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("gosmtp: unexpected AUTH LOGIN server challenge %q", prompt)
	}
}

func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}

func containsFold(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c1 := s[i+j]
			c2 := substr[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 'a' - 'A'
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 'a' - 'A'
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

