// Package gosmtp provides a zero-dependency SMTP client for sending MIME emails
// with STARTTLS, implicit TLS/SSL, authentication, custom encodings, CC/CCI/BCC
// recipients, and file or inline attachments.
package gosmtp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Encryption defines the transport encryption protocol used for the SMTP connection.
type Encryption string

const (
	// EncryptionNone uses an unencrypted plain SMTP connection (default port 25).
	EncryptionNone Encryption = "none"
	// EncryptionSTARTTLS upgrades a plain SMTP connection using STARTTLS (default port 587).
	EncryptionSTARTTLS Encryption = "starttls"
	// EncryptionTLS uses implicit TLS (SMTPS) from the start of the connection (default port 465).
	EncryptionTLS Encryption = "tls"
	// EncryptionSSL is an alias for EncryptionTLS (default port 465).
	EncryptionSSL Encryption = "ssl"
)

// AuthType defines the SMTP authentication mechanism.
type AuthType string

const (
	// AuthAuto selects PLAIN authentication automatically when Username is set.
	AuthAuto AuthType = ""
	// AuthNone disables SMTP authentication.
	AuthNone AuthType = "none"
	// AuthPlain uses the PLAIN SASL mechanism.
	AuthPlain AuthType = "plain"
	// AuthLogin uses the LOGIN SASL mechanism.
	AuthLogin AuthType = "login"
	// AuthCRAMMD5 uses the CRAM-MD5 SASL mechanism.
	AuthCRAMMD5 AuthType = "cram-md5"
)

// Encoding defines the MIME Content-Transfer-Encoding for message bodies.
type Encoding string

const (
	// EncodingQuotedPrintable uses quoted-printable encoding (default).
	EncodingQuotedPrintable Encoding = "quoted-printable"
	// EncodingBase64 uses base64 encoding wrapped at 76 characters.
	EncodingBase64 Encoding = "base64"
	// Encoding8Bit uses 8bit transfer encoding without re-encoding UTF-8 bytes.
	Encoding8Bit Encoding = "8bit"
	// Encoding7Bit uses 7bit ASCII transfer encoding.
	Encoding7Bit Encoding = "7bit"
)

// ContentType defines the MIME media type for a single-part message body.
type ContentType string

const (
	// ContentTypeTextPlain sets the body content type to text/plain (default).
	ContentTypeTextPlain ContentType = "text/plain"
	// ContentTypeTextHTML sets the body content type to text/html.
	ContentTypeTextHTML ContentType = "text/html"
)

// Config holds the SMTP client configuration used to initialize a Client.
type Config struct {
	Host               string
	Port               int
	Username           string
	Password           string
	From               string
	Encryption         Encryption
	AuthType           AuthType
	Encoding           Encoding
	Charset            string
	TLSConfig          *tls.Config
	InsecureSkipVerify bool
	Timeout            time.Duration
	LocalName          string
}

// Validate checks that the configuration is valid without modifying the receiver.
func (c Config) Validate() error {
	copyCfg := c
	return copyCfg.normalizeAndValidate()
}

// normalizeAndValidate applies defaults to empty fields and validates all settings.
func (c *Config) normalizeAndValidate() error {
	c.Host = strings.TrimSpace(c.Host)
	if c.Host == "" {
		return errors.New("gosmtp: Host is required")
	}

	c.Encryption = Encryption(strings.ToLower(strings.TrimSpace(string(c.Encryption))))
	if c.Encryption == "" {
		switch c.Port {
		case 465:
			c.Encryption = EncryptionTLS
		case 25:
			c.Encryption = EncryptionNone
		default:
			c.Encryption = EncryptionSTARTTLS
		}
	}

	switch c.Encryption {
	case EncryptionNone, EncryptionSTARTTLS, EncryptionTLS, EncryptionSSL:
	default:
		return fmt.Errorf("gosmtp: invalid Encryption %q", c.Encryption)
	}

	if c.Port == 0 {
		switch c.Encryption {
		case EncryptionTLS, EncryptionSSL:
			c.Port = 465
		case EncryptionNone:
			c.Port = 25
		default:
			c.Port = 587
		}
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("gosmtp: invalid Port %d (must be between 1 and 65535)", c.Port)
	}

	c.AuthType = AuthType(strings.ToLower(strings.TrimSpace(string(c.AuthType))))
	switch c.AuthType {
	case AuthAuto, AuthNone, AuthPlain, AuthLogin, AuthCRAMMD5:
	default:
		return fmt.Errorf("gosmtp: invalid AuthType %q", c.AuthType)
	}

	c.Encoding = Encoding(strings.ToLower(strings.TrimSpace(string(c.Encoding))))
	if c.Encoding == "" {
		c.Encoding = EncodingQuotedPrintable
	}
	switch c.Encoding {
	case EncodingQuotedPrintable, EncodingBase64, Encoding8Bit, Encoding7Bit:
	default:
		return fmt.Errorf("gosmtp: invalid Encoding %q", c.Encoding)
	}

	c.Charset = strings.TrimSpace(c.Charset)
	if c.Charset == "" {
		c.Charset = "UTF-8"
	}

	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}

	c.LocalName = strings.TrimSpace(c.LocalName)
	if c.LocalName == "" {
		c.LocalName = "localhost"
	}
	if containsCRLF(c.LocalName) {
		return errors.New("gosmtp: LocalName must not contain CR or LF")
	}

	c.From = strings.TrimSpace(c.From)
	if c.From != "" {
		if _, err := extractEmail(c.From); err != nil {
			return fmt.Errorf("gosmtp: invalid Config.From address: %w", err)
		}
	}

	return nil
}

// buildTLSConfig constructs the effective *tls.Config for the client.
func (c Config) buildTLSConfig() *tls.Config {
	var tlsCfg *tls.Config
	if c.TLSConfig != nil {
		tlsCfg = c.TLSConfig.Clone()
	} else {
		tlsCfg = &tls.Config{}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = c.Host
	}
	if c.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	if tlsCfg.MinVersion == 0 {
		tlsCfg.MinVersion = tls.VersionTLS12
	}
	return tlsCfg
}

