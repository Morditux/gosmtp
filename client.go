package gosmtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Client is an SMTP email client configured with a Config struct.
type Client struct {
	config Config
}

// New validates cfg and returns a new SMTP Client.
func New(cfg Config) (*Client, error) {
	if err := cfg.normalizeAndValidate(); err != nil {
		return nil, err
	}
	if cfg.TLSConfig != nil {
		cfg.TLSConfig = cfg.TLSConfig.Clone()
	}
	return &Client{config: cfg}, nil
}

// NewClient is an alias for New.
func NewClient(cfg Config) (*Client, error) {
	return New(cfg)
}

// Config returns a copy of the normalized Client configuration.
func (c *Client) Config() Config {
	cfg := c.config
	if cfg.TLSConfig != nil {
		cfg.TLSConfig = cfg.TLSConfig.Clone()
	}
	return cfg
}

// Send transmits msg using the client's SMTP configuration.
func (c *Client) Send(msg *Message) error {
	return c.SendContext(context.Background(), msg)
}

// SendContext transmits msg using the provided context for cancellation and deadlines.
func (c *Client) SendContext(ctx context.Context, msg *Message) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if msg == nil {
		return errors.New("gosmtp: message is nil")
	}

	fromRaw := strings.TrimSpace(msg.From)
	if fromRaw == "" {
		fromRaw = strings.TrimSpace(c.config.From)
	}
	if fromRaw == "" {
		return errors.New("gosmtp: From address is required")
	}
	fromEmail, err := extractEmail(fromRaw)
	if err != nil {
		return fmt.Errorf("gosmtp: invalid From address: %w", err)
	}

	recipients, err := msg.Recipients()
	if err != nil {
		return err
	}

	payload, err := msg.Build(c.config.From, c.config.Encoding, c.config.Charset)
	if err != nil {
		return err
	}

	auth, err := buildAuth(c.config)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(c.config.Host, strconv.Itoa(c.config.Port))
	dialer := &net.Dialer{Timeout: c.config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("gosmtp: failed to dial %s: %w", addr, err)
	}

	deadline := computeDeadline(ctx, c.config.Timeout)
	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return fmt.Errorf("gosmtp: failed to set connection deadline: %w", err)
		}
	}

	// Ensure connection is aborted if ctx is cancelled mid-session.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	smtpClient, err := c.openSMTPClient(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() {
		_ = smtpClient.Close()
	}()

	if auth != nil {
		if err := smtpClient.Auth(auth); err != nil {
			return fmt.Errorf("gosmtp: SMTP authentication failed: %w", err)
		}
	}

	if err := smtpClient.Mail(fromEmail); err != nil {
		return fmt.Errorf("gosmtp: MAIL FROM failed: %w", err)
	}
	for _, rcpt := range recipients {
		if err := smtpClient.Rcpt(rcpt); err != nil {
			return fmt.Errorf("gosmtp: RCPT TO %q failed: %w", rcpt, err)
		}
	}

	w, err := smtpClient.Data()
	if err != nil {
		return fmt.Errorf("gosmtp: DATA command failed: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("gosmtp: failed to write message body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("gosmtp: failed to finalize message data: %w", err)
	}

	if err := smtpClient.Quit(); err != nil {
		return fmt.Errorf("gosmtp: QUIT failed: %w", err)
	}
	return nil
}

func (c *Client) openSMTPClient(ctx context.Context, conn net.Conn) (*smtp.Client, error) {
	tlsCfg := c.config.buildTLSConfig()

	switch c.config.Encryption {
	case EncryptionTLS, EncryptionSSL:
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("gosmtp: TLS handshake failed: %w", err)
		}
		client, err := smtp.NewClient(tlsConn, c.config.Host)
		if err != nil {
			return nil, fmt.Errorf("gosmtp: failed to initialize TLS SMTP client: %w", err)
		}
		if err := client.Hello(c.config.LocalName); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("gosmtp: EHLO/HELO failed: %w", err)
		}
		return client, nil

	case EncryptionSTARTTLS:
		client, err := smtp.NewClient(conn, c.config.Host)
		if err != nil {
			return nil, fmt.Errorf("gosmtp: failed to initialize SMTP client: %w", err)
		}
		if err := client.Hello(c.config.LocalName); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("gosmtp: EHLO/HELO failed: %w", err)
		}
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			_ = client.Close()
			return nil, errors.New("gosmtp: server does not support STARTTLS")
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("gosmtp: STARTTLS negotiation failed: %w", err)
		}
		return client, nil

	case EncryptionNone:
		client, err := smtp.NewClient(conn, c.config.Host)
		if err != nil {
			return nil, fmt.Errorf("gosmtp: failed to initialize SMTP client: %w", err)
		}
		if err := client.Hello(c.config.LocalName); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("gosmtp: EHLO/HELO failed: %w", err)
		}
		return client, nil

	default:
		return nil, fmt.Errorf("gosmtp: unsupported Encryption %q", c.config.Encryption)
	}
}

func computeDeadline(ctx context.Context, timeout time.Duration) time.Time {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok {
		if deadline.IsZero() || ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	}
	return deadline
}

