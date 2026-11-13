package gosmtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type capturedMail struct {
	From       string
	Recipients []string
	RawData    []byte
	TLSUsed    bool
	AuthMethod string
	Username   string
	Password   string
}

type mockSMTPServer struct {
	listener     net.Listener
	tlsConfig    *tls.Config
	implicitTLS  bool
	allowStartTL bool
	expectedUser string
	expectedPass string
	authMethods  []string

	mu       sync.Mutex
	captured []capturedMail
	wg       sync.WaitGroup
}

func generateTestTLSConfig(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, pool
}

func startMockSMTPServer(t *testing.T, implicitTLS, allowStartTLS bool, authMethods []string, user, pass string) (*mockSMTPServer, *x509.CertPool, int) {
	t.Helper()

	tlsCfg, pool := generateTestTLSConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &mockSMTPServer{
		listener:     ln,
		tlsConfig:    tlsCfg,
		implicitTLS:  implicitTLS,
		allowStartTL: allowStartTLS,
		expectedUser: user,
		expectedPass: pass,
		authMethods:  authMethods,
	}

	srv.wg.Add(1)
	go srv.serve()

	t.Cleanup(func() {
		_ = srv.listener.Close()
		srv.wg.Wait()
	})

	port := ln.Addr().(*net.TCPAddr).Port
	return srv, pool, port
}

func (s *mockSMTPServer) messages() []capturedMail {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]capturedMail, len(s.captured))
	copy(out, s.captured)
	return out
}

func (s *mockSMTPServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(conn)
	}
}

func (s *mockSMTPServer) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	tlsActive := false
	if s.implicitTLS {
		tlsConn := tls.Server(conn, s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		conn = tlsConn
		tlsActive = true
	}

	tp := textproto.NewConn(conn)
	defer func() { _ = tp.Close() }()

	_ = tp.PrintfLine("220 localhost ESMTP mock")

	var mail capturedMail
	mail.TLSUsed = tlsActive

	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO "):
			_ = tp.PrintfLine("250-localhost")
			if s.allowStartTL && !tlsActive {
				_ = tp.PrintfLine("250-STARTTLS")
			}
			if len(s.authMethods) > 0 {
				_ = tp.PrintfLine("250-AUTH %s", strings.Join(s.authMethods, " "))
			}
			_ = tp.PrintfLine("250 SIZE 10485760")

		case strings.HasPrefix(upper, "HELO "):
			_ = tp.PrintfLine("250 localhost")

		case upper == "STARTTLS":
			if !s.allowStartTL || tlsActive {
				_ = tp.PrintfLine("502 Command not implemented")
				continue
			}
			_ = tp.PrintfLine("220 Ready to start TLS")
			tlsConn := tls.Server(conn, s.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			tp = textproto.NewConn(conn)
			tlsActive = true
			mail.TLSUsed = true

		case strings.HasPrefix(upper, "AUTH "):
			if !s.handleAuth(tp, line[5:], &mail) {
				continue
			}

		case strings.HasPrefix(upper, "MAIL FROM:"):
			addr := strings.TrimSpace(line[len("MAIL FROM:"):])
			addr = strings.Trim(addr, "<>")
			mail.From = addr
			_ = tp.PrintfLine("250 OK")

		case strings.HasPrefix(upper, "RCPT TO:"):
			addr := strings.TrimSpace(line[len("RCPT TO:"):])
			addr = strings.Trim(addr, "<>")
			mail.Recipients = append(mail.Recipients, addr)
			_ = tp.PrintfLine("250 OK")

		case upper == "DATA":
			_ = tp.PrintfLine("354 End data with <CR><LF>.<CR><LF>")
			dataBytes, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			mail.RawData = dataBytes
			s.mu.Lock()
			s.captured = append(s.captured, mail)
			s.mu.Unlock()
			_ = tp.PrintfLine("250 OK: queued")
			// Reset envelope for possible next message.
			mail = capturedMail{
				TLSUsed:    tlsActive,
				AuthMethod: mail.AuthMethod,
				Username:   mail.Username,
				Password:   mail.Password,
			}

		case upper == "RSET":
			mail.From = ""
			mail.Recipients = nil
			mail.RawData = nil
			_ = tp.PrintfLine("250 OK")

		case upper == "QUIT":
			_ = tp.PrintfLine("221 Bye")
			return

		default:
			_ = tp.PrintfLine("500 Unknown command")
		}
	}
}

func (s *mockSMTPServer) handleAuth(tp *textproto.Conn, rest string, mail *capturedMail) bool {
	parts := strings.SplitN(strings.TrimSpace(rest), " ", 2)
	mech := strings.ToUpper(parts[0])
	switch mech {
	case "PLAIN":
		var token string
		if len(parts) == 2 {
			token = parts[1]
		} else {
			_ = tp.PrintfLine("334 ")
			var err error
			token, err = tp.ReadLine()
			if err != nil {
				return false
			}
		}
		raw, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			_ = tp.PrintfLine("535 Invalid base64")
			return false
		}
		fields := bytes.Split(raw, []byte{0})
		if len(fields) != 3 {
			_ = tp.PrintfLine("535 Invalid PLAIN payload")
			return false
		}
		user := string(fields[1])
		pass := string(fields[2])
		if user != s.expectedUser || pass != s.expectedPass {
			_ = tp.PrintfLine("535 Authentication failed")
			return false
		}
		mail.AuthMethod = "PLAIN"
		mail.Username = user
		mail.Password = pass
		_ = tp.PrintfLine("235 Authentication successful")
		return true

	case "LOGIN":
		_ = tp.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte("Username:")))
		userB64, err := tp.ReadLine()
		if err != nil {
			return false
		}
		userBytes, err := base64.StdEncoding.DecodeString(userB64)
		if err != nil {
			_ = tp.PrintfLine("535 Invalid base64")
			return false
		}
		_ = tp.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte("Password:")))
		passB64, err := tp.ReadLine()
		if err != nil {
			return false
		}
		passBytes, err := base64.StdEncoding.DecodeString(passB64)
		if err != nil {
			_ = tp.PrintfLine("535 Invalid base64")
			return false
		}
		if string(userBytes) != s.expectedUser || string(passBytes) != s.expectedPass {
			_ = tp.PrintfLine("535 Authentication failed")
			return false
		}
		mail.AuthMethod = "LOGIN"
		mail.Username = string(userBytes)
		mail.Password = string(passBytes)
		_ = tp.PrintfLine("235 Authentication successful")
		return true

	case "CRAM-MD5":
		challenge := "<1234.5678@localhost>"
		_ = tp.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte(challenge)))
		respB64, err := tp.ReadLine()
		if err != nil {
			return false
		}
		respBytes, err := base64.StdEncoding.DecodeString(respB64)
		if err != nil {
			_ = tp.PrintfLine("535 Invalid base64")
			return false
		}
		respParts := strings.SplitN(string(respBytes), " ", 2)
		if len(respParts) != 2 {
			_ = tp.PrintfLine("535 Invalid CRAM-MD5 response")
			return false
		}
		mac := hmac.New(md5.New, []byte(s.expectedPass))
		mac.Write([]byte(challenge))
		expectedHex := hex.EncodeToString(mac.Sum(nil))
		if respParts[0] != s.expectedUser || respParts[1] != expectedHex {
			_ = tp.PrintfLine("535 Authentication failed")
			return false
		}
		mail.AuthMethod = "CRAM-MD5"
		mail.Username = respParts[0]
		_ = tp.PrintfLine("235 Authentication successful")
		return true

	default:
		_ = tp.PrintfLine("504 Unrecognized authentication type")
		return false
	}
}

func TestConfigValidationAndDefaults(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error when Host is empty")
	}
	if _, err := New(Config{Host: "smtp.example.com", Port: 70000}); err == nil {
		t.Fatal("expected error when Port is out of range")
	}
	if _, err := New(Config{Host: "smtp.example.com", Encryption: "bogus"}); err == nil {
		t.Fatal("expected error for invalid Encryption")
	}
	if _, err := New(Config{Host: "smtp.example.com", Encoding: "rot13"}); err == nil {
		t.Fatal("expected error for invalid Encoding")
	}
	if _, err := New(Config{Host: "smtp.example.com", AuthType: "oauth99"}); err == nil {
		t.Fatal("expected error for invalid AuthType")
	}
	if _, err := New(Config{Host: "smtp.example.com", LocalName: "bad\r\nname"}); err == nil {
		t.Fatal("expected error for CRLF in LocalName")
	}

	c1, err := New(Config{Host: "smtp.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg1 := c1.Config()
	if cfg1.Port != 587 || cfg1.Encryption != EncryptionSTARTTLS || cfg1.Encoding != EncodingQuotedPrintable || cfg1.Charset != "UTF-8" {
		t.Fatalf("unexpected defaults: %+v", cfg1)
	}

	c2, err := New(Config{Host: "smtp.example.com", Encryption: EncryptionTLS})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c2.Config().Port != 465 {
		t.Fatalf("expected default port 465 for TLS, got %d", c2.Config().Port)
	}

	c3, err := New(Config{Host: "smtp.example.com", Port: 465})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c3.Config().Encryption != EncryptionTLS {
		t.Fatalf("expected EncryptionTLS inferred from port 465, got %s", c3.Config().Encryption)
	}

	c4, err := New(Config{Host: "smtp.example.com", Encryption: EncryptionNone})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c4.Config().Port != 25 {
		t.Fatalf("expected default port 25 for EncryptionNone, got %d", c4.Config().Port)
	}
}

func TestEncryptionModes(t *testing.T) {
	tests := []struct {
		name        string
		implicitTLS bool
		startTLS    bool
		encryption  Encryption
		expectTLS   bool
	}{
		{
			name:       "None",
			encryption: EncryptionNone,
			expectTLS:  false,
		},
		{
			name:       "STARTTLS",
			startTLS:   true,
			encryption: EncryptionSTARTTLS,
			expectTLS:  true,
		},
		{
			name:        "TLS",
			implicitTLS: true,
			encryption:  EncryptionTLS,
			expectTLS:   true,
		},
		{
			name:        "SSL",
			implicitTLS: true,
			encryption:  EncryptionSSL,
			expectTLS:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, pool, port := startMockSMTPServer(t, tc.implicitTLS, tc.startTLS, nil, "", "")
			client, err := New(Config{
				Host:       "127.0.0.1",
				Port:       port,
				From:       "sender@example.com",
				Encryption: tc.encryption,
				TLSConfig:  &tls.Config{RootCAs: pool},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			msg := NewMessage().
				AddTo("dest@example.com").
				SetSubject("Encryption Test").
				SetBody("Hello over " + string(tc.encryption))

			if err := client.Send(msg); err != nil {
				t.Fatalf("Send: %v", err)
			}

			msgs := srv.messages()
			if len(msgs) != 1 {
				t.Fatalf("expected 1 message, got %d", len(msgs))
			}
			if msgs[0].TLSUsed != tc.expectTLS {
				t.Fatalf("expected TLSUsed=%v, got %v", tc.expectTLS, msgs[0].TLSUsed)
			}
		})
	}
}

func TestSTARTTLSFailsWhenUnsupported(t *testing.T) {
	_, pool, port := startMockSMTPServer(t, false, false, nil, "", "")
	client, err := New(Config{
		Host:       "127.0.0.1",
		Port:       port,
		From:       "sender@example.com",
		Encryption: EncryptionSTARTTLS,
		TLSConfig:  &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	msg := NewMessage().AddTo("dest@example.com").SetSubject("Test").SetBody("Body")
	if err := client.Send(msg); err == nil {
		t.Fatal("expected error when server does not support STARTTLS")
	}
}

func TestAuthenticationMechanisms(t *testing.T) {
	cases := []struct {
		name         string
		authType     AuthType
		expectedMech string
	}{
		{name: "PLAIN", authType: AuthPlain, expectedMech: "PLAIN"},
		{name: "LOGIN", authType: AuthLogin, expectedMech: "LOGIN"},
		{name: "CRAM-MD5", authType: AuthCRAMMD5, expectedMech: "CRAM-MD5"},
		{name: "Auto", authType: AuthAuto, expectedMech: "PLAIN"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, pool, port := startMockSMTPServer(
				t,
				false,
				true,
				[]string{"PLAIN", "LOGIN", "CRAM-MD5"},
				"alice",
				"s3cr3t",
			)
			client, err := New(Config{
				Host:       "127.0.0.1",
				Port:       port,
				Username:   "alice",
				Password:   "s3cr3t",
				From:       "alice@example.com",
				Encryption: EncryptionSTARTTLS,
				AuthType:   tc.authType,
				TLSConfig:  &tls.Config{RootCAs: pool},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			msg := NewMessage().AddTo("bob@example.com").SetSubject("Auth").SetBody("OK")
			if err := client.Send(msg); err != nil {
				t.Fatalf("Send: %v", err)
			}
			msgs := srv.messages()
			if len(msgs) != 1 || msgs[0].AuthMethod != tc.expectedMech {
				t.Fatalf("expected auth %s, got %+v", tc.expectedMech, msgs)
			}
		})
	}

	t.Run("InvalidPassword", func(t *testing.T) {
		_, pool, port := startMockSMTPServer(t, false, true, []string{"PLAIN"}, "alice", "s3cr3t")
		client, err := New(Config{
			Host:       "127.0.0.1",
			Port:       port,
			Username:   "alice",
			Password:   "wrong",
			From:       "alice@example.com",
			Encryption: EncryptionSTARTTLS,
			AuthType:   AuthPlain,
			TLSConfig:  &tls.Config{RootCAs: pool},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		msg := NewMessage().AddTo("bob@example.com").SetSubject("Auth").SetBody("OK")
		if err := client.Send(msg); err == nil {
			t.Fatal("expected authentication error")
		}
	})
}

func TestToCCAndCCIBCCRecipients(t *testing.T) {
	srv, pool, port := startMockSMTPServer(t, false, true, nil, "", "")
	client, err := New(Config{
		Host:       "127.0.0.1",
		Port:       port,
		From:       "Expéditeur <sender@example.com>",
		Encryption: EncryptionSTARTTLS,
		TLSConfig:  &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	msg := NewMessage().
		AddTo("To One <to1@example.com>", "to2@example.com").
		AddCC("cc1@example.com", "CC Two <cc2@example.com>").
		AddCCI("cci1@example.com", "to1@example.com"). // duplicate of To should be deduplicated
		AddBCC("bcc1@example.com").
		SetReplyTo("reply@example.com").
		SetSubject("Test CC et CCI").
		SetBody("Contenu confidentiel")

	if err := client.Send(msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	msgs := srv.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 captured message, got %d", len(msgs))
	}

	got := msgs[0]
	if got.From != "sender@example.com" {
		t.Fatalf("unexpected envelope From: %q", got.From)
	}
	wantRcpts := []string{
		"to1@example.com",
		"to2@example.com",
		"cc1@example.com",
		"cc2@example.com",
		"cci1@example.com",
		"bcc1@example.com",
	}
	if !slices.Equal(got.Recipients, wantRcpts) {
		t.Fatalf("envelope recipients mismatch:\ngot:  %v\nwant: %v", got.Recipients, wantRcpts)
	}

	rawStr := string(got.RawData)
	if strings.Contains(rawStr, "cci1@example.com") || strings.Contains(rawStr, "bcc1@example.com") {
		t.Fatalf("CCI/BCC addresses leaked into message payload:\n%s", rawStr)
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(got.RawData))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	if parsed.Header.Get("Bcc") != "" || parsed.Header.Get("Cci") != "" {
		t.Fatal("Bcc or Cci header must not be present")
	}
	if !strings.Contains(parsed.Header.Get("To"), "to1@example.com") || !strings.Contains(parsed.Header.Get("To"), "to2@example.com") {
		t.Fatalf("unexpected To header: %q", parsed.Header.Get("To"))
	}
	if !strings.Contains(parsed.Header.Get("Cc"), "cc1@example.com") || !strings.Contains(parsed.Header.Get("Cc"), "cc2@example.com") {
		t.Fatalf("unexpected Cc header: %q", parsed.Header.Get("Cc"))
	}
	if !strings.Contains(parsed.Header.Get("Reply-To"), "reply@example.com") {
		t.Fatalf("unexpected Reply-To header: %q", parsed.Header.Get("Reply-To"))
	}
}

func TestEncodingsAndCharset(t *testing.T) {
	utf8Text := "Bonjour à tous, voici des accents : éèêë ç € œuf !"
	asciiText := "Hello pure ASCII 7bit body\nLine 2."

	tests := []struct {
		name     string
		encoding Encoding
		charset  string
		body     string
		subject  string
	}{
		{
			name:     "QuotedPrintable UTF-8",
			encoding: EncodingQuotedPrintable,
			charset:  "UTF-8",
			body:     utf8Text,
			subject:  "Sujet accentué €",
		},
		{
			name:     "Base64 UTF-8",
			encoding: EncodingBase64,
			charset:  "UTF-8",
			body:     utf8Text,
			subject:  "Sujet en Base64 éà",
		},
		{
			name:     "8Bit ISO-8859-1",
			encoding: Encoding8Bit,
			charset:  "ISO-8859-1",
			body:     "Texte ISO-8859-1 \xe9\xe0",
			subject:  "Sujet 8bit",
		},
		{
			name:     "7Bit ASCII",
			encoding: Encoding7Bit,
			charset:  "US-ASCII",
			body:     asciiText,
			subject:  "Plain 7bit subject",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, port := startMockSMTPServer(t, false, false, nil, "", "")
			client, err := New(Config{
				Host:       "127.0.0.1",
				Port:       port,
				From:       "sender@example.com",
				Encryption: EncryptionNone,
				Encoding:   tc.encoding,
				Charset:    tc.charset,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			msg := NewMessage().
				AddTo("dest@example.com").
				SetSubject(tc.subject).
				SetBody(tc.body)

			if err := client.Send(msg); err != nil {
				t.Fatalf("Send: %v", err)
			}

			msgs := srv.messages()
			if len(msgs) != 1 {
				t.Fatalf("expected 1 message, got %d", len(msgs))
			}

			parsed, err := mail.ReadMessage(bytes.NewReader(msgs[0].RawData))
			if err != nil {
				t.Fatalf("mail.ReadMessage: %v", err)
			}
			if gotCTE := strings.ToLower(parsed.Header.Get("Content-Transfer-Encoding")); gotCTE != string(tc.encoding) {
				t.Fatalf("expected Content-Transfer-Encoding %q, got %q", tc.encoding, gotCTE)
			}
			_, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
			if err != nil {
				t.Fatalf("ParseMediaType: %v", err)
			}
			if !strings.EqualFold(params["charset"], tc.charset) {
				t.Fatalf("expected charset %q, got %q", tc.charset, params["charset"])
			}

			rawBody, err := io.ReadAll(parsed.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}

			switch tc.encoding {
			case EncodingQuotedPrintable:
				dec, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(rawBody)))
				if err != nil {
					t.Fatalf("decode qp: %v", err)
				}
				got := strings.TrimSuffix(string(dec), "\n")
				if got != tc.body {
					t.Fatalf("qp body mismatch: got %q, want %q", got, tc.body)
				}
			case EncodingBase64:
				dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(rawBody), "\r\n", ""))
				if err != nil {
					t.Fatalf("decode base64: %v", err)
				}
				if string(dec) != tc.body {
					t.Fatalf("base64 body mismatch: got %q, want %q", string(dec), tc.body)
				}
				// Also verify subject uses B-encoding when non-ASCII
				if !strings.Contains(parsed.Header.Get("Subject"), fmt.Sprintf("=?%s?b?", tc.charset)) &&
					!strings.Contains(parsed.Header.Get("Subject"), fmt.Sprintf("=?%s?B?", tc.charset)) {
					t.Fatalf("expected RFC2047 B-encoded subject, got %q", parsed.Header.Get("Subject"))
				}
			case Encoding8Bit, Encoding7Bit:
				normalized := strings.TrimSuffix(strings.ReplaceAll(string(rawBody), "\r\n", "\n"), "\n")
				if normalized != tc.body {
					t.Fatalf("body mismatch: got %q, want %q", normalized, tc.body)
				}
			}
		})
	}

	t.Run("7BitRejectsNonASCII", func(t *testing.T) {
		msg := NewMessage().
			SetFrom("a@example.com").
			AddTo("b@example.com").
			SetEncoding(Encoding7Bit).
			SetBody("accent é")
		if _, err := msg.Build("", EncodingQuotedPrintable, "UTF-8"); err == nil {
			t.Fatal("expected error for non-ASCII content with 7bit encoding")
		}
	})
}

func TestAttachmentsAndMultipartAlternative(t *testing.T) {
	srv, pool, port := startMockSMTPServer(t, true, false, nil, "", "")
	client, err := New(Config{
		Host:               "127.0.0.1",
		Port:               port,
		From:               "sender@example.com",
		Encryption:         EncryptionTLS,
		InsecureSkipVerify: true,
		TLSConfig:          &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "rapport.txt")
	diskData := []byte("Contenu du rapport sur disque.\nLigne 2.")
	if err := os.WriteFile(diskPath, diskData, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	binData := []byte{0x00, 0x01, 0x02, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF}
	readerData := []byte("{\"hello\":\"world\"}")
	inlineData := []byte("<svg><circle r='5'/></svg>")

	msg := NewMessage().
		AddTo("dest@example.com").
		SetSubject("Rapport et pièces jointes").
		SetBody("Version texte du message.").
		SetHTMLBody("<p>Version <b>HTML</b> avec <img src=\"cid:logo1\"/></p>").
		SetHeader("X-Custom-Tag", "gosmtp-test")

	if err := msg.AttachFile(diskPath); err != nil {
		t.Fatalf("AttachFile: %v", err)
	}
	if err := msg.Attach("image.png", binData, "image/png"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := msg.AttachReader("data.json", bytes.NewReader(readerData), "application/json"); err != nil {
		t.Fatalf("AttachReader: %v", err)
	}
	if err := msg.AttachInline("logo.svg", inlineData, "image/svg+xml", "logo1"); err != nil {
		t.Fatalf("AttachInline: %v", err)
	}

	if err := client.Send(msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	msgs := srv.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(msgs[0].RawData))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	if parsed.Header.Get("X-Custom-Tag") != "gosmtp-test" {
		t.Fatalf("expected custom header X-Custom-Tag, got %q", parsed.Header.Get("X-Custom-Tag"))
	}

	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("expected multipart/mixed, got %s", mediaType)
	}

	mr := multipart.NewReader(parsed.Body, params["boundary"])

	// Part 1: multipart/alternative
	part1, err := mr.NextPart()
	if err != nil {
		t.Fatalf("NextPart 1: %v", err)
	}
	altType, altParams, err := mime.ParseMediaType(part1.Header.Get("Content-Type"))
	if err != nil || altType != "multipart/alternative" {
		t.Fatalf("expected multipart/alternative in part 1, got %q (%v)", altType, err)
	}
	altReader := multipart.NewReader(part1, altParams["boundary"])
	plainPart, err := altReader.NextPart()
	if err != nil {
		t.Fatalf("plainPart: %v", err)
	}
	plainDec, _ := io.ReadAll(quotedprintable.NewReader(plainPart))
	if string(plainDec) != "Version texte du message." {
		t.Fatalf("unexpected plain alternative: %q", string(plainDec))
	}
	htmlPart, err := altReader.NextPart()
	if err != nil {
		t.Fatalf("htmlPart: %v", err)
	}
	htmlDec, _ := io.ReadAll(quotedprintable.NewReader(htmlPart))
	if !strings.Contains(string(htmlDec), "Version <b>HTML</b>") {
		t.Fatalf("unexpected html alternative: %q", string(htmlDec))
	}

	// Parts 2..5: Attachments
	type expectedAtt struct {
		filename    string
		disposition string
		contentID   string
		data        []byte
	}
	expected := []expectedAtt{
		{filename: "rapport.txt", disposition: "attachment", data: diskData},
		{filename: "image.png", disposition: "attachment", data: binData},
		{filename: "data.json", disposition: "attachment", data: readerData},
		{filename: "logo.svg", disposition: "inline", contentID: "<logo1>", data: inlineData},
	}

	for _, exp := range expected {
		p, err := mr.NextPart()
		if err != nil {
			t.Fatalf("NextPart (%s): %v", exp.filename, err)
		}
		disp, dispParams, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		if err != nil {
			t.Fatalf("ParseMediaType Content-Disposition: %v", err)
		}
		if disp != exp.disposition || dispParams["filename"] != exp.filename {
			t.Fatalf("unexpected disposition %q / filename %q (want %q / %q)", disp, dispParams["filename"], exp.disposition, exp.filename)
		}
		if exp.contentID != "" && p.Header.Get("Content-ID") != exp.contentID {
			t.Fatalf("expected Content-ID %q, got %q", exp.contentID, p.Header.Get("Content-ID"))
		}
		b64Bytes, err := io.ReadAll(p)
		if err != nil {
			t.Fatalf("read attachment part: %v", err)
		}
		dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(b64Bytes), "\r\n", ""))
		if err != nil {
			t.Fatalf("decode attachment base64: %v", err)
		}
		if !bytes.Equal(dec, exp.data) {
			t.Fatalf("attachment %s binary mismatch: got %v, want %v", exp.filename, dec, exp.data)
		}
	}

	if _, err := mr.NextPart(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after 5 parts, got %v", err)
	}
}

func TestHeaderInjectionRejected(t *testing.T) {
	validBase := func() *Message {
		return NewMessage().
			SetFrom("sender@example.com").
			AddTo("dest@example.com").
			SetSubject("Hello").
			SetBody("Body")
	}

	cases := []struct {
		name string
		make func() *Message
	}{
		{
			name: "SubjectCRLF",
			make: func() *Message {
				return validBase().SetSubject("Hi\r\nBcc: evil@example.com")
			},
		},
		{
			name: "FromCRLF",
			make: func() *Message {
				return validBase().SetFrom("sender@example.com\r\nX-Evil: 1")
			},
		},
		{
			name: "ToCRLF",
			make: func() *Message {
				return validBase().SetTo("dest@example.com\nX-Evil: 1")
			},
		},
		{
			name: "CCCRLF",
			make: func() *Message {
				return validBase().SetCC("cc@example.com\rX-Evil: 1")
			},
		},
		{
			name: "CCICRLF",
			make: func() *Message {
				return validBase().SetCCI("cci@example.com\r\nX-Evil: 1")
			},
		},
		{
			name: "CustomHeaderKeyCRLF",
			make: func() *Message {
				return validBase().SetHeader("X-Test\r\nEvil", "val")
			},
		},
		{
			name: "CustomHeaderValueCRLF",
			make: func() *Message {
				return validBase().SetHeader("X-Test", "val\r\nBcc: evil@example.com")
			},
		},
		{
			name: "CustomHeaderBccForbidden",
			make: func() *Message {
				return validBase().SetHeader("Bcc", "evil@example.com")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.make().Build("", EncodingQuotedPrintable, "UTF-8"); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}

	msg := validBase()
	if err := msg.Attach("evil\r\n.txt", []byte("x"), "text/plain"); err == nil {
		t.Fatal("expected error for CRLF in attachment filename")
	}
}

func TestSendContextCancellation(t *testing.T) {
	_, _, port := startMockSMTPServer(t, false, false, nil, "", "")
	client, err := New(Config{
		Host:       "127.0.0.1",
		Port:       port,
		From:       "sender@example.com",
		Encryption: EncryptionNone,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	msg := NewMessage().AddTo("dest@example.com").SetSubject("Cancelled").SetBody("Body")
	if err := client.SendContext(ctx, msg); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// Keep bufio import used or verify line lengths in base64 encoding.
func TestBase64LineWrapping(t *testing.T) {
	data := bytes.Repeat([]byte("A"), 200)
	encoded := encodeBase64Wrapped(data)
	scanner := bufio.NewScanner(bytes.NewReader(encoded))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 76 {
			t.Fatalf("base64 line exceeds 76 chars: %d", len(line))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
}

func TestAddressDisplayNameEncoding(t *testing.T) {
	msg := NewMessage().
		SetFrom("Éléonore <eleonore@example.com>").
		AddTo("François <francois@example.com>").
		SetReplyTo("Réponse <reply@example.com>").
		SetEncoding(EncodingBase64).
		SetCharset("ISO-8859-1").
		SetSubject("Test").
		SetBody("Body")

	raw, err := msg.Build("", EncodingQuotedPrintable, "UTF-8")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}

	for _, hdr := range []string{"From", "To", "Reply-To"} {
		val := parsed.Header.Get(hdr)
		if !strings.Contains(val, "=?ISO-8859-1?b?") && !strings.Contains(val, "=?ISO-8859-1?B?") {
			t.Fatalf("expected %s display name to use ISO-8859-1 B-encoding, got %q", hdr, val)
		}
	}
}

func TestAttachmentUTF8FilenameAndContentTypeParams(t *testing.T) {
	msg := NewMessage().
		SetFrom("sender@example.com").
		AddTo("dest@example.com").
		SetSubject("UTF-8 attachment").
		SetBody("See attached")

	content := []byte("héllo")
	if err := msg.Attach("résumé 2026.txt", content, "text/plain; charset=utf-8"); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	raw, err := msg.Build("", EncodingQuotedPrintable, "UTF-8")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	_, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	mr := multipart.NewReader(parsed.Body, params["boundary"])

	if _, err := mr.NextPart(); err != nil {
		t.Fatalf("NextPart body: %v", err)
	}
	attPart, err := mr.NextPart()
	if err != nil {
		t.Fatalf("NextPart attachment: %v", err)
	}

	ct, ctParams, err := mime.ParseMediaType(attPart.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType attachment Content-Type: %v", err)
	}
	if ct != "text/plain" || ctParams["charset"] != "utf-8" || ctParams["name"] != "résumé 2026.txt" {
		t.Fatalf("unexpected attachment Content-Type %q params=%v", ct, ctParams)
	}

	disp, dispParams, err := mime.ParseMediaType(attPart.Header.Get("Content-Disposition"))
	if err != nil {
		t.Fatalf("ParseMediaType attachment Content-Disposition: %v", err)
	}
	if disp != "attachment" || dispParams["filename"] != "résumé 2026.txt" {
		t.Fatalf("unexpected attachment Content-Disposition %q params=%v", disp, dispParams)
	}
}

func TestReservedCustomHeadersRejected(t *testing.T) {
	reserved := []string{
		"Date",
		"From",
		"To",
		"Cc",
		"Bcc",
		"Cci",
		"Reply-To",
		"Subject",
		"MIME-Version",
		"Content-Type",
		"Content-Transfer-Encoding",
		"from",
		"content-type",
	}

	for _, h := range reserved {
		msg := NewMessage().
			SetFrom("sender@example.com").
			AddTo("dest@example.com").
			SetSubject("Test").
			SetBody("Body").
			SetHeader(h, "override")
		if _, err := msg.Build("", EncodingQuotedPrintable, "UTF-8"); err == nil {
			t.Fatalf("expected error for reserved custom header %q", h)
		}
	}
}

func TestLoginAuthNonStandardPrompts(t *testing.T) {
	auth := &loginAuth{
		username: "alice",
		password: "secret",
		host:     "smtp.example.com",
	}
	mech, resp, err := auth.Start(&smtp.ServerInfo{
		Name: "smtp.example.com",
		TLS:  true,
	})
	if err != nil || mech != "LOGIN" || resp != nil {
		t.Fatalf("Start: mech=%q resp=%v err=%v", mech, resp, err)
	}

	u, err := auth.Next([]byte("User:"), true)
	if err != nil || string(u) != "alice" {
		t.Fatalf("step 0 expected alice, got %q (err=%v)", string(u), err)
	}
	p, err := auth.Next([]byte("Pass:"), true)
	if err != nil || string(p) != "secret" {
		t.Fatalf("step 1 expected secret, got %q (err=%v)", string(p), err)
	}
	if _, err := auth.Next([]byte("Extra:"), true); err == nil {
		t.Fatal("expected error on unexpected step 2 challenge")
	}
}

func TestLineLengthLimitFor7BitAnd8Bit(t *testing.T) {
	tooLong := strings.Repeat("a", 999)
	for _, enc := range []Encoding{Encoding7Bit, Encoding8Bit} {
		msg := NewMessage().
			SetFrom("sender@example.com").
			AddTo("dest@example.com").
			SetEncoding(enc).
			SetSubject("Line length").
			SetBody(tooLong)
		if _, err := msg.Build("", EncodingQuotedPrintable, "UTF-8"); err == nil {
			t.Fatalf("expected error for >998 byte line with %s encoding", enc)
		}
	}

	exactly998 := strings.Repeat("a", 998)
	for _, enc := range []Encoding{Encoding7Bit, Encoding8Bit} {
		msg := NewMessage().
			SetFrom("sender@example.com").
			AddTo("dest@example.com").
			SetEncoding(enc).
			SetSubject("Line length ok").
			SetBody(exactly998 + "\n" + exactly998)
		if _, err := msg.Build("", EncodingQuotedPrintable, "UTF-8"); err != nil {
			t.Fatalf("unexpected error for 998-byte lines with %s encoding: %v", enc, err)
		}
	}
}
