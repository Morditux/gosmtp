package gosmtp

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Attachment represents a file or inline asset attached to a Message.
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
	Inline      bool
	ContentID   string
}

// Message represents an email message to be sent via an SMTP Client.
type Message struct {
	From        string
	To          []string
	CC          []string
	CCI         []string
	BCC         []string
	ReplyTo     string
	Subject     string
	Body        string
	HTMLBody    string
	ContentType ContentType
	Encoding    Encoding
	Charset     string
	Headers     map[string]string
	Attachments []Attachment
	Date        time.Time
}

// NewMessage allocates and returns a new empty Message.
func NewMessage() *Message {
	return &Message{}
}

// SetFrom sets the sender address for the message.
func (m *Message) SetFrom(from string) *Message {
	m.From = from
	return m
}

// AddTo appends one or more primary recipient addresses.
func (m *Message) AddTo(addrs ...string) *Message {
	m.To = append(m.To, addrs...)
	return m
}

// SetTo replaces the primary recipient addresses.
func (m *Message) SetTo(addrs ...string) *Message {
	m.To = append([]string(nil), addrs...)
	return m
}

// AddCC appends one or more carbon copy (CC) recipient addresses.
func (m *Message) AddCC(addrs ...string) *Message {
	m.CC = append(m.CC, addrs...)
	return m
}

// SetCC replaces the carbon copy (CC) recipient addresses.
func (m *Message) SetCC(addrs ...string) *Message {
	m.CC = append([]string(nil), addrs...)
	return m
}

// AddCCI appends one or more blind carbon copy (CCI) recipient addresses.
func (m *Message) AddCCI(addrs ...string) *Message {
	m.CCI = append(m.CCI, addrs...)
	return m
}

// SetCCI replaces the blind carbon copy (CCI) recipient addresses.
func (m *Message) SetCCI(addrs ...string) *Message {
	m.CCI = append([]string(nil), addrs...)
	return m
}

// AddBCC appends one or more blind carbon copy (BCC) recipient addresses.
func (m *Message) AddBCC(addrs ...string) *Message {
	m.BCC = append(m.BCC, addrs...)
	return m
}

// SetBCC replaces the blind carbon copy (BCC) recipient addresses.
func (m *Message) SetBCC(addrs ...string) *Message {
	m.BCC = append([]string(nil), addrs...)
	return m
}

// SetReplyTo sets the Reply-To header address.
func (m *Message) SetReplyTo(addr string) *Message {
	m.ReplyTo = addr
	return m
}

// SetSubject sets the message subject.
func (m *Message) SetSubject(subject string) *Message {
	m.Subject = subject
	return m
}

// SetBody sets the plain-text (or single-part) body of the message.
func (m *Message) SetBody(body string) *Message {
	m.Body = body
	return m
}

// SetHTMLBody sets the HTML body of the message.
func (m *Message) SetHTMLBody(htmlBody string) *Message {
	m.HTMLBody = htmlBody
	return m
}

// SetContentType sets the media type for single-part messages.
func (m *Message) SetContentType(ct ContentType) *Message {
	m.ContentType = ct
	return m
}

// SetEncoding sets the Content-Transfer-Encoding for this message, overriding Config.Encoding.
func (m *Message) SetEncoding(enc Encoding) *Message {
	m.Encoding = enc
	return m
}

// SetCharset sets the character set for this message, overriding Config.Charset.
func (m *Message) SetCharset(charset string) *Message {
	m.Charset = charset
	return m
}

// SetHeader sets a custom MIME header on the message.
func (m *Message) SetHeader(key, value string) *Message {
	if m.Headers == nil {
		m.Headers = make(map[string]string)
	}
	m.Headers[key] = value
	return m
}

// AttachFile reads a file from disk and attaches it to the message.
func (m *Message) AttachFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("gosmtp: attachment file path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("gosmtp: failed to read attachment %q: %w", path, err)
	}
	filename := filepath.Base(path)
	ct := detectAttachmentContentType(filename, data)
	return m.Attach(filename, data, ct)
}

// Attach adds an in-memory attachment to the message.
func (m *Message) Attach(filename string, data []byte, contentType string) error {
	return m.addAttachment(filename, data, contentType, false, "")
}

// AttachReader reads all bytes from r and attaches them to the message.
func (m *Message) AttachReader(filename string, r io.Reader, contentType string) error {
	if r == nil {
		return errors.New("gosmtp: attachment reader is nil")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("gosmtp: failed to read attachment %q: %w", filename, err)
	}
	return m.Attach(filename, data, contentType)
}

// AttachInline adds an inline attachment (e.g., an embedded image referenced by Content-ID).
func (m *Message) AttachInline(filename string, data []byte, contentType string, contentID string) error {
	return m.addAttachment(filename, data, contentType, true, contentID)
}

func (m *Message) addAttachment(filename string, data []byte, contentType string, inline bool, contentID string) error {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return errors.New("gosmtp: attachment filename is required")
	}
	if containsCRLF(filename) {
		return errors.New("gosmtp: attachment filename must not contain CR or LF")
	}
	contentType = strings.TrimSpace(contentType)
	if containsCRLF(contentType) {
		return errors.New("gosmtp: attachment content type must not contain CR or LF")
	}
	contentID = strings.TrimSpace(contentID)
	if containsCRLF(contentID) {
		return errors.New("gosmtp: attachment content ID must not contain CR or LF")
	}
	if contentType == "" {
		contentType = detectAttachmentContentType(filename, data)
	}
	copied := make([]byte, len(data))
	copy(copied, data)

	m.Attachments = append(m.Attachments, Attachment{
		Filename:    filename,
		ContentType: contentType,
		Data:        copied,
		Inline:      inline,
		ContentID:   contentID,
	})
	return nil
}

func detectAttachmentContentType(filename string, data []byte) string {
	if ext := filepath.Ext(filename); ext != "" {
		if ct := mime.TypeByExtension(ext); ct != "" {
			return ct
		}
	}
	if len(data) > 0 {
		return http.DetectContentType(data)
	}
	return "application/octet-stream"
}

