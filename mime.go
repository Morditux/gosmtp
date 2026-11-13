package gosmtp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"sort"
	"strings"
	"time"
)

func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

func extractEmail(addr string) (string, error) {
	if containsCRLF(addr) {
		return "", errors.New("gosmtp: address must not contain CR or LF")
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("gosmtp: address is empty")
	}
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return "", fmt.Errorf("gosmtp: invalid email address %q: %w", addr, err)
	}
	if containsCRLF(parsed.Address) {
		return "", errors.New("gosmtp: parsed address must not contain CR or LF")
	}
	return parsed.Address, nil
}

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return true
		}
	}
	return false
}

func formatAddress(addr string, encoding Encoding, charset string) (string, error) {
	if containsCRLF(addr) {
		return "", errors.New("gosmtp: address must not contain CR or LF")
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("gosmtp: address is empty")
	}
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return "", fmt.Errorf("gosmtp: invalid email address %q: %w", addr, err)
	}
	if parsed.Name != "" && hasNonASCII(parsed.Name) {
		return fmt.Sprintf("%s <%s>", encodeHeaderSubject(parsed.Name, encoding, charset), parsed.Address), nil
	}
	return parsed.String(), nil
}

func formatAddressList(addrs []string, encoding Encoding, charset string) (string, error) {
	formatted := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		f, err := formatAddress(addr, encoding, charset)
		if err != nil {
			return "", err
		}
		formatted = append(formatted, f)
	}
	return strings.Join(formatted, ", "), nil
}

// Recipients returns the deduplicated list of raw email addresses from To, CC, CCI, and BCC.
func (m *Message) Recipients() ([]string, error) {
	if m == nil {
		return nil, errors.New("gosmtp: message is nil")
	}
	all := make([]string, 0, len(m.To)+len(m.CC)+len(m.CCI)+len(m.BCC))
	all = append(all, m.To...)
	all = append(all, m.CC...)
	all = append(all, m.CCI...)
	all = append(all, m.BCC...)

	seen := make(map[string]struct{}, len(all))
	recipients := make([]string, 0, len(all))
	for _, raw := range all {
		email, err := extractEmail(raw)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(email)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		recipients = append(recipients, email)
	}
	if len(recipients) == 0 {
		return nil, errors.New("gosmtp: at least one recipient (To, CC, CCI, or BCC) is required")
	}
	return recipients, nil
}

// Build serializes the Message into an RFC 5322 / MIME byte payload.
// CCI and BCC recipients are validated but strictly excluded from MIME headers.
func (m *Message) Build(defaultFrom string, defaultEncoding Encoding, defaultCharset string) ([]byte, error) {
	if m == nil {
		return nil, errors.New("gosmtp: message is nil")
	}

	fromRaw := strings.TrimSpace(m.From)
	if fromRaw == "" {
		fromRaw = strings.TrimSpace(defaultFrom)
	}
	if fromRaw == "" {
		return nil, errors.New("gosmtp: From address is required")
	}

	if _, err := m.Recipients(); err != nil {
		return nil, err
	}

	encoding := Encoding(strings.ToLower(strings.TrimSpace(string(m.Encoding))))
	if encoding == "" {
		encoding = Encoding(strings.ToLower(strings.TrimSpace(string(defaultEncoding))))
	}
	if encoding == "" {
		encoding = EncodingQuotedPrintable
	}
	switch encoding {
	case EncodingQuotedPrintable, EncodingBase64, Encoding8Bit, Encoding7Bit:
	default:
		return nil, fmt.Errorf("gosmtp: invalid Encoding %q", encoding)
	}

	charset := strings.TrimSpace(m.Charset)
	if charset == "" {
		charset = strings.TrimSpace(defaultCharset)
	}
	if charset == "" {
		charset = "UTF-8"
	}
	if containsCRLF(charset) {
		return nil, errors.New("gosmtp: Charset must not contain CR or LF")
	}

	fromFormatted, err := formatAddress(fromRaw, encoding, charset)
	if err != nil {
		return nil, fmt.Errorf("gosmtp: invalid From address: %w", err)
	}

	if containsCRLF(m.Subject) {
		return nil, errors.New("gosmtp: Subject must not contain CR or LF")
	}

	var buf bytes.Buffer

	date := m.Date
	if date.IsZero() {
		date = time.Now()
	}
	writeHeader(&buf, "Date", date.Format(time.RFC1123Z))
	writeHeader(&buf, "From", fromFormatted)

	if len(m.To) > 0 {
		toHeader, err := formatAddressList(m.To, encoding, charset)
		if err != nil {
			return nil, fmt.Errorf("gosmtp: invalid To address: %w", err)
		}
		writeHeader(&buf, "To", toHeader)
	}
	if len(m.CC) > 0 {
		ccHeader, err := formatAddressList(m.CC, encoding, charset)
		if err != nil {
			return nil, fmt.Errorf("gosmtp: invalid CC address: %w", err)
		}
		writeHeader(&buf, "Cc", ccHeader)
	}
	if strings.TrimSpace(m.ReplyTo) != "" {
		replyToFormatted, err := formatAddress(m.ReplyTo, encoding, charset)
		if err != nil {
			return nil, fmt.Errorf("gosmtp: invalid ReplyTo address: %w", err)
		}
		writeHeader(&buf, "Reply-To", replyToFormatted)
	}

	writeHeader(&buf, "Subject", encodeHeaderSubject(m.Subject, encoding, charset))
	writeHeader(&buf, "MIME-Version", "1.0")

	if len(m.Headers) > 0 {
		keys := make([]string, 0, len(m.Headers))
		for k := range m.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := m.Headers[k]
			if err := validateCustomHeader(k, v); err != nil {
				return nil, err
			}
			writeHeader(&buf, k, v)
		}
	}

	if len(m.Attachments) > 0 {
		if err := m.writeMixedBody(&buf, encoding, charset); err != nil {
			return nil, err
		}
	} else {
		if err := m.writeBodyOnly(&buf, encoding, charset); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func validateCustomHeader(key, value string) error {
	trimmedKey := strings.TrimSpace(key)
	if trimmedKey == "" {
		return errors.New("gosmtp: custom header key cannot be empty")
	}
	if containsCRLF(key) || strings.Contains(key, ":") {
		return fmt.Errorf("gosmtp: invalid custom header key %q", key)
	}
	if containsCRLF(value) {
		return fmt.Errorf("gosmtp: custom header %q value must not contain CR or LF", key)
	}
	switch strings.ToLower(trimmedKey) {
	case "bcc", "cci":
		return fmt.Errorf("gosmtp: header %q is not allowed in custom headers; use Message.CCI or Message.BCC", key)
	case "date", "from", "to", "cc", "reply-to", "subject", "mime-version", "content-type", "content-transfer-encoding":
		return fmt.Errorf("gosmtp: reserved header %q cannot be overridden via Message.Headers", key)
	}
	return nil
}

func (m *Message) resolveSingleContentType() (ContentType, error) {
	ct := ContentType(strings.ToLower(strings.TrimSpace(string(m.ContentType))))
	if ct == "" {
		return ContentTypeTextPlain, nil
	}
	switch ct {
	case ContentTypeTextPlain, ContentTypeTextHTML:
		return ct, nil
	default:
		if containsCRLF(string(ct)) {
			return "", errors.New("gosmtp: ContentType must not contain CR or LF")
		}
		return ct, nil
	}
}

func (m *Message) writeBodyOnly(buf *bytes.Buffer, encoding Encoding, charset string) error {
	if m.Body != "" && m.HTMLBody != "" {
		return m.writeAlternativePart(buf, encoding, charset)
	}

	contentType, bodyText, err := m.singleBodyParams()
	if err != nil {
		return err
	}

	encodedBody, err := encodeBody([]byte(bodyText), encoding)
	if err != nil {
		return err
	}

	writeHeader(buf, "Content-Type", fmt.Sprintf("%s; charset=%q", contentType, charset))
	writeHeader(buf, "Content-Transfer-Encoding", string(encoding))
	buf.WriteString("\r\n")
	buf.Write(encodedBody)
	return nil
}

func (m *Message) singleBodyParams() (ContentType, string, error) {
	if m.Body == "" && m.HTMLBody != "" {
		return ContentTypeTextHTML, m.HTMLBody, nil
	}
	ct, err := m.resolveSingleContentType()
	if err != nil {
		return "", "", err
	}
	return ct, m.Body, nil
}

func (m *Message) writeAlternativePart(buf *bytes.Buffer, encoding Encoding, charset string) error {
	var altBuf bytes.Buffer
	altWriter := multipart.NewWriter(&altBuf)

	writeHeader(buf, "Content-Type", fmt.Sprintf("multipart/alternative; boundary=%q", altWriter.Boundary()))
	buf.WriteString("\r\n")

	if err := writeTextMIMEPart(altWriter, string(ContentTypeTextPlain), charset, encoding, m.Body); err != nil {
		return err
	}
	if err := writeTextMIMEPart(altWriter, string(ContentTypeTextHTML), charset, encoding, m.HTMLBody); err != nil {
		return err
	}
	if err := altWriter.Close(); err != nil {
		return err
	}

	buf.Write(altBuf.Bytes())
	return nil
}

func (m *Message) writeMixedBody(buf *bytes.Buffer, encoding Encoding, charset string) error {
	var mixedBuf bytes.Buffer
	mixedWriter := multipart.NewWriter(&mixedBuf)

	writeHeader(buf, "Content-Type", fmt.Sprintf("multipart/mixed; boundary=%q", mixedWriter.Boundary()))
	buf.WriteString("\r\n")

	if m.Body != "" && m.HTMLBody != "" {
		var altBuf bytes.Buffer
		altWriter := multipart.NewWriter(&altBuf)
		if err := writeTextMIMEPart(altWriter, string(ContentTypeTextPlain), charset, encoding, m.Body); err != nil {
			return err
		}
		if err := writeTextMIMEPart(altWriter, string(ContentTypeTextHTML), charset, encoding, m.HTMLBody); err != nil {
			return err
		}
		if err := altWriter.Close(); err != nil {
			return err
		}

		h := make(textproto.MIMEHeader)
		h.Set("Content-Type", fmt.Sprintf("multipart/alternative; boundary=%q", altWriter.Boundary()))
		pw, err := mixedWriter.CreatePart(h)
		if err != nil {
			return err
		}
		if _, err := pw.Write(altBuf.Bytes()); err != nil {
			return err
		}
	} else {
		contentType, bodyText, err := m.singleBodyParams()
		if err != nil {
			return err
		}
		if err := writeTextMIMEPart(mixedWriter, string(contentType), charset, encoding, bodyText); err != nil {
			return err
		}
	}

	for _, att := range m.Attachments {
		if err := writeAttachmentPart(mixedWriter, att); err != nil {
			return err
		}
	}

	if err := mixedWriter.Close(); err != nil {
		return err
	}
	buf.Write(mixedBuf.Bytes())
	return nil
}

func writeTextMIMEPart(mw *multipart.Writer, mediaType, charset string, encoding Encoding, body string) error {
	encodedBody, err := encodeBody([]byte(body), encoding)
	if err != nil {
		return err
	}
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", fmt.Sprintf("%s; charset=%q", mediaType, charset))
	h.Set("Content-Transfer-Encoding", string(encoding))
	pw, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	_, err = pw.Write(encodedBody)
	return err
}

func writeAttachmentPart(mw *multipart.Writer, att Attachment) error {
	if containsCRLF(att.Filename) || containsCRLF(att.ContentType) || containsCRLF(att.ContentID) {
		return errors.New("gosmtp: attachment metadata must not contain CR or LF")
	}
	if strings.TrimSpace(att.Filename) == "" {
		return errors.New("gosmtp: attachment filename is required")
	}
	ct := strings.TrimSpace(att.ContentType)
	if ct == "" {
		ct = detectAttachmentContentType(att.Filename, att.Data)
	}

	disposition := "attachment"
	if att.Inline {
		disposition = "inline"
	}

	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType = ct
		params = make(map[string]string)
	} else if params == nil {
		params = make(map[string]string)
	}
	params["name"] = att.Filename

	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", mime.FormatMediaType(mediaType, params))
	h.Set("Content-Transfer-Encoding", "base64")
	h.Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": att.Filename}))
	if att.Inline && strings.TrimSpace(att.ContentID) != "" {
		cid := strings.Trim(strings.TrimSpace(att.ContentID), "<>")
		h.Set("Content-ID", fmt.Sprintf("<%s>", cid))
	}

	pw, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	_, err = pw.Write(encodeBase64Wrapped(att.Data))
	return err
}

func writeHeader(buf *bytes.Buffer, key, value string) {
	buf.WriteString(key)
	buf.WriteString(": ")
	buf.WriteString(value)
	buf.WriteString("\r\n")
}

func encodeHeaderSubject(subject string, encoding Encoding, charset string) string {
	if subject == "" {
		return ""
	}
	if encoding == EncodingBase64 {
		return mime.BEncoding.Encode(charset, subject)
	}
	return mime.QEncoding.Encode(charset, subject)
}

func encodeBody(data []byte, encoding Encoding) ([]byte, error) {
	switch encoding {
	case EncodingQuotedPrintable:
		var buf bytes.Buffer
		qw := quotedprintable.NewWriter(&buf)
		if _, err := qw.Write(data); err != nil {
			return nil, err
		}
		if err := qw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case EncodingBase64:
		return encodeBase64Wrapped(data), nil
	case Encoding8Bit:
		normalized := normalizeCRLFBytes(data)
		if err := validateLineLengths(normalized, 998); err != nil {
			return nil, err
		}
		return normalized, nil
	case Encoding7Bit:
		for _, b := range data {
			if b > 127 {
				return nil, errors.New("gosmtp: 7bit encoding cannot represent non-ASCII bytes")
			}
		}
		normalized := normalizeCRLFBytes(data)
		if err := validateLineLengths(normalized, 998); err != nil {
			return nil, err
		}
		return normalized, nil
	default:
		return nil, fmt.Errorf("gosmtp: unsupported encoding %q", encoding)
	}
}

func validateLineLengths(data []byte, maxLen int) error {
	lineStart := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\r' || data[i] == '\n' {
			if i-lineStart > maxLen {
				return fmt.Errorf("gosmtp: line length %d exceeds RFC 5322 limit of %d bytes", i-lineStart, maxLen)
			}
			if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
				i++
			}
			lineStart = i + 1
		}
	}
	if len(data)-lineStart > maxLen {
		return fmt.Errorf("gosmtp: line length %d exceeds RFC 5322 limit of %d bytes", len(data)-lineStart, maxLen)
	}
	return nil
}

func encodeBase64Wrapped(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	const lineLen = 76
	var buf bytes.Buffer
	for i := 0; i < len(encoded); i += lineLen {
		end := i + lineLen
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteString("\r\n")
	}
	return buf.Bytes()
}

func normalizeCRLFBytes(data []byte) []byte {
	var buf bytes.Buffer
	buf.Grow(len(data))
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' && (i == 0 || data[i-1] != '\r') {
			buf.WriteByte('\r')
		}
		buf.WriteByte(data[i])
	}
	return buf.Bytes()
}
