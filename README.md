# gosmtp

Zero-dependency Go library for sending emails over SMTP, initialized through a `Config` struct.

## Features

- Centralized client initialization via `Config` and `gosmtp.New(cfg)`
- Standard transport encryption protocols:
  - `EncryptionSTARTTLS` (`"starttls"`, default port `587`)
  - `EncryptionTLS` / `EncryptionSSL` (`"tls"` / `"ssl"`, implicit TLS / SMTPS, default port `465`)
  - `EncryptionNone` (`"none"`, unencrypted SMTP, default port `25`)
- Authentication mechanisms: `AuthAuto`, `AuthPlain`, `AuthLogin`, `AuthCRAMMD5`, `AuthNone`
- Full recipient support: `To`, `CC`, and `BCC` / `CCI` (blind carbon copy, included only in the SMTP `RCPT TO` envelope and strictly omitted from MIME headers)
- Configurable transfer encoding (`EncodingQuotedPrintable`, `EncodingBase64`, `Encoding8Bit`, `Encoding7Bit`) and charset (`Charset`, defaults to `"UTF-8"`) globally in `Config` or per `Message`
- Attachments from disk (`AttachFile`), in-memory bytes (`Attach`), `io.Reader` (`AttachReader`), or inline with `Content-ID` (`AttachInline`)
- Plain text (`Body`), HTML (`HTMLBody`), or combined (`multipart/alternative`) bodies
- Protection against CRLF header injection and context support (`SendContext`)

## Installation

```bash
go get github.com/Morditux/gosmtp
```

## Quick Start

```go
package main

import (
	"log"
	"time"

	"github.com/Morditux/gosmtp"
)

func main() {
	client, err := gosmtp.New(gosmtp.Config{
		Host:       "smtp.example.com",
		Port:       587,
		Username:   "user@example.com",
		Password:   "password",
		From:       "Sender <user@example.com>",
		Encryption: gosmtp.EncryptionSTARTTLS,
		AuthType:   gosmtp.AuthPlain,
		Encoding:   gosmtp.EncodingQuotedPrintable,
		Charset:    "UTF-8",
		Timeout:    15 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	msg := gosmtp.NewMessage().
		AddTo("recipient@example.com").
		AddCC("cc@example.com").
		AddCCI("hidden@example.com"). // or AddBCC(...)
		SetSubject("Monthly Report").
		SetBody("Hello,\n\nPlease find the report attached.").
		SetHTMLBody("<p>Hello,</p><p>Please find the report attached.</p>")

	if err := msg.AttachFile("report.pdf"); err != nil {
		log.Fatal(err)
	}

	if err := client.Send(msg); err != nil {
		log.Fatal(err)
	}
}
```

## Configuration

`Config` fields and defaults:

| Field | Default | Description |
| --- | --- | --- |
| `Host` | *(required)* | SMTP server hostname or IP address |
| `Port` | `587` / `465` / `25` | Derived from `Encryption` when `0` |
| `Encryption` | `EncryptionSTARTTLS` | `EncryptionSTARTTLS`, `EncryptionTLS`, `EncryptionSSL`, or `EncryptionNone` (inferred as `EncryptionTLS` for port `465`, `EncryptionNone` for port `25`) |
| `Username` / `Password` | `""` | Credentials for SMTP authentication |
| `AuthType` | `AuthAuto` | `AuthAuto` (uses `PLAIN` when `Username` is set), `AuthNone`, `AuthPlain`, `AuthLogin`, `AuthCRAMMD5` |
| `From` | `""` | Default sender address when `Message.From` is empty |
| `Encoding` | `EncodingQuotedPrintable` | `EncodingQuotedPrintable`, `EncodingBase64`, `Encoding8Bit`, `Encoding7Bit` |
| `Charset` | `"UTF-8"` | Default MIME character set |
| `TLSConfig` | `nil` | Custom `*tls.Config` (cloned before use; minimum TLS 1.2 enforced if unset) |
| `InsecureSkipVerify` | `false` | Skips TLS certificate verification when `true` |
| `Timeout` | `30s` | Connection and session deadline |
| `LocalName` | `"localhost"` | Hostname sent in `EHLO`/`HELO` |

## Testing

```bash
go test -v -race ./...
go vet ./...
```

## License

This project is licensed under the [MIT License](LICENSE).
