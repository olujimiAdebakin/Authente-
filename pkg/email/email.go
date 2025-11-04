package email

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"

	"authentio/pkg/logger"
)

// Client is a simple SMTP client used to send transactional emails (OTP, password reset, etc.)
type Client struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string // optional From address; if empty Username will be used
}

// NewClient constructs a new email client.
func NewClient(host string, port int, username, password, from string) *Client {
	return &Client{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		From:     from,
	}
}

// Send sends an email to one or more recipients. The body may contain HTML.
func (c *Client) Send(to []string, subject, body string) error {
	if len(to) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	from := c.From
	if from == "" {
		from = c.Username
	}

	// Build message with basic MIME headers (HTML)
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = strings.Join(to, ",")
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"utf-8\""

	var msg strings.Builder
	for k, v := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))

	auth := smtp.PlainAuth("", c.Username, c.Password, c.Host)

	// Use direct TLS for port 465, otherwise try SendMail which will typically use STARTTLS on 587
	if c.Port == 465 {
		return c.sendUsingTLS(addr, auth, from, to, []byte(msg.String()))
	}

	// Try standard SendMail (works for servers advertising STARTTLS)
	if err := smtp.SendMail(addr, auth, from, to, []byte(msg.String())); err != nil {
		logger.Warn("smtp.SendMail failed, falling back to direct TLS", "error", err)
		return c.sendUsingTLS(addr, auth, from, to, []byte(msg.String()))
	}
	return nil
}

// sendUsingTLS connects to the SMTP server over TLS and sends the message.
func (c *Client) sendUsingTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	// Establish TLS connection
	tlsconfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         c.Host,
	}

	conn, err := tls.Dial("tcp", addr, tlsconfig)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return fmt.Errorf("new smtp client: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err = client.Auth(auth); err != nil {
				return fmt.Errorf("auth failed: %w", err)
			}
		}
	}

	if err = client.Mail(from); err != nil {
		return fmt.Errorf("mail from failed: %w", err)
	}

	for _, addr := range to {
		if err = client.Rcpt(addr); err != nil {
			return fmt.Errorf("rcpt to %s failed: %w", addr, err)
		}
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("data command failed: %w", err)
	}
	_, err = wc.Write(msg)
	if err != nil {
		return fmt.Errorf("write message failed: %w", err)
	}
	if err = wc.Close(); err != nil {
		return fmt.Errorf("close writer failed: %w", err)
	}

	// Send the QUIT command and close the connection.
	if err = client.Quit(); err != nil {
		return fmt.Errorf("quit failed: %w", err)
	}
	return nil
}

// SendOTP is a convenience helper that formats and sends an OTP email.
func (c *Client) SendOTP(to string, code string) error {
	subject := "Your verification code"
	body := fmt.Sprintf(`<p>Your verification code is <strong>%s</strong>. It will expire in 10 minutes.</p>`, code)
	return c.Send([]string{to}, subject, body)
}

// SendPasswordReset sends a password reset email with a provided code or link.
func (c *Client) SendPasswordReset(to string, codeOrLink string) error {
	subject := "Password reset request"
	body := fmt.Sprintf(`<p>We received a request to reset your password. Use the code below or click the link:</p><p><strong>%s</strong></p>`, codeOrLink)
	return c.Send([]string{to}, subject, body)
}
