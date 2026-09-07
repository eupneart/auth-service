package mail

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
)

type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

type SMTPMailer struct {
	cfg SMTPConfig
}

func NewSMTPMailer(cfg SMTPConfig) *SMTPMailer {
	return &SMTPMailer{cfg: cfg}
}

// SendPasswordReset delivers the reset link over SMTP. smtp.PlainAuth refuses to
// hand over credentials on a connection the server has not secured with
// STARTTLS, so a misconfigured host fails rather than leaking the password.
//
// ctx is accepted for interface conformity; net/smtp has no context-aware API.
func (m *SMTPMailer) SendPasswordReset(ctx context.Context, recipient, resetURL string) error {
	addr := net.JoinHostPort(m.cfg.Host, m.cfg.Port)
	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)

	msg := fmt.Appendf(nil,
		"From: %s\r\nTo: %s\r\nSubject: Reset your password\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n\r\n"+
			"Use the link below to choose a new password. It expires shortly and can be used once.\r\n\r\n"+
			"%s\r\n\r\nIf you did not request this, no action is needed.\r\n",
		m.cfg.From, recipient, resetURL)

	if err := smtp.SendMail(addr, auth, m.cfg.From, []string{recipient}, msg); err != nil {
		// The error is not wrapped with the recipient or URL: both are sensitive
		// and callers log this.
		return fmt.Errorf("sending password reset email: %w", err)
	}

	return nil
}
