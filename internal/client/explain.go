package client

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
)

const StatusReady = "есть связь с сервером"

// Explain переводит сбой открытия сессии в одну фразу.
// Адрес назначения и PSK в текст не входят: их нет среди распознаваемых причин.
func Explain(err error) string {
	if err == nil {
		return ""
	}
	if phrase := knownPhrase(err); phrase != "" {
		return phrase
	}
	if unreachable(err) {
		return "сервер не ответил"
	}
	if certRejected(err) {
		return "сертификат сервера не принят"
	}
	return "нет связи с сервером: " + brief(err)
}

func knownPhrase(err error) string {
	text := err.Error()
	switch {
	case strings.Contains(text, "сервер не принял ключ"):
		return "сервер не принял ключ"
	case strings.Contains(text, "сервер не согласовал HTTP/2"):
		return "сервер не согласовал HTTP/2"
	default:
		return ""
	}
}

func unreachable(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETDOWN) {
		return true
	}
	var dns *net.DNSError
	if errors.As(err, &dns) && (dns.IsNotFound || dns.Err == "no such host") {
		return true
	}
	text := strings.ToLower(err.Error())
	for _, part := range []string{
		"timeout",
		"timed out",
		"connection refused",
		"actively refused",
		"network is unreachable",
		"host is unreachable",
		"no such host",
	} {
		if strings.Contains(text, part) {
			return true
		}
	}
	return false
}

func certRejected(err error) bool {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var host x509.HostnameError
	var roots x509.SystemRootsError
	if errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &host) || errors.As(err, &roots) {
		return true
	}
	return strings.Contains(err.Error(), "x509:")
}

func brief(err error) string {
	text := err.Error()
	if i := strings.IndexAny(text, "\r\n"); i >= 0 {
		text = text[:i]
	}
	text = strings.TrimSpace(text)
	runes := []rune(text)
	const max = 160
	if len(runes) > max {
		text = string(runes[:max]) + "…"
	}
	return text
}
