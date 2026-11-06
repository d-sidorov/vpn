package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
)

func TestExplain(t *testing.T) {
	refused := &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 443},
		Err:  syscall.ECONNREFUSED,
	}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: "сервер не ответил"},
		{name: "silent timeout", err: &net.OpError{Op: "dial", Err: silentTimeout{}}, want: "сервер не ответил"},
		{name: "refused", err: refused, want: "сервер не ответил"},
		{name: "refused text", err: errors.New("dial tcp: connection refused"), want: "сервер не ответил"},
		{name: "unreachable", err: &net.OpError{Op: "dial", Err: syscall.ENETUNREACH}, want: "сервер не ответил"},
		{name: "host unreachable", err: &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, want: "сервер не ответил"},
		{name: "unreachable text", err: errors.New("connect: network is unreachable"), want: "сервер не ответил"},
		{name: "dns", err: &net.DNSError{Err: "no such host", Name: "example.test", IsNotFound: true}, want: "сервер не ответил"},
		{name: "dns text", err: errors.New("lookup example.test: no such host"), want: "сервер не ответил"},
		{name: "x509 type", err: x509.UnknownAuthorityError{}, want: "сертификат сервера не принят"},
		{name: "x509 text", err: errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority"), want: "сертификат сервера не принят"},
		{name: "key", err: errors.New("сервер не принял ключ"), want: "сервер не принял ключ"},
		{name: "key wrapped", err: fmt.Errorf("ответ: %w", errors.New("сервер не принял ключ")), want: "сервер не принял ключ"},
		{name: "h2", err: errors.New("сервер не согласовал HTTP/2"), want: "сервер не согласовал HTTP/2"},
		{name: "h2 wrapped", err: fmt.Errorf("http2: %w", errors.New("сервер не согласовал HTTP/2")), want: "сервер не согласовал HTTP/2"},
		{name: "other", err: errors.New("unexpected EOF"), want: "нет связи с сервером: unexpected EOF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Explain(tc.err)
			if got != tc.want {
				t.Fatalf("Explain() = %q, хотели %q", got, tc.want)
			}
			if strings.Contains(got, "203.0.113.9") || strings.Contains(strings.ToLower(got), "psk") {
				t.Fatalf("фраза содержит лишнее: %s", got)
			}
		})
	}
	opened := Explain(&openError{err: errors.New("сервер не принял ключ")})
	if opened != "сервер не принял ключ" {
		t.Fatalf("openError: %s", opened)
	}
	long := Explain(errors.New(strings.Repeat("а", 200)))
	if !strings.HasPrefix(long, "нет связи с сервером: ") || !strings.HasSuffix(long, "…") {
		t.Fatalf("короткая причина: %s", long)
	}
	if Explain(nil) != "" {
		t.Fatal("nil")
	}
}

type silentTimeout struct{}

func (silentTimeout) Error() string   { return "waiting" }
func (silentTimeout) Timeout() bool   { return true }
func (silentTimeout) Temporary() bool { return true }
