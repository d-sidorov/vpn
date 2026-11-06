package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("локальный резолвер")
		},
	}
	os.Exit(m.Run())
}

func startProxy(t *testing.T, dial DialFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { _ = Serve(ln, dial) }()
	return ln.Addr().String()
}

func TestConnectHostname(t *testing.T) {
	got := make(chan string, 1)
	addr := startProxy(t, func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		got <- net.JoinHostPort(host, strconv.Itoa(int(port)))
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			_, _ = io.Copy(b, b)
		}()
		return a, nil
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("статус: %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	select {
	case hostport := <-got:
		host, port, err := net.SplitHostPort(hostport)
		if err != nil || host != "example.com" || port != "443" || net.ParseIP(host) != nil {
			t.Fatalf("dial: %s", hostport)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial не вызван")
	}
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("эхо: %q", buf)
	}
}

func TestAbsoluteURLHostname(t *testing.T) {
	type hit struct {
		host string
		port uint16
		body string
		hdr  string
	}
	hits := make(chan hit, 1)
	dialed := make(chan struct{})
	addr := startProxy(t, func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		close(dialed)
		srv, cli := net.Pipe()
		go func() {
			defer srv.Close()
			req, err := http.ReadRequest(bufio.NewReader(srv))
			if err != nil {
				hits <- hit{host: host, port: port}
				return
			}
			b, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()
			hits <- hit{host: host, port: port, body: string(b), hdr: req.Host}
			io.WriteString(srv, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}()
		return cli, nil
	})

	pr, pw := io.Pipe()
	go func() {
		<-dialed
		_, _ = pw.Write([]byte("hi"))
		_ = pw.Close()
	}()
	req, err := http.NewRequest(http.MethodPost, "http://example.com/path", pr)
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})},
		Timeout:   3 * time.Second,
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("статус %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("тело: %q", body)
	}
	select {
	case h := <-hits:
		if h.host != "example.com" || h.port != 80 || net.ParseIP(h.host) != nil {
			t.Fatalf("dial: %s:%d", h.host, h.port)
		}
		if h.hdr != "example.com" || h.body != "hi" {
			t.Fatalf("запрос: host %q body %q", h.hdr, h.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial не вызван")
	}
}

func TestDialErrorIs502(t *testing.T) {
	const secret = "veil-server.example psk=supersecret"
	dial := func(context.Context, string, uint16) (net.Conn, error) {
		return nil, errors.New("dial tcp " + secret)
	}
	addr := startProxy(t, dial)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("статус %d", resp.StatusCode)
	}
	if bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte("psk")) {
		t.Fatalf("утечка: %q", body)
	}

	cl := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})},
		Timeout:   3 * time.Second,
	}
	resp, err = cl.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("GET статус %d", resp.StatusCode)
	}
	if bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte("example.com")) {
		t.Fatalf("утечка GET: %q", body)
	}
}
