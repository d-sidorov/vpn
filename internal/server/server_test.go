package server_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"veil/internal/client"
	"veil/internal/proto"
	"veil/internal/server"
	"veil/internal/tlsutil"
)

func TestProbeAndTunnel(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, 32)
	certPEM, keyPEM, err := tlsutil.Generate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvReady := make(chan string, 1)
	go func() {
		_ = server.Serve(ctx, server.Config{
			Listen:        "127.0.0.1:0",
			Certificate:   pair,
			PSK:           psk,
			AllowLoopback: true,
			OnListen: func(addr string) {
				srvReady <- addr
			},
		})
	}()
	srvAddr := waitAddr(t, srvReady)

	page := httpClient()
	resp, err := page.Get("https://" + srvAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("<html")) {
		t.Fatalf("зонд GET: %d %q", resp.StatusCode, body)
	}

	resp, err = page.Post("https://"+srvAddr+"/", "text/plain", bytes.NewReader([]byte("probe")))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("зонд POST: %d %s %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}

	echo := echoServer(t)
	cliReady := make(chan string, 1)
	go func() {
		_ = client.Run(ctx, client.Config{
			Listen:     "127.0.0.1:0",
			ServerAddr: srvAddr,
			SNI:        "127.0.0.1",
			PSK:        psk,
			Insecure:   true,
			OnListen: func(addr string) {
				cliReady <- addr
			},
		})
	}()
	socksAddr := waitAddr(t, cliReady)

	conn := socksDial(t, socksAddr, echo)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte("q"), 20000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("эхо не совпало")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	closed := closedPort(t)
	refused := socksDialExpectFail(t, socksAddr, closed)
	if !refused {
		t.Fatal("закрытый порт принят как успешный")
	}
}

func TestSecondKeyAndSamePage(t *testing.T) {
	first := bytes.Repeat([]byte{0x42}, 32)
	second := bytes.Repeat([]byte{0x43}, 32)
	foreign := bytes.Repeat([]byte{0x44}, 32)
	path := filepath.Join(t.TempDir(), "keys")
	line := base64.StdEncoding.EncodeToString(second) + "\n"
	if err := os.WriteFile(path, []byte("# люди\n"+line), 0600); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := tlsutil.Generate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvReady := make(chan string, 1)
	go func() {
		_ = server.Serve(ctx, server.Config{
			Listen:        "127.0.0.1:0",
			Certificate:   pair,
			PSK:           first,
			KeysFile:      path,
			AllowLoopback: true,
			OnListen:      func(addr string) { srvReady <- addr },
		})
	}()
	srvAddr := waitAddr(t, srvReady)

	page := httpClient()
	getBody := getPage(t, page, srvAddr)

	echo := echoServer(t)
	cliReady := make(chan string, 1)
	go func() {
		_ = client.Run(ctx, client.Config{
			Listen:     "127.0.0.1:0",
			ServerAddr: srvAddr,
			SNI:        "127.0.0.1",
			PSK:        second,
			Insecure:   true,
			OnListen:   func(addr string) { cliReady <- addr },
		})
	}()
	conn := socksDial(t, waitAddr(t, cliReady), echo)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := []byte("второй ключ")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("туннель второго ключа")
	}

	if body := postHello(t, page, srvAddr, foreign); !bytes.Equal(body, getBody) {
		t.Fatal("чужой ключ получил другую страницу")
	}

	if err := server.RemoveKey(path, second); err != nil {
		t.Fatal(err)
	}
	if body := postHello(t, page, srvAddr, second); !bytes.Equal(body, getPage(t, page, srvAddr)) {
		t.Fatal("отозванный ключ получил другую страницу")
	}
	if ctype := postHelloType(t, page, srvAddr, first); !strings.Contains(ctype, "application/octet-stream") {
		t.Fatalf("первый ключ после отзыва: %s", ctype)
	}
}

func getPage(t *testing.T, page *http.Client, addr string) []byte {
	t.Helper()
	resp, err := page.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("<html")) {
		t.Fatalf("GET: %d %q", resp.StatusCode, body)
	}
	return body
}

func postHello(t *testing.T, page *http.Client, addr string, psk []byte) []byte {
	t.Helper()
	resp, err := page.Post("https://"+addr+"/", "application/octet-stream", bytes.NewReader(sealHello(t, psk)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("hello: %d %s %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	return body
}

func postHelloType(t *testing.T, page *http.Client, addr string, psk []byte) string {
	t.Helper()
	resp, err := page.Post("https://"+addr+"/", "application/octet-stream", bytes.NewReader(sealHello(t, psk)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header.Get("Content-Type")
}

func sealHello(t *testing.T, psk []byte) []byte {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, _, err := proto.SealClientHello(psk, priv.PublicKey().Bytes(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitAddr(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case addr := <-ch:
		return addr
	case <-time.After(5 * time.Second):
		t.Fatal("адрес не появился")
		return ""
	}
}

func socksDial(t *testing.T, proxy, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	if err := socksConnect(conn, target); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	return conn
}

func socksDialExpectFail(t *testing.T, proxy, target string) bool {
	t.Helper()
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	err = socksConnect(conn, target)
	return err != nil
}

func socksConnect(conn net.Conn, target string) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host).To4()
	req := []byte{5, 1, 0, 1}
	req = append(req, ip...)
	var p [2]byte
	n, err := net.LookupPort("tcp", port)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(p[:], uint16(n))
	req = append(req, p[:]...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[1] != 0 {
		return io.ErrClosedPipe
	}
	return nil
}
