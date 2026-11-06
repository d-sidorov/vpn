package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"veil/internal/proto"
	"veil/internal/relay"
)

type Config struct {
	Listen         string
	Certificate    tls.Certificate
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	NextProtos     []string
	PSK            []byte
	KeysFile       string
	AllowLoopback  bool
	OnListen       func(addr string)
}

type Server struct {
	static        [][]byte
	filePath      string
	fileKeys      [][]byte
	fileMtime     time.Time
	page          []byte
	readErrLogged bool
	allowLoopback bool
	mu            sync.Mutex
	replay        replay
}

func Serve(ctx context.Context, cfg Config) error {
	s, err := newServer(cfg)
	if err != nil {
		return err
	}
	if cfg.GetCertificate == nil && len(cfg.Certificate.Certificate) == 0 {
		return errors.New("нужен сертификат")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	next := cfg.NextProtos
	if len(next) == 0 {
		next = []string{"h2", "http/1.1"}
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: next,
	}
	if cfg.GetCertificate != nil {
		tlsCfg.GetCertificate = cfg.GetCertificate
	} else {
		tlsCfg.Certificates = []tls.Certificate{cfg.Certificate}
	}
	srv := &http.Server{
		Handler:           s,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		ln.Close()
		return err
	}
	if cfg.OnListen != nil {
		cfg.OnListen(ln.Addr().String())
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(tls.NewListener(ln, tlsCfg))
	}()
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Body != nil && s.accept(w, r) {
		return
	}
	// Любой другой запрос, включая неверный ключ, получает ту же страницу.
	// Активный зонд не должен отличить порт от обычного сайта.
	_, page := s.snapshot()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page)
}

func (s *Server) accept(w http.ResponseWriter, r *http.Request) bool {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(10 * time.Second))
	keys, _ := s.snapshot()
	wire, err := proto.ReadHello(r.Body)
	if err != nil {
		return false
	}
	now := time.Now()
	var pub, clientNonce, psk []byte
	for _, key := range keys {
		p, n, err := proto.OpenClientHello(key, bytes.NewReader(wire), now)
		if err != nil {
			continue
		}
		pub, clientNonce, psk = p, n, key
		break
	}
	if psk == nil || !s.replay.add(clientNonce, now) {
		return false
	}
	_ = rc.SetReadDeadline(time.Time{})

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return false
	}
	peer, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return false
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return false
	}
	hello, serverNonce, err := proto.SealServerHello(psk, priv.PublicKey().Bytes(), clientNonce, time.Now())
	if err != nil {
		return false
	}
	c2s, s2c, err := proto.NewSession(psk, shared, pub, priv.PublicKey().Bytes(), clientNonce, serverNonce)
	if err != nil {
		return false
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fw := flushWriter{w: w, flush: func() { _ = rc.Flush() }}
	if _, err := fw.Write(hello); err != nil {
		return true
	}

	stream := proto.NewStream(r.Body, fw, s2c, c2s, func() error {
		return r.Body.Close()
	})
	defer stream.Close()

	_ = rc.SetReadDeadline(time.Now().Add(30 * time.Second))
	typ, payload, err := stream.ReadFrame()
	_ = rc.SetReadDeadline(time.Time{})
	if err != nil || typ != proto.FrameDial {
		return true
	}
	host, port, err := proto.DecodeTarget(payload)
	if err != nil {
		_ = stream.WriteFrame(proto.FrameDialErr, nil)
		return true
	}
	dst, err := s.dialTarget(r.Context(), host, port)
	if err != nil {
		log.Printf("dial: %v", err)
		_ = stream.WriteFrame(proto.FrameDialErr, nil)
		return true
	}
	if err := stream.WriteFrame(proto.FrameDialOK, nil); err != nil {
		dst.Close()
		return true
	}
	relay.Pipe(dst, stream)
	return true
}

func (s *Server) dialTarget(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if port == 0 {
		return nil, errors.New("порт 0")
	}
	ips, err := s.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	var last error
	for _, ip := range ips {
		if !s.allow(ip) {
			last = errors.New("адрес запрещён")
			continue
		}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("нет адреса")
	}
	return nil, last
}

func (s *Server) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// Loopback и link-local закрыты: утёкший PSK не должен открывать сервисы самой машины.
func (s *Server) allow(ip net.IP) bool {
	if ip == nil || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsLoopback() && !s.allowLoopback {
		return false
	}
	return true
}

type flushWriter struct {
	w     io.Writer
	flush func()
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if f.flush != nil {
		f.flush()
	}
	return n, err
}

type replay struct {
	mu   sync.Mutex
	seen map[[24]byte]time.Time
}

func (r *replay) add(nonce []byte, now time.Time) bool {
	if len(nonce) != 24 {
		return false
	}
	var key [24]byte
	copy(key[:], nonce)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = make(map[[24]byte]time.Time)
	}
	cutoff := now.Add(-4 * time.Minute)
	for k, ts := range r.seen {
		if ts.Before(cutoff) {
			delete(r.seen, k)
		}
	}
	if _, ok := r.seen[key]; ok {
		return false
	}
	r.seen[key] = now
	return true
}
