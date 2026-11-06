package client

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"veil/internal/dnsproxy"
	"veil/internal/httpproxy"
	"veil/internal/proto"
	"veil/internal/socks5"
)

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

type Config struct {
	Listen       string
	HTTPListen   string
	DNSListen    string
	ServerAddr   string
	SNI          string
	PSK          []byte
	Insecure     bool
	OnListen     func(addr string)
	OnHTTPListen func(addr string)
	OnDNSListen  func(addr string)
}

type Client struct {
	cfg  Config
	http *http.Client
	base context.Context
}

func Run(ctx context.Context, cfg Config) error {
	c, err := newClient(ctx, cfg)
	if err != nil {
		return err
	}
	cfg = c.cfg
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	var httpLn net.Listener
	if !disabled(cfg.HTTPListen) {
		httpLn, err = net.Listen("tcp", cfg.HTTPListen)
		if err != nil {
			ln.Close()
			return err
		}
	}
	var dnsPC net.PacketConn
	if !disabled(cfg.DNSListen) {
		dnsPC, err = net.ListenPacket("udp", cfg.DNSListen)
		if err != nil {
			ln.Close()
			if httpLn != nil {
				httpLn.Close()
			}
			return err
		}
	}
	closeAll := func() {
		ln.Close()
		if httpLn != nil {
			httpLn.Close()
		}
		if dnsPC != nil {
			dnsPC.Close()
		}
	}
	go func() {
		<-ctx.Done()
		closeAll()
	}()

	errCh := make(chan error, 3)
	n := 1
	go func() { errCh <- serveSOCKS(ctx, ln, c.handle) }()
	if httpLn != nil {
		n++
		go func() { errCh <- httpproxy.Serve(httpLn, c.dialApp) }()
	}
	if dnsPC != nil {
		n++
		go func() { errCh <- dnsproxy.Serve(ctx, dnsPC, c.Dial) }()
	}
	if cfg.OnListen != nil {
		cfg.OnListen(ln.Addr().String())
	}
	if cfg.OnHTTPListen != nil {
		addr := ""
		if httpLn != nil {
			addr = httpLn.Addr().String()
		}
		cfg.OnHTTPListen(addr)
	}
	if dnsPC != nil && cfg.OnDNSListen != nil {
		cfg.OnDNSListen(dnsPC.LocalAddr().String())
	}

	var first error
	for i := 0; i < n; i++ {
		err := <-errCh
		closeAll()
		if err != nil && first == nil && ctx.Err() == nil {
			first = err
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	return first
}

func disabled(addr string) bool {
	return addr == "" || addr == "-"
}

func serveSOCKS(ctx context.Context, ln net.Listener, handle func(net.Conn)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handle(conn)
	}
}

func (c *Client) handle(conn net.Conn) {
	defer conn.Close()
	host, port, err := socks5.ReadRequest(conn)
	if err != nil {
		if !errors.Is(err, socks5.ErrHandled) {
			_ = socks5.Reply(conn, false)
		}
		return
	}
	remote, err := c.dialApp(c.base, host, port)
	if err != nil {
		_ = socks5.Reply(conn, false)
		return
	}
	defer remote.Close()
	if err := socks5.Reply(conn, true); err != nil {
		return
	}
	splice(conn, remote)
}

func newClient(ctx context.Context, cfg Config) (*Client, error) {
	if len(cfg.PSK) != proto.PSKSize {
		return nil, errors.New("psk должен быть 32 байта")
	}
	addr, err := withPort(cfg.ServerAddr, "443")
	if err != nil {
		return nil, err
	}
	cfg.ServerAddr = addr
	cfg.Listen = strings.TrimSpace(cfg.Listen)
	cfg.HTTPListen = strings.TrimSpace(cfg.HTTPListen)
	cfg.DNSListen = strings.TrimSpace(cfg.DNSListen)
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}
	c := &Client{cfg: cfg, base: ctx}
	c.http = &http.Client{
		Transport: &http2.Transport{
			DialTLSContext:     c.dialTLS,
			DisableCompression: true,
			ReadIdleTimeout:    30 * time.Second,
			PingTimeout:        15 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c, nil
}

// Check один раз проходит рукопожатие и сразу закрывает поток, без кадра Dial.
// Дедлайн нужен, когда у ctx его нет: иначе зависший TCP не отдаёт фразу про сервер.
func Check(ctx context.Context, cfg Config) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
	}
	c, err := newClient(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeIdle(c)
	stream, err := c.open(ctx)
	if err != nil {
		return err
	}
	stream.Close()
	return nil
}

func closeIdle(c *Client) {
	tr, ok := c.http.Transport.(*http2.Transport)
	if ok {
		tr.CloseIdleConnections()
	}
}

func (c *Client) dialApp(ctx context.Context, host string, port uint16) (net.Conn, error) {
	conn, err := c.Dial(ctx, host, port)
	if err != nil {
		logOpenFailure(err)
	}
	return conn, err
}

func logOpenFailure(err error) {
	var opened *openError
	if !errors.As(err, &opened) {
		return
	}
	log.Print(Explain(err))
}

func (c *Client) open(parent context.Context) (*proto.Stream, error) {
	ctx, cancel := context.WithCancel(parent)
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), pr)
	if err != nil {
		cancel()
		pw.Close()
		return nil, err
	}
	// Неизвестная длина, иначе клиент не отправит тело, пока его не дочитают целиком.
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", chromeUA)
	req.Header.Set("Accept", "*/*")

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		cancel()
		pw.Close()
		return nil, err
	}
	wire, clientNonce, err := proto.SealClientHello(c.cfg.PSK, priv.PublicKey().Bytes(), time.Now())
	if err != nil {
		cancel()
		pw.Close()
		return nil, err
	}
	wrote := make(chan error, 1)
	go func() {
		_, err := pw.Write(wire)
		wrote <- err
	}()

	resp, err := c.http.Do(req)
	if err != nil {
		cancel()
		pw.Close()
		return nil, err
	}
	fail := func(err error) (*proto.Stream, error) {
		cancel()
		resp.Body.Close()
		pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "application/octet-stream") {
		return fail(errors.New("сервер не принял ключ"))
	}
	if err := <-wrote; err != nil {
		return fail(err)
	}
	serverPub, serverNonce, err := proto.OpenServerHello(c.cfg.PSK, resp.Body, clientNonce, time.Now())
	if err != nil {
		return fail(err)
	}
	peer, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return fail(err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return fail(err)
	}
	c2s, s2c, err := proto.NewSession(c.cfg.PSK, shared, priv.PublicKey().Bytes(), serverPub, clientNonce, serverNonce)
	if err != nil {
		return fail(err)
	}
	return proto.NewStream(resp.Body, pw, c2s, s2c, func() error {
		cancel()
		resp.Body.Close()
		return pw.Close()
	}), nil
}

// ClientHello виден фильтру в открытом виде, поэтому он повторяет Chrome, а не Go.
// TCP-адрес и имя в сертификате разделены: к машине можно идти по IP, а SNI оставить доменом.
func (c *Client) dialTLS(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, c.cfg.ServerAddr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(raw, &utls.Config{
		ServerName:         c.sni(),
		InsecureSkipVerify: c.cfg.Insecure,
	}, utls.HelloChrome_Auto)
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	if uconn.ConnectionState().NegotiatedProtocol != "h2" {
		uconn.Close()
		return nil, errors.New("сервер не согласовал HTTP/2")
	}
	return &utlsConn{UConn: uconn}, nil
}

func (c *Client) sni() string {
	if c.cfg.SNI != "" {
		return c.cfg.SNI
	}
	host, _, err := net.SplitHostPort(c.cfg.ServerAddr)
	if err != nil {
		return c.cfg.ServerAddr
	}
	return host
}

func (c *Client) endpoint() string {
	host := c.sni()
	_, port, err := net.SplitHostPort(c.cfg.ServerAddr)
	if err != nil || port == "" || port == "443" {
		return "https://" + host + "/"
	}
	return "https://" + net.JoinHostPort(host, port) + "/"
}

func withPort(addr, port string) (string, error) {
	if addr == "" {
		return "", errors.New("не задан адрес сервера")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, port), nil
	}
	return addr, nil
}

// http2 смотрит состояние TLS через интерфейс crypto/tls, а uTLS возвращает свой тип.
type utlsConn struct {
	*utls.UConn
}

func (c *utlsConn) ConnectionState() tls.ConnectionState {
	st := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     st.Version,
		HandshakeComplete:           st.HandshakeComplete,
		DidResume:                   st.DidResume,
		CipherSuite:                 st.CipherSuite,
		NegotiatedProtocol:          st.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  st.NegotiatedProtocolIsMutual,
		ServerName:                  st.ServerName,
		PeerCertificates:            st.PeerCertificates,
		VerifiedChains:              st.VerifiedChains,
		SignedCertificateTimestamps: st.SignedCertificateTimestamps,
		OCSPResponse:                st.OCSPResponse,
	}
}

func (c *utlsConn) NetConn() net.Conn { return c.UConn.NetConn() }
