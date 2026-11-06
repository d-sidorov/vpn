package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	msgBadRequest = "неподдерживаемый запрос"
	msgBadGateway = "не удалось подключиться"
)

// Dial открывает TCP к host:port. Имя передаётся как в запросе, без локального резолва.
type DialFunc func(ctx context.Context, host string, port uint16) (net.Conn, error)

// Serve принимает HTTP-прокси на уже открытом слушателе.
func Serve(ln net.Listener, dial DialFunc) error {
	if dial == nil {
		return errors.New("не задан набор соединений")
	}
	srv := &http.Server{
		Handler:           &handler{dial: dial},
		ReadHeaderTimeout: 30 * time.Second,
	}
	err := srv.Serve(ln)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type handler struct {
	dial DialFunc
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.connect(w, r)
		return
	}
	h.forward(w, r)
}

func (h *handler) connect(w http.ResponseWriter, r *http.Request) {
	hostport := r.Host
	if hostport == "" && r.URL != nil {
		hostport = r.URL.Host
	}
	host, port, err := splitHost(hostport, 443)
	if err != nil {
		http.Error(w, msgBadRequest, http.StatusBadRequest)
		return
	}
	up, err := h.dial(r.Context(), host, port)
	if err != nil {
		http.Error(w, msgBadGateway, http.StatusBadGateway)
		return
	}
	defer up.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, msgBadGateway, http.StatusBadGateway)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		http.Error(w, msgBadGateway, http.StatusBadGateway)
		return
	}
	defer client.Close()
	if _, err := io.WriteString(rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	splice(client, rw.Reader, up)
}

func (h *handler) forward(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, msgBadRequest, http.StatusBadRequest)
		return
	}
	host := r.URL.Hostname()
	if host == "" {
		http.Error(w, msgBadRequest, http.StatusBadRequest)
		return
	}
	port := uint16(80)
	if raw := r.URL.Port(); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || n == 0 {
			http.Error(w, msgBadRequest, http.StatusBadRequest)
			return
		}
		port = uint16(n)
	}

	up, err := h.dial(r.Context(), host, port)
	if err != nil {
		http.Error(w, msgBadGateway, http.StatusBadGateway)
		return
	}
	defer up.Close()

	out := r.Clone(r.Context())
	out.Header = stripHop(r.Header)
	out.Header.Set("Connection", "close")
	if err := out.Write(up); err != nil {
		http.Error(w, msgBadGateway, http.StatusBadGateway)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), out)
	if err != nil {
		http.Error(w, msgBadGateway, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	hdr := w.Header()
	for k, vals := range stripHop(resp.Header) {
		for _, v := range vals {
			hdr.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_ = http.NewResponseController(w).Flush()
	_, _ = io.Copy(w, resp.Body)
}

func splitHost(hostport string, def uint16) (string, uint16, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", 0, errors.New("пустое имя")
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") && len(hostport) > 2 {
			return hostport[1 : len(hostport)-1], def, nil
		}
		if strings.Contains(hostport, " ") {
			return "", 0, err
		}
		return hostport, def, nil
	}
	if host == "" {
		return "", 0, errors.New("пустое имя")
	}
	n, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || n == 0 {
		return "", 0, errors.New("порт")
	}
	return host, uint16(n), nil
}

func stripHop(h http.Header) http.Header {
	out := h.Clone()
	if out == nil {
		out = make(http.Header)
	}
	var extra []string
	for _, v := range out.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				extra = append(extra, f)
			}
		}
	}
	for _, k := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		out.Del(k)
	}
	for _, k := range extra {
		out.Del(k)
	}
	return out
}

func splice(left net.Conn, leftR io.Reader, right net.Conn) {
	if leftR == nil {
		leftR = left
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(right, leftR)
		if err == nil || errors.Is(err, net.ErrClosed) {
			closeWrite(right)
			return
		}
		right.Close()
		left.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(left, right)
		if err == nil || errors.Is(err, net.ErrClosed) {
			closeWrite(left)
			return
		}
		left.Close()
		right.Close()
	}()
	wg.Wait()
	left.Close()
	right.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
