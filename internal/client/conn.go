package client

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"veil/internal/proto"
)

// openError — не удалось открыть сессию с сервером Veil, а не целевой адрес.
type openError struct{ err error }

func (e *openError) Error() string { return e.err.Error() }

func (e *openError) Unwrap() error { return e.err }

// Dial открывает TCP к host:port через туннель и возвращает соединение после DialOK.
// host уходит в кадр как есть: клиент его не резолвит.
func (c *Client) Dial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	stream, err := c.open(ctx)
	if err != nil {
		return nil, &openError{err: err}
	}
	target, err := proto.EncodeTarget(host, port)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if err := stream.WriteFrame(proto.FrameDial, target); err != nil {
		stream.Close()
		return nil, err
	}
	typ, _, err := readFrameTimeout(ctx, stream, 30*time.Second)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if typ != proto.FrameDialOK {
		stream.Close()
		return nil, errors.New("сервер не открыл соединение")
	}
	sc := &streamConn{
		stream: stream,
		host:   host,
		port:   port,
		done:   make(chan struct{}),
	}
	// Контекст обрывает поток: у кадров нет дедлайнов сокета.
	go func() {
		select {
		case <-ctx.Done():
			sc.Close()
		case <-sc.done:
		}
	}()
	return sc, nil
}

func readFrameTimeout(ctx context.Context, stream *proto.Stream, d time.Duration) (byte, []byte, error) {
	type result struct {
		typ byte
		p   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		typ, p, err := stream.ReadFrame()
		ch <- result{typ, p, err}
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.typ, r.p, r.err
	case <-timer.C:
		stream.Close()
		return 0, nil, errors.New("таймаут ответа")
	case <-ctx.Done():
		stream.Close()
		return 0, nil, ctx.Err()
	}
}

// streamConn — TCP поверх кадров. CloseWrite шлёт FrameClose (FIN), Close рвёт поток.
type streamConn struct {
	stream      *proto.Stream
	host        string
	port        uint16
	rmu         sync.Mutex
	wmu         sync.Mutex
	pending     []byte
	readEOF     bool
	writeClosed bool
	closeOnce   sync.Once
	done        chan struct{}
}

func (c *streamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		if c.readEOF {
			return 0, io.EOF
		}
		typ, payload, err := c.stream.ReadFrame()
		if err != nil {
			return 0, err
		}
		switch typ {
		case proto.FrameData:
			if len(payload) == 0 {
				continue
			}
			c.pending = payload
		case proto.FrameClose:
			c.readEOF = true
			return 0, io.EOF
		default:
			return 0, errors.New("неожиданный кадр")
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *streamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeClosed {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > proto.MaxPayload {
			n = proto.MaxPayload
		}
		if err := c.stream.WriteFrame(proto.FrameData, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *streamConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	return c.stream.WriteFrame(proto.FrameClose, nil)
}

func (c *streamConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return c.stream.Close()
}

func (c *streamConn) LocalAddr() net.Addr { return tcpAddr("0.0.0.0:0") }
func (c *streamConn) RemoteAddr() net.Addr {
	return tcpAddr(net.JoinHostPort(c.host, strconv.Itoa(int(c.port))))
}

func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

type tcpAddr string

func (a tcpAddr) Network() string { return "tcp" }
func (a tcpAddr) String() string  { return string(a) }

func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := copyHalf(b, a); err != nil {
			a.Close()
			b.Close()
		}
	}()
	go func() {
		defer wg.Done()
		if err := copyHalf(a, b); err != nil {
			a.Close()
			b.Close()
		}
	}()
	wg.Wait()
	a.Close()
	b.Close()
}

func copyHalf(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)
	if err == nil || errors.Is(err, net.ErrClosed) {
		closeWrite(dst)
		return nil
	}
	return err
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
