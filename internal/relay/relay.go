package relay

import (
	"errors"
	"io"
	"net"
	"sync"

	"veil/internal/proto"
)

// Pipe гоняет байты в обе стороны.
// FrameClose закрывает только запись: это FIN, ответ ещё может идти обратно.
func Pipe(local net.Conn, stream *proto.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := localToStream(local, stream); err != nil {
			stream.Close()
			local.Close()
		}
	}()
	go func() {
		defer wg.Done()
		if err := streamToLocal(stream, local); err != nil {
			local.Close()
			stream.Close()
		}
	}()
	wg.Wait()
	stream.Close()
	local.Close()
}

func localToStream(local net.Conn, stream *proto.Stream) error {
	buf := make([]byte, proto.MaxPayload)
	for {
		n, err := local.Read(buf)
		if n > 0 {
			if werr := stream.WriteFrame(proto.FrameData, buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if werr := stream.WriteFrame(proto.FrameClose, nil); werr != nil {
				return werr
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

func streamToLocal(stream *proto.Stream, local net.Conn) error {
	for {
		typ, payload, err := stream.ReadFrame()
		if err != nil {
			return err
		}
		switch typ {
		case proto.FrameData:
			if _, err := local.Write(payload); err != nil {
				return err
			}
		case proto.FrameClose:
			closeWrite(local)
			return nil
		default:
			return errors.New("неожиданный кадр")
		}
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
