package proto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func testPSK(t *testing.T) []byte {
	t.Helper()
	psk := bytes.Repeat([]byte{0x11}, PSKSize)
	return psk
}

func TestHandshakeFrame(t *testing.T) {
	psk := testPSK(t)
	now := time.Now()
	cpriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, cnonce, err := SealClientHello(psk, cpriv.PublicKey().Bytes(), now)
	if err != nil {
		t.Fatal(err)
	}
	gotWire, err := ReadHello(bytes.NewReader(wire))
	if err != nil || !bytes.Equal(gotWire, wire) {
		t.Fatal("ReadHello", err)
	}
	pub, gotNonce, err := OpenClientHello(psk, bytes.NewReader(wire), now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, cpriv.PublicKey().Bytes()) || !bytes.Equal(cnonce, gotNonce) {
		t.Fatal("клиентское рукопожатие разошлось")
	}

	swire, snonce, err := SealServerHello(psk, spriv.PublicKey().Bytes(), cnonce, now)
	if err != nil {
		t.Fatal(err)
	}
	spub, gotS, err := OpenServerHello(psk, bytes.NewReader(swire), cnonce, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spub, spriv.PublicKey().Bytes()) || !bytes.Equal(snonce, gotS) {
		t.Fatal("ответ сервера разошёлся")
	}

	shared, err := cpriv.ECDH(spriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	c2s, s2c, err := NewSession(psk, shared, pub, spub, cnonce, snonce)
	if err != nil {
		t.Fatal(err)
	}
	client, server := netPair()
	cs := NewStream(client, client, c2s, s2c, client.Close)
	ss := NewStream(server, server, s2c, c2s, server.Close)
	payload := []byte("через два кадра")
	if err := cs.WriteFrame(FrameData, payload); err != nil {
		t.Fatal(err)
	}
	typ, got, err := ss.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if typ != FrameData || !bytes.Equal(got, payload) {
		t.Fatalf("кадр %d %q", typ, got)
	}
	wire[len(wire)-1] ^= 0xff
	if _, _, err := OpenClientHello(psk, bytes.NewReader(wire), now); err == nil {
		t.Fatal("порченый пакет принят")
	}
}

func TestReadHelloRejectsLong(t *testing.T) {
	head := make([]byte, chacha20poly1305.NonceSizeX+2)
	binary.BigEndian.PutUint16(head[chacha20poly1305.NonceSizeX:], uint16(512+chacha20poly1305.Overhead+1))
	_, err := ReadHello(io.MultiReader(bytes.NewReader(head), failIfRead{}))
	if err == nil || err.Error() == "хвост прочитан" {
		t.Fatal(err)
	}
}

type failIfRead struct{}

func (failIfRead) Read([]byte) (int, error) {
	return 0, errors.New("хвост прочитан")
}

func TestWrongPSKAndSkew(t *testing.T) {
	psk := testPSK(t)
	other := bytes.Repeat([]byte{0x22}, PSKSize)
	now := time.Now()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, _, err := SealClientHello(psk, priv.PublicKey().Bytes(), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenClientHello(other, bytes.NewReader(wire), now); err == nil {
		t.Fatal("чужой psk принят")
	}
	if _, _, err := OpenClientHello(psk, bytes.NewReader(wire), now.Add(time.Hour)); err == nil {
		t.Fatal("старое рукопожатие принято")
	}
}

func TestTarget(t *testing.T) {
	b, err := EncodeTarget("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := DecodeTarget(b)
	if err != nil || host != "example.com" || port != 443 {
		t.Fatalf("%s %d %v", host, port, err)
	}
	b, err = EncodeTarget("127.0.0.1", 80)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err = DecodeTarget(b)
	if err != nil || host != "127.0.0.1" || port != 80 {
		t.Fatalf("%s %d %v", host, port, err)
	}
}

type pipe struct {
	r *bytes.Buffer
	w *bytes.Buffer
}

func (p pipe) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p pipe) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p pipe) Close() error                { return nil }

func netPair() (client, server pipe) {
	a, b := &bytes.Buffer{}, &bytes.Buffer{}
	return pipe{r: b, w: a}, pipe{r: a, w: b}
}
