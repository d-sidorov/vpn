package proto

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	PSKSize    = 32
	MaxPayload = 16 * 1024
	MaxPad     = 512

	version       byte = 1
	helloSkew          = 120 * time.Second
	maxHelloPad        = 200
	maxHelloPlain      = 1 + 8 + 32 + 24 + maxHelloPad
)

const (
	FrameDial byte = iota + 1
	FrameDialOK
	FrameDialErr
	FrameData
	FrameClose
)

// Первые байты сессии случайны и раскрываются только ключом этого сервера.
// Общей строки протокола, по которой можно узнать все установки сразу, нет.
const (
	helloC2S = "veil-v1-hello-c2s"
	helloS2C = "veil-v1-hello-s2c"
)

func ParsePSK(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		hex.DecodeString,
	} {
		b, err := dec(s)
		if err == nil && len(b) == PSKSize {
			return b, nil
		}
	}
	return nil, errors.New("psk должен быть 32 байта в base64 или hex")
}

func SealClientHello(psk, pub []byte, now time.Time) (wire, nonce []byte, err error) {
	plain, err := clientHelloPlain(pub, now)
	if err != nil {
		return nil, nil, err
	}
	aead, err := helloCipher(psk, helloC2S)
	if err != nil {
		return nil, nil, err
	}
	return sealHello(aead, plain)
}

func OpenClientHello(psk []byte, r io.Reader, now time.Time) (pub, nonce []byte, err error) {
	aead, err := helloCipher(psk, helloC2S)
	if err != nil {
		return nil, nil, err
	}
	plain, nonce, err := openHello(aead, r)
	if err != nil {
		return nil, nil, err
	}
	pub, err = parseClientHello(plain, now)
	if err != nil {
		return nil, nil, err
	}
	return pub, nonce, nil
}

func SealServerHello(psk, pub, clientNonce []byte, now time.Time) (wire, nonce []byte, err error) {
	plain, err := serverHelloPlain(pub, clientNonce, now)
	if err != nil {
		return nil, nil, err
	}
	aead, err := helloCipher(psk, helloS2C)
	if err != nil {
		return nil, nil, err
	}
	return sealHello(aead, plain)
}

func OpenServerHello(psk []byte, r io.Reader, clientNonce []byte, now time.Time) (pub, nonce []byte, err error) {
	aead, err := helloCipher(psk, helloS2C)
	if err != nil {
		return nil, nil, err
	}
	plain, nonce, err := openHello(aead, r)
	if err != nil {
		return nil, nil, err
	}
	pub, err = parseServerHello(plain, clientNonce, now)
	if err != nil {
		return nil, nil, err
	}
	return pub, nonce, nil
}

func NewSession(psk, shared, clientPub, serverPub, clientNonce, serverNonce []byte) (c2s, s2c cipher.AEAD, err error) {
	if len(psk) != PSKSize || len(shared) == 0 || isZero(shared) {
		return nil, nil, errors.New("слабые ключи сессии")
	}
	if len(clientPub) != 32 || len(serverPub) != 32 || len(clientNonce) != 24 || len(serverNonce) != 24 {
		return nil, nil, errors.New("неполное рукопожатие")
	}
	salt := make([]byte, 0, len(psk)+32+32+24+24)
	salt = append(salt, psk...)
	salt = append(salt, clientPub...)
	salt = append(salt, serverPub...)
	salt = append(salt, clientNonce...)
	salt = append(salt, serverNonce...)
	c2s, err = sessionCipher(shared, salt, "veil-v1-c2s")
	if err != nil {
		return nil, nil, err
	}
	s2c, err = sessionCipher(shared, salt, "veil-v1-s2c")
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

func EncodeTarget(host string, port uint16) ([]byte, error) {
	if port == 0 || strings.ContainsAny(host, " \r\n") {
		return nil, errors.New("некорректный адрес")
	}
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append([]byte{1}, ip4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if host == "" || len(host) > 255 {
			return nil, errors.New("некорректное имя")
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return append(b, byte(port>>8), byte(port)), nil
}

func DecodeTarget(p []byte) (string, uint16, error) {
	if len(p) < 1 {
		return "", 0, errors.New("пустой адрес")
	}
	var host string
	var rest []byte
	switch p[0] {
	case 1:
		if len(p) != 7 {
			return "", 0, errors.New("плохой IPv4")
		}
		host = net.IP(p[1:5]).String()
		rest = p[5:]
	case 4:
		if len(p) != 19 {
			return "", 0, errors.New("плохой IPv6")
		}
		host = net.IP(p[1:17]).String()
		rest = p[17:]
	case 3:
		if len(p) < 2 {
			return "", 0, errors.New("плохое имя")
		}
		n := int(p[1])
		if n == 0 || len(p) != 2+n+2 {
			return "", 0, errors.New("плохое имя")
		}
		host = string(p[2 : 2+n])
		rest = p[2+n:]
	default:
		return "", 0, errors.New("неизвестный тип адреса")
	}
	port := binary.BigEndian.Uint16(rest)
	if port == 0 || strings.ContainsAny(host, " \r\n") {
		return "", 0, errors.New("некорректный адрес")
	}
	return host, port, nil
}

type Stream struct {
	reader io.Reader
	writer io.Writer
	close  func() error
	send   cipher.AEAD
	recv   cipher.AEAD
	sendN  uint64
	recvN  uint64
	wmu    sync.Mutex
	rmu    sync.Mutex
	once   sync.Once
}

func NewStream(r io.Reader, w io.Writer, send, recv cipher.AEAD, closeFn func() error) *Stream {
	return &Stream{reader: r, writer: w, close: closeFn, send: send, recv: recv}
}

func (s *Stream) Close() error {
	var err error
	s.once.Do(func() {
		if s.close != nil {
			err = s.close()
		}
	})
	return err
}

func (s *Stream) WriteFrame(typ byte, payload []byte) error {
	if len(payload) > MaxPayload {
		return errors.New("кадр слишком большой")
	}
	pad, err := randInt(MaxPad + 1)
	if err != nil {
		return err
	}
	plain := make([]byte, 3+len(payload)+pad)
	plain[0] = typ
	binary.BigEndian.PutUint16(plain[1:3], uint16(pad))
	copy(plain[3:], payload)

	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.sendN == ^uint64(0) {
		return errors.New("счётчик кадров исчерпан")
	}
	slen := len(plain) + s.send.Overhead()
	if slen > 65535 {
		return errors.New("кадр не влезает")
	}
	var lenb [2]byte
	binary.BigEndian.PutUint16(lenb[:], uint16(slen))
	sealed := s.send.Seal(nil, nonce12(s.sendN), plain, lenb[:])
	s.sendN++
	buf := make([]byte, 2+len(sealed))
	copy(buf, lenb[:])
	copy(buf[2:], sealed)
	_, err = s.writer.Write(buf)
	return err
}

func (s *Stream) ReadFrame() (byte, []byte, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	var lenb [2]byte
	if _, err := io.ReadFull(s.reader, lenb[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(lenb[:]))
	maxSealed := 3 + MaxPayload + MaxPad + s.recv.Overhead()
	if n < s.recv.Overhead() || n > maxSealed {
		return 0, nil, errors.New("длина кадра")
	}
	sealed := make([]byte, n)
	if _, err := io.ReadFull(s.reader, sealed); err != nil {
		return 0, nil, err
	}
	plain, err := s.recv.Open(nil, nonce12(s.recvN), sealed, lenb[:])
	if err != nil {
		return 0, nil, err
	}
	s.recvN++
	if len(plain) < 3 {
		return 0, nil, errors.New("короткий кадр")
	}
	pad := int(binary.BigEndian.Uint16(plain[1:3]))
	if pad > MaxPad {
		return 0, nil, errors.New("padding кадра")
	}
	body := len(plain) - 3 - pad
	if body < 0 || body > MaxPayload {
		return 0, nil, errors.New("тело кадра")
	}
	payload := make([]byte, body)
	copy(payload, plain[3:3+body])
	return plain[0], payload, nil
}

func clientHelloPlain(pub []byte, now time.Time) ([]byte, error) {
	if len(pub) != 32 {
		return nil, errors.New("публичный ключ")
	}
	pad, err := randInt(maxHelloPad + 1)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 1+8+32+pad)
	plain[0] = version
	binary.BigEndian.PutUint64(plain[1:9], uint64(now.Unix()))
	copy(plain[9:41], pub)
	return plain, nil
}

func serverHelloPlain(pub, clientNonce []byte, now time.Time) ([]byte, error) {
	if len(pub) != 32 || len(clientNonce) != 24 {
		return nil, errors.New("ответ сервера")
	}
	pad, err := randInt(maxHelloPad + 1)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 1+8+32+24+pad)
	plain[0] = version
	binary.BigEndian.PutUint64(plain[1:9], uint64(now.Unix()))
	copy(plain[9:41], pub)
	copy(plain[41:65], clientNonce)
	return plain, nil
}

func parseClientHello(plain []byte, now time.Time) ([]byte, error) {
	if len(plain) < 41 || len(plain) > maxHelloPlain || plain[0] != version {
		return nil, errors.New("рукопожатие")
	}
	if err := checkTime(plain[1:9], now); err != nil {
		return nil, err
	}
	pub := make([]byte, 32)
	copy(pub, plain[9:41])
	return pub, nil
}

func parseServerHello(plain, clientNonce []byte, now time.Time) ([]byte, error) {
	if len(plain) < 65 || len(plain) > maxHelloPlain || plain[0] != version {
		return nil, errors.New("ответ сервера")
	}
	if err := checkTime(plain[1:9], now); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(plain[41:65], clientNonce) != 1 {
		return nil, errors.New("ответ не к этому запросу")
	}
	pub := make([]byte, 32)
	copy(pub, plain[9:41])
	return pub, nil
}

func checkTime(b []byte, now time.Time) error {
	ts := time.Unix(int64(binary.BigEndian.Uint64(b)), 0)
	d := now.Sub(ts)
	if d < 0 {
		d = -d
	}
	if d > helloSkew {
		return errors.New("время рукопожатия")
	}
	return nil
}

func helloCipher(psk []byte, info string) (cipher.AEAD, error) {
	if len(psk) != PSKSize {
		return nil, errors.New("psk")
	}
	key, err := hkdf.Key(sha256.New, psk, nil, info, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(key)
}

func sessionCipher(shared, salt []byte, info string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, salt, info, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

func sealHello(aead cipher.AEAD, plain []byte) (wire, nonce []byte, err error) {
	nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	sealed := aead.Seal(nil, nonce, plain, nil)
	if len(sealed) > 512+aead.Overhead() {
		return nil, nil, errors.New("рукопожатие длиннее допустимого")
	}
	wire = make([]byte, len(nonce)+2+len(sealed))
	copy(wire, nonce)
	binary.BigEndian.PutUint16(wire[len(nonce):], uint16(len(sealed)))
	copy(wire[len(nonce)+2:], sealed)
	return wire, nonce, nil
}

// ReadHello читает одно hello с теми же пределами длины, что и расшифровка.
// Сервер пробует несколько ключей, а тело POST можно прочитать только один раз.
func ReadHello(r io.Reader) ([]byte, error) {
	return readHello(r, chacha20poly1305.NonceSizeX, chacha20poly1305.Overhead)
}

func openHello(aead cipher.AEAD, r io.Reader) (plain, nonce []byte, err error) {
	wire, err := readHello(r, aead.NonceSize(), aead.Overhead())
	if err != nil {
		return nil, nil, err
	}
	nonce = append([]byte(nil), wire[:aead.NonceSize()]...)
	sealed := wire[aead.NonceSize()+2:]
	plain, err = aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, nil, errors.New("рукопожатие")
	}
	return plain, nonce, nil
}

func readHello(r io.Reader, nonceSize, overhead int) ([]byte, error) {
	buf := make([]byte, nonceSize+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(buf[nonceSize:]))
	if n < overhead || n > 512+overhead {
		return nil, errors.New("рукопожатие")
	}
	sealed := make([]byte, n)
	if _, err := io.ReadFull(r, sealed); err != nil {
		return nil, err
	}
	return append(buf, sealed...), nil
}

func nonce12(n uint64) []byte {
	var b [12]byte
	binary.BigEndian.PutUint64(b[4:], n)
	return b[:]
}

func randInt(n int) (int, error) {
	if n <= 1 {
		return 0, nil
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

func isZero(b []byte) bool {
	var x byte
	for _, v := range b {
		x |= v
	}
	return x == 0
}
