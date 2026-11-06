package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"veil/internal/autostart"
	"veil/internal/client"
	"veil/internal/profile"
	"veil/internal/proto"
	"veil/internal/server"
	"veil/internal/tlsutil"
	"veil/internal/tray"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		if handled, err := launchWithoutArgs(); handled {
			return err
		}
		usage()
		return errors.New("нужна команда")
	}
	switch args[0] {
	case "keygen":
		return keygen()
	case "cert":
		return cert(args[1:])
	case "serve":
		return serve(args[1:])
	case "revoke":
		return revoke(args[1:])
	case "connect":
		return connect(args[1:])
	case "autostart":
		return autostartCmd(args[1:])
	case "link":
		return link(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("неизвестная команда %q", args[0])
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `veil — туннель, который снаружи выглядит как обычный HTTPS

  veil keygen
  veil cert -host ИМЯ -cert cert.pem -key key.pem
  veil serve -listen :443 -cert cert.pem -key key.pem -psk КЛЮЧ [-keys ФАЙЛ]
  veil serve -listen :443 -acme-domain ДОМЕН -acme-accept [-acme-cache КАТАЛОГ] [-acme-http :80] -keys ФАЙЛ
  veil revoke -keys ФАЙЛ -psk КЛЮЧ
  veil connect -server ХОСТ:443 -psk КЛЮЧ [-sni ИМЯ] [-listen 127.0.0.1:1080] [-http 127.0.0.1:8080] [-dns АДРЕС] [-insecure] [-tray]
  veil connect -config ФАЙЛ.json
  veil connect -url ССЫЛКА
  veil autostart on -config ФАЙЛ.json
  veil autostart off
  veil link -server ХОСТ:443 -psk КЛЮЧ [-sni ИМЯ] [-insecure]

Для обхода блокировок нужен свой сервер, домен и сертификат, которому доверяет система.
Самоподписанный сертификат подходит только для проверки на своей машине.
Клиент поднимает локальный SOCKS5 и HTTP-прокси. Системный прокси и DNS программа не меняет.
На Windows значок в трее включён. -tray=false оставляет только консоль. Автозапуск читает файл настроек и не пишет ключ в реестр.
Двойной щелчок по veil.exe ищет client.json в той же папке и подключается. Из консоли без команды печатается эта справка.
`)
}

func keygen() error {
	var b [proto.PSKSize]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(b[:]))
	return nil
}

func cert(args []string) error {
	fs := flag.NewFlagSet("cert", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	host := fs.String("host", "", "домен или IP в сертификате")
	certPath := fs.String("cert", "cert.pem", "куда записать сертификат")
	keyPath := fs.String("key", "key.pem", "куда записать ключ")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return errors.New("нужен -host")
	}
	if exists(*certPath) || exists(*keyPath) {
		return errors.New("cert или key уже существуют")
	}
	certPEM, keyPEM, err := tlsutil.Generate(*host)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*certPath, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(*keyPath, keyPEM, 0600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "сертификат для %s записан. Для реального обхода замените его на сертификат от доверенного центра.\n", *host)
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", ":443", "адрес прослушивания")
	certPath := fs.String("cert", "cert.pem", "сертификат PEM")
	keyPath := fs.String("key", "key.pem", "ключ PEM")
	psk := fs.String("psk", "", "общий секрет")
	keysPath := fs.String("keys", "", "файл ключей, одна строка — один ключ")
	acmeDomain := fs.String("acme-domain", "", "домен для сертификата Let's Encrypt")
	acmeCache := fs.String("acme-cache", "autocert", "каталог кэша сертификата")
	acmeHTTP := fs.String("acme-http", ":80", "адрес проверки HTTP-01")
	acmeAccept := fs.Bool("acme-accept", false, "согласие с условиями центра сертификации")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *psk == "" && *keysPath == "" {
		return errors.New("нужен -psk или -keys")
	}
	var key []byte
	if *psk != "" {
		parsed, err := proto.ParsePSK(*psk)
		if err != nil {
			return err
		}
		key = parsed
	}
	domain := strings.TrimSpace(*acmeDomain)
	var pair tls.Certificate
	var getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	var protos []string
	var acmeSrv *http.Server
	if domain != "" {
		if !*acmeAccept {
			return errors.New("для -acme-domain нужен -acme-accept")
		}
		cache := *acmeCache
		if cache == "" {
			cache = "autocert"
		}
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cache),
			HostPolicy: autocert.HostWhitelist(domain),
		}
		ln, err := net.Listen("tcp", *acmeHTTP)
		if err != nil {
			return err
		}
		acmeSrv = &http.Server{
			Handler:           mgr.HTTPHandler(nil),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := acmeSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("acme: %v", err)
			}
		}()
		getCert = mgr.GetCertificate
		// autocert сначала предлагает tls-alpn-01. Без этого имени проверка домена доходит до HTTP-01 только после отказа.
		protos = []string{"h2", "http/1.1", acme.ALPNProto}
	} else {
		loaded, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			return err
		}
		pair = loaded
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if acmeSrv != nil {
		defer func() {
			shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = acmeSrv.Shutdown(shut)
		}()
	}
	fmt.Fprintf(os.Stderr, "сервер %s\n", *listen)
	return server.Serve(ctx, server.Config{
		Listen:         *listen,
		Certificate:    pair,
		GetCertificate: getCert,
		NextProtos:     protos,
		PSK:            key,
		KeysFile:       *keysPath,
		OnListen: func(addr string) {
			fmt.Fprintf(os.Stderr, "слушаю %s\n", addr)
		},
	})
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	keysPath := fs.String("keys", "", "файл ключей")
	psk := fs.String("psk", "", "ключ, который убрать")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *keysPath == "" || *psk == "" {
		return errors.New("нужны -keys и -psk")
	}
	key, err := proto.ParsePSK(*psk)
	if err != nil {
		return err
	}
	if err := server.RemoveKey(*keysPath, key); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "ключ удалён из файла")
	return nil
}

func connect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverAddr := fs.String("server", "", "адрес сервера host:port")
	sni := fs.String("sni", "", "имя в TLS, если оно отличается от адреса")
	listen := fs.String("listen", "127.0.0.1:1080", "локальный SOCKS5")
	httpListen := fs.String("http", "127.0.0.1:8080", "локальный HTTP-прокси, «-» выключает")
	dnsListen := fs.String("dns", "", "локальный DNS, например 127.0.0.1:5353")
	psk := fs.String("psk", "", "общий секрет")
	insecure := fs.Bool("insecure", false, "не проверять сертификат")
	trayOn := fs.Bool("tray", defaultTray(), "значок в области уведомлений")
	configPath := fs.String("config", "", "файл JSON с параметрами")
	rawURL := fs.String("url", "", "ссылка veil://")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath != "" && *rawURL != "" {
		return errors.New("нельзя одновременно указывать -config и -url")
	}

	var base profile.Settings
	fromSource := *configPath != "" || *rawURL != ""
	if *configPath != "" {
		loaded, err := profile.Load(*configPath)
		if err != nil {
			return err
		}
		base = loaded
	}
	if *rawURL != "" {
		loaded, err := profile.ParseURL(*rawURL)
		if err != nil {
			return err
		}
		base = loaded
	}
	cfg, err := mergeConnect(fs, base, fromSource, *serverAddr, *sni, *listen, *httpListen, *dnsListen, *psk, *insecure)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	phrase, failed, err := probe(ctx, cfg)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}

	var icon *tray.Icon
	if *trayOn && tray.Supported() {
		icon, err = tray.Open(phrase, stop)
		if err != nil {
			fmt.Fprintf(os.Stderr, "трей: %v\n", err)
		}
	}
	if icon != nil {
		defer icon.Close()
	}
	if failed && icon == nil {
		return errors.New(phrase)
	}
	fmt.Fprintln(os.Stderr, phrase)

	cfg.OnListen = func(addr string) {
		fmt.Fprintf(os.Stderr, "SOCKS5 на %s\n", addr)
	}
	cfg.OnHTTPListen = func(addr string) {
		if addr == "" {
			fmt.Fprintf(os.Stderr, "HTTP-прокси выключен\n")
			return
		}
		fmt.Fprintf(os.Stderr, "HTTP-прокси на %s\n", addr)
	}
	cfg.OnDNSListen = func(addr string) {
		fmt.Fprintf(os.Stderr, "DNS на %s\n", addr)
	}
	return client.Run(ctx, cfg)
}

func probe(ctx context.Context, cfg client.Config) (phrase string, failed bool, err error) {
	err = client.Check(ctx, cfg)
	if err == nil {
		return client.StatusReady, false, nil
	}
	if ctx.Err() != nil {
		return "", false, nil
	}
	if configMistake(err) {
		return "", false, err
	}
	return client.Explain(err), true, nil
}

func configMistake(err error) bool {
	switch err.Error() {
	case "psk должен быть 32 байта", "не задан адрес сервера":
		return true
	default:
		return false
	}
}

func autostartCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("нужно on или off")
	}
	switch args[0] {
	case "on":
		if err := rejectSecretFlags(args[1:]); err != nil {
			return err
		}
		fs := flag.NewFlagSet("autostart", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := fs.String("config", "", "файл JSON с параметрами")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || strings.TrimSpace(*configPath) == "" {
			return errors.New("нужен -config: ключ не должен попасть в реестр")
		}
		return autostart.Enable(*configPath)
	case "off":
		if len(args) != 1 {
			return errors.New("autostart off не принимает параметры")
		}
		return autostart.Disable()
	default:
		return fmt.Errorf("неизвестная команда autostart %q", args[0])
	}
}

func rejectSecretFlags(args []string) error {
	for _, arg := range args {
		name := arg
		if strings.HasPrefix(name, "--") {
			name = name[2:]
		} else if strings.HasPrefix(name, "-") {
			name = name[1:]
		} else {
			continue
		}
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name == "psk" || name == "url" {
			return errors.New("нужен -config: ключ не должен попасть в реестр")
		}
	}
	return nil
}

func link(args []string) error {
	fs := flag.NewFlagSet("link", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverAddr := fs.String("server", "", "адрес сервера host:port")
	sni := fs.String("sni", "", "имя в TLS, если оно отличается от адреса")
	psk := fs.String("psk", "", "общий секрет")
	insecure := fs.Bool("insecure", false, "не проверять сертификат")
	if err := fs.Parse(args); err != nil {
		return err
	}
	u, err := profile.FormatURL(*serverAddr, *sni, *psk, *insecure)
	if err != nil {
		return err
	}
	fmt.Println(u)
	return nil
}

// Пустой флаг по умолчанию не перекрывает файл или ссылку: смотрим, передали ли его явно.
func mergeConnect(fs *flag.FlagSet, base profile.Settings, fromSource bool, server, sni, listen, httpListen, dnsListen, psk string, insecure bool) (client.Config, error) {
	seen := map[string]struct{}{}
	fs.Visit(func(f *flag.Flag) {
		seen[f.Name] = struct{}{}
	})
	set := func(name string) bool {
		_, ok := seen[name]
		return ok
	}
	if !fromSource || set("server") {
		base.Server = server
	}
	if !fromSource || set("sni") {
		base.SNI = sni
	}
	if !fromSource || set("listen") {
		base.Listen = listen
	} else if base.Listen == "" {
		base.Listen = listen
	}
	if !fromSource || set("http") {
		base.HTTPListen = httpListen
	} else if base.HTTPListen == "" {
		base.HTTPListen = httpListen
	}
	if !fromSource || set("dns") {
		base.DNSListen = dnsListen
	}
	if !fromSource || set("insecure") {
		base.Insecure = insecure
	}
	if !fromSource || set("psk") {
		key, err := proto.ParsePSK(psk)
		if err != nil {
			return client.Config{}, err
		}
		base.PSK = key
	}
	return client.Config{
		Listen:     base.Listen,
		HTTPListen: base.HTTPListen,
		DNSListen:  base.DNSListen,
		ServerAddr: base.Server,
		SNI:        base.SNI,
		PSK:        base.PSK,
		Insecure:   base.Insecure,
	}, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
