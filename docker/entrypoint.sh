#!/bin/sh
set -eu

if [ -z "${VEIL_PSK:-}" ] && [ -z "${VEIL_KEYS:-}" ]; then
	echo "ошибка: нужен VEIL_PSK или VEIL_KEYS" >&2
	exit 1
fi

# exec оставляет veil процессом 1, чтобы SIGTERM от Docker дошёл до serve.
set -- /usr/local/bin/veil serve -listen "${VEIL_LISTEN:-:443}"

if [ -n "${VEIL_ACME_DOMAIN:-}" ] && [ "${VEIL_ACME_ACCEPT:-}" = "1" ]; then
	set -- "$@" \
		-acme-domain "$VEIL_ACME_DOMAIN" \
		-acme-accept \
		-acme-cache "${VEIL_ACME_CACHE:-/var/lib/veil/autocert}"
else
	cert="${VEIL_CERT:-/etc/veil/cert.pem}"
	key="${VEIL_KEY:-/etc/veil/key.pem}"
	if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
		echo "ошибка: нужны $cert и $key либо VEIL_ACME_DOMAIN и VEIL_ACME_ACCEPT=1" >&2
		exit 1
	fi
	set -- "$@" -cert "$cert" -key "$key"
fi

if [ -n "${VEIL_PSK:-}" ]; then
	set -- "$@" -psk "$VEIL_PSK"
fi
if [ -n "${VEIL_KEYS:-}" ]; then
	set -- "$@" -keys "$VEIL_KEYS"
fi

exec "$@"
