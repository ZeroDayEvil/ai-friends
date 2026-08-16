#!/usr/bin/env bash
#
# Добавляет узел в меш. Запускается на концентраторе (VPS).
#
#   sudo ./new-peer.sh --name winsrv-01 --address 10.99.0.11 --endpoint vpn.example.com
#
set -euo pipefail

NAME=""
ADDRESS=""
ENDPOINT=""
WG_IF="wg0"
WG_PORT=51820

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --address) ADDRESS="$2"; shift 2 ;;
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --interface) WG_IF="$2"; shift 2 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$NAME" && -n "$ADDRESS" ]] || { echo "Нужны --name и --address" >&2; exit 2; }
# Публичный адрес концентратора задаётся явно. Определять его запросом к
# внешнему сервису вроде ipify мы не станем: это лишний внешний вызов с узла,
# который по нашей политике не должен обращаться куда попало.
[[ -n "$ENDPOINT" ]] || { echo "Нужен --endpoint: публичный адрес или имя концентратора" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "Требуются права root" >&2; exit 1; }

SERVER_CONF="/etc/wireguard/${WG_IF}.conf"
[[ -f "$SERVER_CONF" ]] || { echo "Нет $SERVER_CONF: сначала настройте концентратор" >&2; exit 1; }

SERVER_PUB=$(wg show "$WG_IF" public-key)

umask 077
PRIV=$(wg genkey)
PUB=$(printf '%s' "$PRIV" | wg pubkey)
PSK=$(wg genpsk)

# Пир добавляется и в рабочую конфигурацию, и в файл: без записи в файл
# он исчезнет после перезагрузки узла.
wg set "$WG_IF" peer "$PUB" preshared-key <(printf '%s' "$PSK") allowed-ips "${ADDRESS}/32"

cat >> "$SERVER_CONF" <<EOF

# ${NAME}, добавлен $(date -u +%Y-%m-%dT%H:%M:%SZ)
[Peer]
PublicKey = ${PUB}
PresharedKey = ${PSK}
AllowedIPs = ${ADDRESS}/32
EOF

cat <<EOF

Конфиг для узла ${NAME}. Приватный ключ показывается один раз и нигде не сохраняется.

[Interface]
PrivateKey = ${PRIV}
Address = ${ADDRESS}/24

[Peer]
PublicKey = ${SERVER_PUB}
PresharedKey = ${PSK}
Endpoint = ${ENDPOINT}:${WG_PORT}
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25

EOF
