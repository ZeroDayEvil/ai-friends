#!/usr/bin/env bash
#
# Развёртывание web-узла платформы на Ubuntu 24.04 LTS.
#
# Ставит Docker, cloudflared и WireGuard из официальных репозиториев
# (никаких curl|bash), настраивает файрвол и запускает наш образ.
#
# Скрипт идемпотентен: повторный запуск не ломает уже настроенное.
#
# Использование:
#   sudo ./setup-server.sh --admin-ip 88.99.219.110
#
set -euo pipefail

ADMIN_IP=""
SKIP_APP=0
ENABLE_OS_SECURITY_UPDATES=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-ip) ADMIN_IP="$2"; shift 2 ;;
    --skip-app) SKIP_APP=1; shift ;;
    --no-os-updates) ENABLE_OS_SECURITY_UPDATES=0; shift ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Требуются права root" >&2; exit 1; }

log() { printf '\n== %s ==\n' "$1"; }

# ---------------------------------------------------------------------------
log "Базовые пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg lsb-release ufw fail2ban jq

# ---------------------------------------------------------------------------
log "Docker из официального репозитория"
# Ключ и репозиторий берём с download.docker.com, а не через get.docker.com:
# тот способ предполагает исполнение скачанного скрипта без проверки.
install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
fi
cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable
EOF
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

# ---------------------------------------------------------------------------
log "cloudflared из официального репозитория Cloudflare"
if [[ ! -f /etc/apt/keyrings/cloudflare-main.gpg ]]; then
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
    -o /etc/apt/keyrings/cloudflare-main.gpg
  chmod a+r /etc/apt/keyrings/cloudflare-main.gpg
fi
cat > /etc/apt/sources.list.d/cloudflared.list <<EOF
deb [signed-by=/etc/apt/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main
EOF
apt-get update -qq
apt-get install -y -qq cloudflared

# ---------------------------------------------------------------------------
log "WireGuard"
apt-get install -y -qq wireguard wireguard-tools
# Форвардинг нужен, если этот узел работает концентратором меша.
cat > /etc/sysctl.d/99-wireguard.conf <<'EOF'
net.ipv4.ip_forward = 1
EOF
sysctl --system >/dev/null

# ---------------------------------------------------------------------------
log "Файрвол"
# Входящих портов наружу не открываем вообще: публичный доступ идёт через
# Cloudflare Tunnel, который создаёт исходящее соединение. Открыт только SSH,
# и по возможности ограничен адресом администратора.
ufw --force reset >/dev/null
ufw default deny incoming
ufw default deny outgoing

if [[ -n "$ADMIN_IP" ]]; then
  ufw allow from "$ADMIN_IP" to any port 22 proto tcp comment 'SSH admin'
else
  echo "ВНИМАНИЕ: --admin-ip не задан, SSH открыт всем адресам."
  ufw allow 22/tcp comment 'SSH any'
fi

# Меш: обмен с пирами WireGuard.
ufw allow 51820/udp comment 'WireGuard'

# Исходящие: то, без чего узел неработоспособен.
#
# Оговорка по честности: это ограничение по портам, а не по адресам. Оно не даёт
# компоненту открыть произвольный канал на нестандартном порту, но не мешает
# обратиться к произвольному хосту по 443. Полноценный контроль исходящего
# трафика требует фильтрующего прокси со списком разрешённых доменов -- это
# отдельная задача, см. docs/design/egress.md.
ufw allow out 53 comment 'DNS'
ufw allow out 123/udp comment 'NTP'
ufw allow out 80/tcp comment 'apt'
ufw allow out 443/tcp comment 'apt, registry, Cloudflare'
ufw allow out 7844 comment 'Cloudflare Tunnel'
ufw allow out 51820/udp comment 'WireGuard'

ufw --force enable
ufw status verbose

# ---------------------------------------------------------------------------
log "fail2ban"
cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
mode = aggressive
maxretry = 4
findtime = 10m
bantime = 1h
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# ---------------------------------------------------------------------------
log "Обновления"
if [[ "$ENABLE_OS_SECURITY_UPDATES" -eq 1 ]]; then
  # Автоматически обновляется только базовая ОС и только исправления
  # безопасности. Наши образы не обновляются автоматически никогда: их версия
  # закреплена digest-ом и меняется отдельным изменением в репозитории.
  apt-get install -y -qq unattended-upgrades
  cat > /etc/apt/apt.conf.d/51platform-unattended <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  systemctl enable --now unattended-upgrades
else
  systemctl disable --now unattended-upgrades 2>/dev/null || true
  echo "Автообновления ОС отключены по требованию."
fi

# ---------------------------------------------------------------------------
if [[ "$SKIP_APP" -eq 0 ]]; then
  log "Приложение"
  APP_DIR=/opt/electerm-platform
  mkdir -p "$APP_DIR"
  if [[ ! -f "$APP_DIR/.env" ]]; then
    echo "Файл $APP_DIR/.env не найден."
    echo "Скопируйте infra/vps/.env.sample, заполните значения и запустите снова"
    echo "или используйте --skip-app, если приложение поднимается отдельно."
  else
    cp -f "$(dirname "$0")/docker-compose.yml" "$APP_DIR/docker-compose.yml"
    cd "$APP_DIR"
    docker compose pull
    docker compose up -d
    docker compose ps
  fi
fi

log "Готово"
echo "Дальше: настроить туннель по infra/cloudflare/README.md и узел меша по infra/wireguard/README.md"
