#!/usr/bin/env bash
#
# Развёртывание веб-панели платформы на сервере с ISPmanager 6, на котором уже
# работают клиентские сайты.
#
# НЕ ЗАПУСКАЙТЕ на этом сервере infra/vps/setup-server.sh. Тот скрипт написан
# под чистую Ubuntu: он сбрасывает ufw, ставит fail2ban, включает Docker с
# правкой iptables и закрывает всё входящее, кроме 22. На сервере с панелью это
# означает недоступность 80, 443 и 1500, то есть одновременно остановку всех
# клиентских сайтов и потерю доступа к ISPmanager. Этот скрипт -- отдельный
# путь для такого сервера: он не ставит пакеты и не касается фаервола.
#
# Что делает:
#   1. проверяет предпосылки, ничего не меняя;
#   2. складывает копию затрагиваемых файлов и снимок состояния в каталог с
#      меткой времени и печатает путь к нему;
#   3. поднимает приложение в Docker на 127.0.0.1:5577;
#   4. по запросу устанавливает фрагмент проксирования для одного домена в
#      каталог ресурсов, который ISPmanager подключает сам, проверяет
#      конфигурацию веб-сервера и откатывает фрагмент, если проверка не прошла.
#
# Чего не делает никогда:
#   - не устанавливает Docker (это отдельное решение владельца сервера);
#   - не правит файлы конфигурации сайтов, созданные панелью;
#   - не трогает порты 80, 443, 1500 и правила фаервола;
#   - не перезапускает веб-сервер (только graceful reload, и только по флагу).
#
# Использование:
#   sudo ./deploy-panel.sh --dry-run
#   sudo ./deploy-panel.sh --dry-run --with-proxy nginx
#   sudo ./deploy-panel.sh
#   sudo ./deploy-panel.sh --with-proxy nginx --reload-web
#
# Флаги:
#   --dry-run              напечатать план и выйти, ничего не меняя
#   --domain <домен>       домен, через который отдаётся панель (mql5.ink)
#   --port <порт>          локальный порт приложения (5577)
#   --prefix </panel/>     путь на домене, по которому доступна панель
#   --app-dir <путь>       каталог приложения (/opt/electerm-platform)
#   --with-proxy nginx|apache|none  какой веб-сервер настраивать (none)
#   --reload-web           выполнить graceful reload после успешной проверки
#   --skip-app             не трогать контейнеры, только проксирование
#   --allow-subnet-overlap продолжить при пересечении подсетей Docker
#
set -euo pipefail

DRY_RUN=0
DOMAIN="mql5.ink"
APP_PORT="5577"
PREFIX="/panel/"
APP_DIR="/opt/electerm-platform"
WITH_PROXY="none"
RELOAD_WEB=0
SKIP_APP=0
ALLOW_SUBNET_OVERLAP=0

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
COMPOSE_SRC="${SCRIPT_DIR}/../docker-compose.yml"
COMPOSE_PROJECT="electerm-platform"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/electerm-platform/${TS}"
BACKUP_READY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --port) APP_PORT="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --app-dir) APP_DIR="$2"; shift 2 ;;
    --with-proxy) WITH_PROXY="$2"; shift 2 ;;
    --reload-web) RELOAD_WEB=1; shift ;;
    --skip-app) SKIP_APP=1; shift ;;
    --allow-subnet-overlap) ALLOW_SUBNET_OVERLAP=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Вывод
# ---------------------------------------------------------------------------
log()  { printf '\n== %s ==\n' "$1"; }
info() { printf '   %s\n' "$1"; }
ok()   { printf '   [ок] %s\n' "$1"; }
warn() { printf '   [внимание] %s\n' "$1"; }
die()  { printf '\nОСТАНОВ: %s\n' "$1" >&2; exit "${2:-1}"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Выполняет изменение или печатает его при сухом прогоне.
change() {
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '   [план] %s\n' "$*"
  else
    printf '   [делаю] %s\n' "$*"
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# Проверка аргументов
# ---------------------------------------------------------------------------
case "$WITH_PROXY" in
  none|nginx|apache) ;;
  *) die "--with-proxy принимает none, nginx или apache, получено: ${WITH_PROXY}" 2 ;;
esac

[[ "$APP_PORT" =~ ^[0-9]+$ ]] || die "--port должен быть числом" 2
[[ "$PREFIX" == /* && "$PREFIX" == */ ]] || die "--prefix должен начинаться и заканчиваться слэшем, например /panel/" 2
if [[ "$PREFIX" == "/" ]]; then
  die "--prefix / не поддерживается: конфигурация сайта, созданная ISPmanager,
уже содержит location / , и второй такой блок nginx не примет (duplicate
location). Отдавать панель на корне домена без правки шаблонов панели нельзя.
Варианты описаны в reverse-proxy.md, разделы «Вариант Б» и «Вариант В»." 2
fi
PREFIX_BARE="${PREFIX%/}"

[[ ${EUID} -eq 0 ]] || die "требуются права root" 1

printf 'Развёртывание веб-панели на сервере с ISPmanager\n'
printf 'Домен: %s   путь: %s   порт приложения: 127.0.0.1:%s\n' "$DOMAIN" "$PREFIX" "$APP_PORT"
printf 'Проксирование: %s   каталог приложения: %s\n' "$WITH_PROXY" "$APP_DIR"
if [[ $DRY_RUN -eq 1 ]]; then
  printf '\nРЕЖИМ СУХОГО ПРОГОНА. Ни один файл не будет изменён, ни одна служба\n'
  printf 'не будет перезапущена. Ниже -- план действий.\n'
fi

# ---------------------------------------------------------------------------
log "1. Предпосылки (только чтение)"

# --- Docker ---------------------------------------------------------------
# Docker сознательно не устанавливается. На сервере с десятками клиентских
# сайтов установка демона -- это новые цепочки iptables (DOCKER, DOCKER-USER,
# DOCKER-ISOLATION), новый мост docker0 и новая политика форвардинга. Каждое
# из трёх способно изменить обработку трафика для существующих сайтов, а
# перезапуск демона позже пересоздаст цепочки заново. Такое решение принимает
# владелец сервера отдельно и с окном обслуживания.
if ! have docker; then
  die "Docker не установлен.
Скрипт не ставит его сам: установка добавляет цепочки iptables и сетевой мост,
что на сервере с работающими клиентскими сайтами является отдельным
изменением с собственным окном обслуживания и планом отката.
Что делать: снять отчёт inventory.sh, оценить пересечения по фаерволу и
подсетям, затем установить Docker из официального репозитория вручную и
запустить этот скрипт снова." 3
fi
ok "docker найден: $(docker --version)"

if ! docker compose version >/dev/null 2>&1; then
  die "нет docker compose v2 (плагин docker-compose-plugin).
Скрипт рассчитан на 'docker compose', а не на устаревший 'docker-compose'." 3
fi
ok "docker compose найден: $(docker compose version --short 2>/dev/null || echo 'версия не определена')"

docker info >/dev/null 2>&1 || die "демон Docker не отвечает: 'docker info' завершился с ошибкой" 3
ok "демон Docker отвечает"

# --- Файл compose и его порты --------------------------------------------
[[ -f "$COMPOSE_SRC" ]] || die "не найден ${COMPOSE_SRC}: запускайте скрипт из каталога репозитория" 3

# Публикация портов проверяется явно: если в compose появится порт без привязки
# к 127.0.0.1, Docker откроет его наружу через цепочку DOCKER, которую ufw и
# правила панели не перекрывают. На сервере с панелью это означает внезапно
# доступный из интернета сервис.
BAD_PORTS="$(grep -nE '^[[:space:]]*-[[:space:]]*"?[0-9]+:[0-9]+"?[[:space:]]*$' "$COMPOSE_SRC" || true)"
if [[ -n "$BAD_PORTS" ]]; then
  printf '%s\n' "$BAD_PORTS"
  die "в ${COMPOSE_SRC} есть публикация порта без привязки к 127.0.0.1" 3
fi
if grep -qE '^[[:space:]]*-[[:space:]]*"?(0\.0\.0\.0:)?(80|443|1500):' "$COMPOSE_SRC"; then
  die "в ${COMPOSE_SRC} публикуются 80, 443 или 1500 -- эти порты заняты веб-сервером и панелью" 3
fi
ok "в compose публикуются только порты на 127.0.0.1"

# --- Порт приложения ------------------------------------------------------
PORT_HOLDER=""
if have ss; then
  PORT_HOLDER="$(ss -lntp 2>/dev/null | grep -E "[:.]${APP_PORT}[[:space:]]" || true)"
elif have netstat; then
  PORT_HOLDER="$(netstat -lntp 2>/dev/null | grep -E "[:.]${APP_PORT}[[:space:]]" || true)"
else
  warn "ни ss, ни netstat не найдены: занятость порта ${APP_PORT} не проверена"
fi
if [[ -n "$PORT_HOLDER" ]]; then
  OURS="$(docker ps --filter "name=^${COMPOSE_PROJECT}-" --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep ":${APP_PORT}->" || true)"
  if [[ -n "$OURS" ]]; then
    ok "порт ${APP_PORT} держит наш контейнер (повторный запуск, это нормально): ${OURS}"
  else
    printf '%s\n' "$PORT_HOLDER"
    die "порт ${APP_PORT} занят посторонним процессом. Выберите другой через --port
и не забудьте указать тот же порт в фрагменте проксирования." 3
  fi
else
  ok "порт ${APP_PORT} свободен"
fi

# --- Порты, которые трогать нельзя ---------------------------------------
for p in 80 443 1500; do
  if have ss && ! ss -lnt 2>/dev/null | grep -qE "[:.]${p}[[:space:]]"; then
    warn "порт ${p} не слушается. Ожидалось, что его занимает веб-сервер или панель.
   Проверьте отчёт inventory.sh: возможно, состояние сервера не то, под которое
   этот комплект рассчитан."
  fi
done

# --- Пересечение подсетей -------------------------------------------------
# Docker выдаёт своим сетям адреса из пулов 172.17.0.0/12 и 192.168.0.0/16.
# Если сервер уже маршрутизирует что-то из этих диапазонов (внутренняя сеть
# провайдера, vpn, сети панели), новая сеть compose может перехватить чужой
# трафик. Проверка эвристическая: она смотрит таблицу маршрутов и не видит
# маршрутов, которые появятся позже.
if have ip; then
  OVERLAP="$(ip route show 2>/dev/null \
    | grep -E '^(172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' \
    | grep -v -E 'dev (docker0|br-[0-9a-f]+)' || true)"
  if [[ -n "$OVERLAP" ]]; then
    printf '%s\n' "$OVERLAP"
    if [[ $ALLOW_SUBNET_OVERLAP -eq 1 ]]; then
      warn "пересечение подсетей принято флагом --allow-subnet-overlap"
    else
      die "существуют маршруты в диапазонах, из которых Docker выдаёт адреса своим
сетям. Создание сети compose может перехватить этот трафик.
Что делать: либо задать сети явную подсеть вне занятых диапазонов, либо
ограничить пул Docker в /etc/docker/daemon.json, либо, убедившись что
пересечения фактически нет, повторить с --allow-subnet-overlap." 3
    fi
  else
    ok "явных пересечений подсетей в таблице маршрутов не видно"
  fi
fi

# --- Место на диске -------------------------------------------------------
FREE_MB="$(df -Pm /var/lib/docker 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
if [[ -n "$FREE_MB" && "$FREE_MB" -lt 3072 ]]; then
  warn "под /var/lib/docker свободно ${FREE_MB} МБ. Образам платформы нужно около 2-3 ГБ.
   Заполнение диска на этом сервере остановит клиентские сайты и базы данных."
else
  ok "свободно под /var/lib/docker: ${FREE_MB} МБ"
fi

# --- Файл окружения ------------------------------------------------------
ENV_FILE="${APP_DIR}/.env"
if [[ $SKIP_APP -eq 0 ]]; then
  if [[ ! -f "$ENV_FILE" ]]; then
    die "нет ${ENV_FILE}.
Скопируйте infra/vps/.env.sample в ${ENV_FILE} и заполните APP_IMAGE,
POSTGRES_IMAGE (оба с digest, не тегом), POSTGRES_PASSWORD, SERVER_SECRET.
Секреты в репозиторий не попадают, поэтому файл создаётся на сервере." 3
  fi
  MISSING=""
  for v in APP_IMAGE POSTGRES_IMAGE POSTGRES_PASSWORD SERVER_SECRET; do
    grep -qE "^${v}=.+" "$ENV_FILE" || MISSING="${MISSING} ${v}"
  done
  [[ -z "$MISSING" ]] || die "в ${ENV_FILE} не заполнены:${MISSING}" 3
  if grep -qE '^(APP_IMAGE|POSTGRES_IMAGE)=.*(REPLACE_ME|:latest)$' "$ENV_FILE"; then
    die "в ${ENV_FILE} образы указаны заглушкой или тегом. Требуется digest вида
name@sha256:... -- тег можно перезаписать, digest нет (security/README.md)." 3
  fi
  if ! grep -qE '^(APP_IMAGE)=.*@sha256:[0-9a-f]{64}' "$ENV_FILE"; then
    die "APP_IMAGE в ${ENV_FILE} задан без digest" 3
  fi
  ok "файл окружения заполнен, образы закреплены digest-ом"
fi

# --- Веб-сервер и каталог ресурсов домена --------------------------------
ISPMGR_CONF="/usr/local/mgr5/etc/ispmgr.conf"
VHOST_FILE=""
RESOURCE_DIR=""
SAMPLE=""
CONFIG_TEST=()
RELOAD_CMD=()

detect_nginx() {
  local vhosts_dir="/etc/nginx/vhosts"
  local from_conf
  from_conf="$(grep -E "^[[:space:]]*path[[:space:]]+nginx-vhosts[[:space:]]" "$ISPMGR_CONF" 2>/dev/null | awk '{print $3}' | head -n 1 || true)"
  [[ -n "$from_conf" ]] && vhosts_dir="$from_conf"
  info "каталог сайтов nginx: ${vhosts_dir}"

  VHOST_FILE="$(grep -rl -- "$DOMAIN" "$vhosts_dir" 2>/dev/null | head -n 1 || true)"
  [[ -n "$VHOST_FILE" ]] || die "в ${vhosts_dir} нет конфигурации для ${DOMAIN}.
Домен должен быть создан и работать в панели ДО этого шага." 4
  info "конфигурация домена: ${VHOST_FILE}"

  # Каталог ресурсов берётся из самого файла сайта, а не угадывается: только
  # так мы знаем, что панель действительно подключает этот каталог в
  # server-секцию именно этого домена.
  local inc
  inc="$(grep -oE "include[[:space:]]+[^;]*resources[^;]*;" "$VHOST_FILE" 2>/dev/null | grep -F "$DOMAIN" | head -n 1 || true)"
  if [[ -z "$inc" ]]; then
    die "в ${VHOST_FILE} нет include каталога ресурсов этого домена.
Без него файл, положенный в каталог ресурсов, не подключится, и проксирование
не заработает -- при этом внешне всё будет выглядеть как успешная установка.
Что делать: открыть домен в панели и сохранить его, чтобы конфигурация была
перегенерирована текущим шаблоном, затем повторить. Если include не появился,
используйте Вариант Б из reverse-proxy.md." 4
  fi
  info "найден include: ${inc}"
  RESOURCE_DIR="$(printf '%s' "$inc" | sed -E 's/^include[[:space:]]+//; s/;$//; s#/\*\.conf$##')"

  # Include должен быть и в HTTPS-секции, иначе панель откроется по http и не
  # откроется по https.
  local inc_count
  inc_count="$(grep -cF "$RESOURCE_DIR" "$VHOST_FILE" || true)"
  local srv_count
  srv_count="$(grep -cE '^[[:space:]]*server[[:space:]]*\{' "$VHOST_FILE" || true)"
  info "server-секций в файле: ${srv_count}, включений каталога ресурсов: ${inc_count}"
  if [[ "$srv_count" -gt "$inc_count" ]]; then
    warn "server-секций больше, чем включений каталога ресурсов. Вероятно, в одной из
   секций (обычно HTTPS) include отсутствует. Проверьте файл глазами до reload."
  fi

  # Наличие location / -- причина, по которой панель отдаётся на подпути.
  if grep -qE '^[[:space:]]*location[[:space:]]+/[[:space:]]*\{' "$VHOST_FILE"; then
    info "в конфигурации есть location / -- поэтому панель отдаётся на подпути ${PREFIX}"
  fi
  if grep -qE "location[[:space:]]+\^~[[:space:]]*${PREFIX}" "$VHOST_FILE"; then
    warn "в конфигурации домена уже есть location ${PREFIX}. Возможен конфликт."
  fi

  SAMPLE="${SCRIPT_DIR}/nginx-panel.conf.sample"
  CONFIG_TEST=(nginx -t)
  if have systemctl && systemctl is-active --quiet nginx; then
    RELOAD_CMD=(systemctl reload nginx)
  else
    RELOAD_CMD=(nginx -s reload)
  fi
}

detect_apache() {
  local ctl=""
  for c in apache2ctl apachectl httpd; do
    have "$c" && { ctl="$c"; break; }
  done
  [[ -n "$ctl" ]] || die "не найдена управляющая команда Apache" 4
  info "управляющая команда Apache: ${ctl}"

  local mods
  mods="$("$ctl" -M 2>/dev/null || true)"
  local missing=""
  for m in proxy_module proxy_http_module proxy_wstunnel_module rewrite_module headers_module; do
    printf '%s' "$mods" | grep -q "$m" || missing="${missing} ${m}"
  done
  if [[ -n "$missing" ]]; then
    die "у Apache не включены модули:${missing}
Скрипт не включает их сам: a2enmod с последующим перезапуском Apache
затрагивает все сайты сервера. Это отдельное изменение с окном обслуживания.
Без proxy_wstunnel_module терминалы панели работать не будут." 4
  fi
  ok "нужные модули Apache включены"

  local vhosts_dir="/etc/apache2/vhosts"
  [[ -d "$vhosts_dir" ]] || vhosts_dir="/etc/httpd/conf/vhosts"
  VHOST_FILE="$(grep -rl -- "$DOMAIN" "$vhosts_dir" 2>/dev/null | head -n 1 || true)"
  [[ -n "$VHOST_FILE" ]] || die "в ${vhosts_dir} нет конфигурации для ${DOMAIN}" 4
  info "конфигурация домена: ${VHOST_FILE}"

  local inc
  inc="$(grep -oE "Include(Optional)?[[:space:]]+[^[:space:]]*resources[^[:space:]]*" "$VHOST_FILE" 2>/dev/null | grep -F "$DOMAIN" | head -n 1 || true)"
  [[ -n "$inc" ]] || die "в ${VHOST_FILE} нет Include каталога ресурсов этого домена.
См. пояснение в reverse-proxy.md: без него фрагмент не подключится." 4
  info "найден include: ${inc}"
  RESOURCE_DIR="$(printf '%s' "$inc" | awk '{print $2}' | sed -E 's#/\*\.conf$##')"

  SAMPLE="${SCRIPT_DIR}/apache-panel.conf.sample"
  CONFIG_TEST=("$ctl" configtest)
  if have systemctl && systemctl is-active --quiet apache2; then
    RELOAD_CMD=(systemctl reload apache2)
  elif have systemctl && systemctl is-active --quiet httpd; then
    RELOAD_CMD=(systemctl reload httpd)
  else
    RELOAD_CMD=("$ctl" graceful)
  fi
}

case "$WITH_PROXY" in
  nginx) detect_nginx ;;
  apache) detect_apache ;;
  none) info "проксирование не настраивается (--with-proxy none)" ;;
esac

TARGET_CONF=""
[[ -n "$RESOURCE_DIR" ]] && TARGET_CONF="${RESOURCE_DIR}/10-electerm-panel.conf"
[[ -n "$TARGET_CONF" ]] && info "фрагмент будет установлен как ${TARGET_CONF}"

# ---------------------------------------------------------------------------
log "2. Резервные копии и снимок состояния"

# Копия делается ДО любого изменения. Полные пути внутри каталога копии
# сохраняются (cp --parents), поэтому откат -- это копирование файла обратно по
# тому же пути, без разбора, что куда относилось.
ensure_backup() {
  if [[ $BACKUP_READY -eq 1 ]]; then return 0; fi
  change mkdir -p "$BACKUP_DIR"
  if [[ $DRY_RUN -eq 0 ]]; then
    chmod 700 "$(dirname "$BACKUP_DIR")" "$BACKUP_DIR"
  fi
  BACKUP_READY=1
}

backup_path() {
  local p="$1"
  [[ -e "$p" ]] || { info "нечего копировать: ${p} не существует"; return 0; }
  ensure_backup
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '   [план] копия %s -> %s%s\n' "$p" "$BACKUP_DIR" "$p"
  else
    cp -a --parents "$p" "$BACKUP_DIR"
    info "копия: ${BACKUP_DIR}${p}"
  fi
}

snapshot() {
  local name="$1"; shift
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '   [план] снимок %s: %s\n' "$name" "$*"
    return 0
  fi
  ensure_backup
  { printf '$ %s\n' "$*"; "$@" 2>&1 || true; } > "${BACKUP_DIR}/${name}" || true
  info "снимок: ${BACKUP_DIR}/${name}"
}

ensure_backup
info "каталог резервной копии: ${BACKUP_DIR}"

# Снимки состояния до изменений. Их ценность в откате: по ним видно, что было
# нормой, а не в том, чтобы их применять автоматически.
snapshot "iptables-filter.txt" iptables -S
snapshot "iptables-nat.txt" iptables -t nat -S
snapshot "listeners.txt" ss -lntup
snapshot "docker-ps.txt" docker ps -a
snapshot "docker-networks.txt" docker network ls

backup_path "${APP_DIR}/docker-compose.yml"
backup_path "$ENV_FILE"
if [[ -n "$TARGET_CONF" ]]; then
  backup_path "$VHOST_FILE"
  backup_path "$RESOURCE_DIR"
fi

if [[ $DRY_RUN -eq 0 ]]; then
  cat > "${BACKUP_DIR}/RESTORE.txt" <<TXT
Снимок состояния перед развёртыванием веб-панели, ${TS}.

Откат, по шагам (подробно -- в rollback.md репозитория):

1. Проксирование. Удалить установленный фрагмент и перечитать конфигурацию:
     rm -f ${TARGET_CONF:-<фрагмент не устанавливался>}
     nginx -t && systemctl reload nginx
   Конфигурация сайта панелью не менялась, восстанавливать её не нужно.
   Копия файла сайта на случай сомнений: ${BACKUP_DIR}${VHOST_FILE:-}

2. Приложение. Остановить и удалить контейнеры:
     cd ${APP_DIR} && docker compose down
   Данные останутся в томах Docker. Полное удаление вместе с данными:
     docker compose down -v

3. Файлы приложения. Вернуть предыдущие версии, если они были:
     cp -a ${BACKUP_DIR}${APP_DIR}/. ${APP_DIR}/

Фаервол, порты 80, 443, 1500 и конфигурация сайтов панели не изменялись.
Файлы iptables-*.txt и listeners.txt -- это снимки для сверки, а не для
применения. Восстанавливать правила из них автоматически нельзя.
TXT
  info "инструкция по откату: ${BACKUP_DIR}/RESTORE.txt"
fi

# ---------------------------------------------------------------------------
log "3. Приложение в Docker"

if [[ $SKIP_APP -eq 1 ]]; then
  info "пропущено по --skip-app"
else
  change mkdir -p "$APP_DIR"
  if [[ -f "${APP_DIR}/docker-compose.yml" ]] && cmp -s "$COMPOSE_SRC" "${APP_DIR}/docker-compose.yml"; then
    ok "docker-compose.yml уже актуален"
  else
    change cp -f "$COMPOSE_SRC" "${APP_DIR}/docker-compose.yml"
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    printf '   [план] cd %s && docker compose config -q\n' "$APP_DIR"
    printf '   [план] cd %s && docker compose pull\n' "$APP_DIR"
    printf '   [план] cd %s && docker compose up -d\n' "$APP_DIR"
  else
    cd "$APP_DIR"
    docker compose config -q || die "docker compose config не прошёл: проверьте .env" 5
    ok "описание сервисов корректно"
    docker compose pull
    docker compose up -d
    docker compose ps
  fi
fi

# ---------------------------------------------------------------------------
log "4. Проверка приложения на loopback"

probe() {
  if have curl; then
    curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${APP_PORT}/" 2>/dev/null || printf '000'
  elif have wget; then
    if wget -q -O /dev/null --timeout=5 "http://127.0.0.1:${APP_PORT}/" 2>/dev/null; then printf '200'; else printf '000'; fi
  else
    printf 'skip'
  fi
}

if [[ $DRY_RUN -eq 1 ]]; then
  info "[план] опрос http://127.0.0.1:${APP_PORT}/ до ответа, максимум 60 секунд"
elif [[ $SKIP_APP -eq 1 ]]; then
  info "приложение не разворачивалось, проверка пропущена"
else
  CODE="skip"
  for ((attempt = 0; attempt < 20; attempt++)); do
    CODE="$(probe)"
    [[ "$CODE" != "000" ]] && break
    sleep 3
  done
  case "$CODE" in
    skip) warn "нет ни curl, ни wget: проверьте вручную" ;;
    000) die "приложение не отвечает на 127.0.0.1:${APP_PORT}.
Логи: cd ${APP_DIR} && docker compose logs --tail 100 app
Проксирование настраивать бессмысленно, пока приложение не отвечает." 6 ;;
    *) ok "приложение отвечает, код ${CODE} (401 -- норма при включённой проверке личности)" ;;
  esac
fi

# ---------------------------------------------------------------------------
log "5. Фрагмент проксирования"

if [[ "$WITH_PROXY" == "none" ]]; then
  info "не настраивается. Панель слушает только 127.0.0.1:${APP_PORT} и снаружи недоступна."
  info "Как подключить её к домену -- reverse-proxy.md."
else
  [[ -f "$SAMPLE" ]] || die "не найден шаблон ${SAMPLE}" 7

  RENDERED="$(mktemp)"
  trap 'rm -f "$RENDERED"' EXIT
  sed -e "s#@DOMAIN@#${DOMAIN}#g" \
      -e "s#@PREFIX@#${PREFIX}#g" \
      -e "s#@PREFIX_BARE@#${PREFIX_BARE}#g" \
      -e "s#@PORT@#${APP_PORT}#g" \
      "$SAMPLE" > "$RENDERED"

  if grep -q '@[A-Z_]\+@' "$RENDERED"; then
    grep -n '@[A-Z_]\+@' "$RENDERED"
    die "в готовом фрагменте остались незаполненные подстановки" 7
  fi

  if [[ -f "$TARGET_CONF" ]] && cmp -s "$RENDERED" "$TARGET_CONF"; then
    ok "фрагмент уже установлен и совпадает, изменений не требуется"
  elif [[ $DRY_RUN -eq 1 ]]; then
    printf '   [план] создать каталог %s\n' "$RESOURCE_DIR"
    printf '   [план] записать %s, содержимое:\n\n' "$TARGET_CONF"
    sed 's/^/       /' "$RENDERED"
    printf '\n   [план] %s\n' "${CONFIG_TEST[*]}"
    if [[ $RELOAD_WEB -eq 1 ]]; then
      printf '   [план] %s\n' "${RELOAD_CMD[*]}"
    else
      printf '   [план] reload НЕ выполняется (нет --reload-web)\n'
    fi
  else
    HAD_CONF=0
    [[ -f "$TARGET_CONF" ]] && HAD_CONF=1
    mkdir -p "$RESOURCE_DIR"
    install -m 0644 "$RENDERED" "$TARGET_CONF"
    info "записан ${TARGET_CONF}"

    # Проверка конфигурации до перечитывания. Если она не прошла, фрагмент
    # снимается немедленно: оставлять на сервере файл, который ломает
    # конфигурацию, нельзя -- панель перечитает nginx сама при любом
    # изменении любого домена, и тогда упадут все сайты, а не наш.
    if ! "${CONFIG_TEST[@]}"; then
      if [[ $HAD_CONF -eq 1 ]]; then
        cp -a "${BACKUP_DIR}${TARGET_CONF}" "$TARGET_CONF"
        info "восстановлена предыдущая версия фрагмента из копии"
      else
        rm -f "$TARGET_CONF"
        info "фрагмент удалён"
      fi
      if "${CONFIG_TEST[@]}" >/dev/null 2>&1; then
        info "конфигурация веб-сервера снова корректна"
      else
        warn "конфигурация веб-сервера не проходит проверку и БЕЗ нашего фрагмента.
   Это состояние существовало до запуска скрипта. Не перезагружайте веб-сервер,
   пока не разберётесь: reload с битой конфигурацией остановит клиентские сайты."
      fi
      die "проверка конфигурации не прошла, изменение отменено" 8
    fi
    ok "конфигурация веб-сервера проходит проверку"

    if [[ $RELOAD_WEB -eq 1 ]]; then
      "${RELOAD_CMD[@]}"
      ok "выполнено: ${RELOAD_CMD[*]}"
    else
      warn "reload не выполнен (нет --reload-web). Фрагмент лежит на диске, но ещё не
   действует. Он вступит в силу при следующем перечитывании конфигурации, в том
   числе при любом изменении домена через панель. Конфигурация проверена, так
   что такое перечитывание безопасно. Выполнить сейчас:
   ${RELOAD_CMD[*]}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
log "Итог"

printf 'Резервная копия и снимки: %s\n' "$BACKUP_DIR"
if [[ $DRY_RUN -eq 1 ]]; then
  printf 'Сухой прогон: изменений не сделано.\n'
else
  printf 'Приложение: 127.0.0.1:%s, снаружи напрямую недоступно.\n' "$APP_PORT"
  if [[ "$WITH_PROXY" != "none" ]]; then
    printf 'Проксирование: %s -> 127.0.0.1:%s\n' "https://${DOMAIN}${PREFIX}" "$APP_PORT"
  fi
fi
printf 'Откат: %s/RESTORE.txt и rollback.md\n' "$BACKUP_DIR"
printf 'Проверить снаружи: терминал в панели должен открыться и не отваливаться.\n'
printf 'Если страница открывается, а терминал нет -- дело в WebSocket, см. reverse-proxy.md.\n'
