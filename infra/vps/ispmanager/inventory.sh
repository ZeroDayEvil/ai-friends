#!/usr/bin/env bash
#
# Инвентаризация Linux-сервера с панелью ISPmanager 6 перед размещением
# веб-панели платформы.
#
# Скрипт только читает. Он не создаёт, не удаляет и не правит ни одного файла,
# не устанавливает пакеты, не запускает и не перезапускает службы. Всё, что он
# делает -- вызывает диагностические команды и печатает их вывод.
#
# Сознательно НЕ используются, хотя и выглядят безобидно:
#   nginx -t, apache2ctl configtest -- проверка конфигурации открывает файлы
#     журналов и может создать отсутствующие. Это запись, поэтому проверка
#     конфигурации выполняется только в deploy-panel.sh, где она уместна;
#   named-checkconf -z    -- загружает все зоны, на большом сервере это
#     заметная нагрузка;
#   docker network create, docker pull -- любое изменение состояния демона.
#
# Вывод сохраняйте на своей машине, а не на сервере:
#   ssh root@<адрес> 'bash -s' < inventory.sh > inventory-$(date +%F).txt
# либо, если скрипт уже лежит на сервере:
#   sudo ./inventory.sh | tee /tmp/inventory.txt
# Второй вариант создаёт файл в /tmp -- это делает tee по вашему решению, сам
# скрипт ничего не пишет.
#
# Использование:
#   sudo ./inventory.sh [--domain mql5.ink] [--port 5577]
#
# set -e здесь намеренно НЕ включён: отчёт должен дойти до конца даже если
# половина команд отсутствует или отвечает ошибкой. Отсутствие команды -- это
# такой же результат инвентаризации, как её вывод.
set -uo pipefail

DOMAIN="mql5.ink"
SECOND_DOMAIN="vpn-service-api.pro"
APP_PORT="5577"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --port) APP_PORT="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

section() { printf '\n\n===== %s =====\n' "$*"; }
item() { printf '\n-- %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }

# Печатает команду и её вывод. Ненулевой код не прерывает отчёт.
run() {
  printf '\n$ %s\n' "$*"
  if ! have "$1"; then
    printf '   команда не найдена\n'
    return 0
  fi
  "$@" 2>&1 || printf '   (код возврата %s)\n' "$?"
}

# То же для конвейеров и подстановок: строка выполняется через sh -c.
runsh() {
  printf '\n$ %s\n' "$1"
  sh -c "$1" 2>&1 || printf '   (код возврата %s)\n' "$?"
}

show_file() {
  local f="$1" limit="${2:-200}"
  printf '\n--- %s\n' "$f"
  if [[ -r "$f" ]]; then
    head -n "$limit" -- "$f"
    local total
    total=$(wc -l < "$f" 2>/dev/null || echo '?')
    printf -- '--- (показано до %s строк из %s)\n' "$limit" "$total"
  elif [[ -e "$f" ]]; then
    printf '    существует, но недоступен для чтения текущему пользователю\n'
  else
    printf '    файла нет\n'
  fi
}

# ---------------------------------------------------------------------------
section "0. Общая информация об отчёте"

printf 'Отчёт снят: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
printf 'Хост: %s\n' "$(hostname -f 2>/dev/null || hostname 2>/dev/null)"
printf 'Пользователь: %s (uid %s)\n' "$(id -un 2>/dev/null)" "${EUID}"
printf 'Проверяемый домен панели: %s\n' "$DOMAIN"
printf 'Проверяемый порт приложения: %s\n' "$APP_PORT"

if [[ ${EUID} -ne 0 ]]; then
  printf '\nВНИМАНИЕ: скрипт запущен без root. Разделы про фаервол, конфигурацию\n'
  printf 'ISPmanager, владельцев сокетов и Docker будут неполными. Это не ошибка\n'
  printf 'скрипта: соответствующие данные просто недоступны непривилегированному\n'
  printf 'пользователю. Для полного отчёта повторите под sudo.\n'
fi

run uptime

# ---------------------------------------------------------------------------
section "1. Дистрибутив и ядро"

show_file /etc/os-release 40
run uname -a
runsh 'cat /etc/debian_version 2>/dev/null || cat /etc/redhat-release 2>/dev/null'
run getconf LONG_BIT

item "Менеджер пакетов"
runsh 'command -v apt-get >/dev/null && echo "apt (Debian/Ubuntu)"; command -v dnf >/dev/null && echo "dnf (RHEL-совместимый)"; command -v yum >/dev/null && echo "yum (RHEL-совместимый)"'

# ---------------------------------------------------------------------------
section "2. Панель ISPmanager"

item "Каталог панели"
runsh 'ls -la /usr/local/mgr5 2>/dev/null | head -n 30'

item "Пакеты панели"
# shellcheck disable=SC2016  # ${Package} -- формат dpkg-query, а не переменная bash
runsh 'dpkg-query -W -f="\${Package} \${Version}\n" 2>/dev/null | grep -i -E "ispmanager|coremanager|mgr5" || rpm -qa 2>/dev/null | grep -i -E "ispmanager|coremanager" || echo "пакеты панели не найдены штатным менеджером"'

item "Версия ядра панели"
runsh '/usr/local/mgr5/sbin/core -v 2>&1 | head -n 5'

# Пути, по которым панель раскладывает конфигурацию веб-серверов, берутся
# только из её собственного конфига: угадывать их нельзя, они различаются
# между Debian- и RHEL-сборками и между версиями панели.
item "Пути веб-серверов из ispmgr.conf"
runsh 'grep -E "^[[:space:]]*path[[:space:]]+(nginx|apache|httpd)" /usr/local/mgr5/etc/ispmgr.conf 2>/dev/null || echo "не прочитано: нет файла или нет прав"'

item "Прочие пути и параметры панели, влияющие на веб"
runsh 'grep -E "^[[:space:]]*(path|option)[[:space:]]+" /usr/local/mgr5/etc/ispmgr.conf 2>/dev/null | grep -i -E "vhost|conf|ctl|resource|include|restart|WebRestartDelay" || true'

item "Переопределённые шаблоны конфигурации (если есть -- их правил человек)"
runsh 'ls -la /usr/local/mgr5/etc/templates/ 2>/dev/null | grep -v "^d" | head -n 40'

# ---------------------------------------------------------------------------
section "3. Веб-серверы: что установлено и что работает"

item "Наличие и версии"
run nginx -v
run apache2 -v
run httpd -v
run openlitespeed -v
runsh 'command -v caddy >/dev/null && caddy version || true'

item "Собранные модули nginx"
runsh 'nginx -V 2>&1 | tr " " "\n" | grep -E "^--with|^--add" | sort | head -n 60'

item "Модули Apache (важны proxy, proxy_http, proxy_wstunnel, rewrite, headers)"
runsh 'apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null || apachectl -M 2>/dev/null || echo "список модулей не получен"'

item "Что из веб-серверов запущено"
runsh 'ps -eo pid,ppid,user,comm,args 2>/dev/null | grep -E "nginx|apache2|httpd|litespeed" | grep -v grep | head -n 30'

item "Связка nginx + apache или одиночный nginx"
note "Признак связки: в конфигурации сайтов nginx есть proxy_pass на локальный"
note "порт (обычно 81 или 8080), а Apache слушает именно этот порт."
runsh 'grep -rhoE "proxy_pass[[:space:]]+http://[0-9a-zA-Z._:-]+" /etc/nginx/vhosts 2>/dev/null | sort | uniq -c | sort -rn | head -n 20'
runsh 'grep -rhE "^[[:space:]]*Listen" /etc/apache2/ports.conf /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf 2>/dev/null'

item "Точки включения в главном конфиге nginx"
note "Отсюда видно, читается ли /etc/nginx/conf.d -- он понадобится, если"
note "решите вынести map для WebSocket на уровень http."
runsh 'grep -nE "^[[:space:]]*include" /etc/nginx/nginx.conf 2>/dev/null'

item "Существуют ли каталоги пользовательских дополнений"
runsh 'ls -ld /etc/nginx/vhosts /etc/nginx/vhosts-includes /etc/nginx/vhosts-resources /etc/nginx/users-resources /etc/nginx/conf.d 2>&1'
runsh 'ls -ld /etc/apache2/vhosts /etc/apache2/vhosts-includes /etc/apache2/vhosts-resources /etc/httpd/conf/vhosts /etc/httpd/conf/vhosts-resources 2>&1'

# ---------------------------------------------------------------------------
section "4. Список сайтов и где лежат их конфигурации"

item "Сколько сайтов обслуживает nginx"
runsh 'find /etc/nginx/vhosts -maxdepth 2 -name "*.conf" 2>/dev/null | wc -l'
runsh 'find /etc/nginx/vhosts -maxdepth 2 -name "*.conf" 2>/dev/null | sort | head -n 100'

item "Сколько сайтов обслуживает Apache"
runsh 'find /etc/apache2/vhosts /etc/httpd/conf/vhosts -maxdepth 2 -name "*.conf" 2>/dev/null | wc -l'
runsh 'find /etc/apache2/vhosts /etc/httpd/conf/vhosts -maxdepth 2 -name "*.conf" 2>/dev/null | sort | head -n 100'

item "Все server_name, которые обслуживает nginx"
runsh 'grep -rhE "^[[:space:]]*server_name" /etc/nginx/vhosts 2>/dev/null | sed "s/;.*//" | sort -u | head -n 200'

item "Корни сайтов"
runsh 'ls -la /var/www/www-root/data/www 2>/dev/null | head -n 100'

# ---------------------------------------------------------------------------
section "5. Домен ${DOMAIN}: конфигурация, корень, SSL"

item "Файлы конфигурации, где встречается домен"
runsh "grep -rl -- '${DOMAIN}' /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null | sort"

NGINX_VHOST=$(grep -rl -- "$DOMAIN" /etc/nginx/vhosts 2>/dev/null | head -n 1)
APACHE_VHOST=$(grep -rl -- "$DOMAIN" /etc/apache2/vhosts /etc/httpd/conf/vhosts 2>/dev/null | head -n 1)

if [[ -n "${NGINX_VHOST:-}" ]]; then
  item "Конфигурация nginx для ${DOMAIN}: ${NGINX_VHOST}"
  show_file "$NGINX_VHOST" 200
else
  item "Конфигурация nginx для ${DOMAIN} не найдена"
fi

if [[ -n "${APACHE_VHOST:-}" ]]; then
  item "Конфигурация Apache для ${DOMAIN}: ${APACHE_VHOST}"
  show_file "$APACHE_VHOST" 200
else
  item "Конфигурация Apache для ${DOMAIN} не найдена"
fi

item "Ключевые строки: корень, SSL, include, location"
note "Три вопроса, от ответа на которые зависит способ проксирования:"
note "  1) есть ли в server-секции include каталога vhosts-resources;"
note "  2) есть ли уже location / (тогда второй такой добавить нельзя);"
note "  3) есть ли отдельная server-секция для 443."
if [[ -n "${NGINX_VHOST:-}" ]]; then
  runsh "grep -nE 'server[[:space:]]*\{|listen|server_name|root|set \\\$root_path|ssl_certificate|include|location|proxy_pass' '${NGINX_VHOST}'"
fi

item "Сертификаты домена"
runsh "ls -la /etc/letsencrypt/live 2>/dev/null | head -n 40"
runsh "find /usr/local/mgr5/etc/manager /var/www/httpd-cert -maxdepth 2 -name '*${DOMAIN}*' 2>/dev/null | head -n 20"

item "Второй прямой домен ${SECOND_DOMAIN} (проверяем, что его не задеваем)"
runsh "grep -rl -- '${SECOND_DOMAIN}' /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null | sort"

# ---------------------------------------------------------------------------
section "6. Порты и слушатели"

item "Все слушающие сокеты"
runsh 'ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || echo "ни ss, ни netstat не найдены"'

item "Занят ли порт приложения ${APP_PORT}"
runsh "ss -lntp 2>/dev/null | grep -w ':${APP_PORT}' || echo 'порт ${APP_PORT} свободен (по данным ss)'"

item "Кто держит 80, 443, 1500, 22, 53"
runsh "ss -lntp 2>/dev/null | grep -E ':(80|443|1500|22|53)\b' || true"

item "Внешние адреса интерфейсов"
runsh 'ip -brief address 2>/dev/null || ifconfig -a 2>/dev/null | head -n 40'

# ---------------------------------------------------------------------------
section "7. Docker"

item "Наличие и версия"
run docker --version
runsh 'docker compose version 2>&1 | head -n 3'
runsh 'docker-compose --version 2>&1 | head -n 3'
# shellcheck disable=SC2016  # ${Package} -- формат dpkg-query, а не переменная bash
runsh 'dpkg-query -W -f="\${Package} \${Version}\n" 2>/dev/null | grep -i -E "docker|containerd" || rpm -qa 2>/dev/null | grep -i -E "docker|containerd" || true'

item "Демон запущен"
runsh 'systemctl is-active docker 2>&1; systemctl is-enabled docker 2>&1'
runsh 'docker info --format "server: {{.ServerVersion}} storage: {{.Driver}} cgroup: {{.CgroupDriver}} контейнеров: {{.Containers}}" 2>&1'
runsh 'docker info 2>&1 | grep -i -E "warning|iptables|bridge" | head -n 20'

item "Контейнеры и сети"
runsh 'docker ps -a --format "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>&1 | head -n 40'
runsh 'docker network ls 2>&1'

item "Подсети существующих сетей Docker"
note "Нужно для проверки пересечений с адресацией сервера и панели."
runsh 'docker network ls -q 2>/dev/null | xargs -r docker network inspect -f "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}" 2>&1'

item "Пул адресов по умолчанию, если он переопределён"
show_file /etc/docker/daemon.json 40

item "Таблица маршрутов: с чем может пересечься Docker"
runsh 'ip route show 2>&1 | head -n 40'

# ---------------------------------------------------------------------------
section "8. Фаервол: iptables, nftables, ufw"

item "Какая подсистема активна"
runsh 'iptables --version 2>&1'
runsh 'nft --version 2>&1'

item "Правила filter"
runsh 'iptables -S 2>&1 | head -n 120'

item "Правила nat (здесь живут цепочки DOCKER)"
runsh 'iptables -t nat -S 2>&1 | head -n 80'

item "Счётчики по цепочкам"
runsh 'iptables -L -n -v --line-numbers 2>&1 | head -n 120'

item "nftables"
runsh 'nft list ruleset 2>&1 | head -n 120'

item "ufw"
runsh 'ufw status verbose 2>&1'

item "firewalld"
runsh 'systemctl is-active firewalld 2>&1; firewall-cmd --state 2>&1'

item "fail2ban и его правила (важно: он может блокировать наш адрес)"
runsh 'systemctl is-active fail2ban 2>&1; fail2ban-client status 2>&1 | head -n 20'

item "Фаервол панели"
note "ISPmanager умеет управлять правилами сам. Если ниже видны цепочки с"
note "именами панели, любые ручные правки iptables могут быть перезаписаны."
runsh 'iptables -S 2>&1 | grep -i -E "isp|mgr|panel" || echo "цепочек с именем панели не видно"'

# ---------------------------------------------------------------------------
section "9. systemd и службы"

runsh 'systemctl --version 2>&1 | head -n 2'
runsh 'systemctl list-units --type=service --state=running --no-pager 2>&1 | head -n 60'
runsh 'systemctl is-active nginx apache2 httpd php-fpm ispmgr 2>&1'

# ---------------------------------------------------------------------------
section "10. Диск и память"

run df -h
runsh 'df -h /var/lib/docker /var/www /var 2>&1'
run free -m
runsh 'swapon --show 2>&1'
runsh 'nproc 2>&1'

item "Крупнейшие потребители места в /var (осторожно: чтение может занять время)"
runsh 'du -x -h -d 1 /var 2>/dev/null | sort -rh | head -n 15'

# ---------------------------------------------------------------------------
section "11. PHP"

runsh 'php -v 2>&1 | head -n 3'
runsh 'ls -d /opt/php* /usr/bin/php* /etc/php/* 2>/dev/null | head -n 40'
runsh 'ls /etc/php/*/fpm/pool.d 2>/dev/null | head -n 40'

# ---------------------------------------------------------------------------
section "12. cloudflared"

runsh 'command -v cloudflared >/dev/null && cloudflared --version 2>&1 || echo "cloudflared не установлен"'
runsh 'systemctl is-active cloudflared 2>&1'
runsh 'ls -la /etc/cloudflared 2>&1'
runsh 'ls /etc/apt/sources.list.d 2>/dev/null | head -n 40'

# ---------------------------------------------------------------------------
section "13. Служба DNS и обслуживаемые зоны"

item "Установлены ли серверы имён"
runsh 'command -v named >/dev/null && named -v 2>&1 || echo "bind (named) не найден"'
runsh 'command -v pdns_server >/dev/null && pdns_server --version 2>&1 || echo "powerdns не найден"'
runsh 'command -v nsd >/dev/null && nsd -v 2>&1 || true'
runsh 'command -v knotd >/dev/null && knotd -V 2>&1 || true'

item "Работает ли служба и слушает ли 53"
runsh 'systemctl is-active named bind9 pdns 2>&1'
runsh "ss -lnup 2>/dev/null | grep -w ':53' || true"

item "Зоны bind"
runsh 'grep -rhE "^[[:space:]]*zone[[:space:]]+\"" /etc/bind/named.conf* /etc/bind/*.conf /etc/named.conf /etc/named/*.conf 2>/dev/null | sed "s/[[:space:]]*{.*//" | sort -u | head -n 100'
runsh 'ls /etc/bind/zones /var/named /var/lib/bind 2>/dev/null | head -n 60'

item "Зоны PowerDNS"
runsh 'pdnsutil list-all-zones 2>&1 | head -n 100'

item "Зоны, которые ведёт панель"
runsh 'find /usr/local/mgr5/etc -maxdepth 2 -name "dns*" 2>/dev/null | head -n 20'

# ---------------------------------------------------------------------------
section "14. Что проверить глазами в отчёте"

cat <<'TXT'
Перед запуском deploy-panel.sh ответьте по отчёту на эти вопросы. Каждый из них
меняет план развёртывания, поэтому «наверное, так» не годится.

 1. Веб-сервер: только nginx, только Apache или связка nginx перед Apache?
    От этого зависит, в какой каталог кладётся фрагмент проксирования.
 2. Есть ли в конфигурации домена строка include с каталогом vhosts-resources?
    Если её нет, файл в этом каталоге не подключится, и настройка не заработает.
 3. Есть ли в server-секции домена location / ? Если есть, второй такой
    добавлять нельзя: nginx откажется перезагружаться с ошибкой duplicate
    location. Тогда работает только вариант с отдельным префиксом пути.
 4. Есть ли отдельная server-секция для 443, и подключается ли include в неё
    тоже? Если include есть только в HTTP-секции, панель будет доступна по
    http и недоступна по https.
 5. Свободен ли порт 5577 на loopback?
 6. Установлен ли Docker? Если нет -- решение об установке принимает владелец
    сервера отдельно, deploy-panel.sh его не поставит.
 7. Пересекаются ли подсети Docker с адресацией сервера и его сетей?
 8. Управляет ли фаерволом панель? Если да, ручные правила iptables недолговечны.
 9. Есть ли модуль proxy_wstunnel у Apache -- нужен только для варианта без
    nginx. Включение модуля перезапускает Apache и задевает все сайты.
10. Сколько свободно места под образы Docker (каталог /var/lib/docker)?
TXT

printf '\nОтчёт закончен. Ни один файл на сервере не изменён.\n'
