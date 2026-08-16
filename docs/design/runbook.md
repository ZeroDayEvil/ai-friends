# Регламент развёртывания

Порядок важен: каждый шаг опирается на предыдущий, а два шага способны отрезать
доступ к машине, если сделать их раньше времени. Они отмечены отдельно.

## 0. Что нужно иметь на руках

- Linux VPS, Ubuntu 24.04, root по SSH-ключу;
- домен в зоне Cloudflare;
- аккаунт Cloudflare Zero Trust (бесплатного плана достаточно);
- список сотрудников с рабочими адресами почты;
- доступ администратора на Windows-цели.

## 1. Образ платформы

Собирается из форка и публикуется в реестр, откуда его возьмёт узел.

```bash
cd apps/electerm-web
docker build -t <реестр>/electerm-platform:5.1.20 .
docker push <реестр>/electerm-platform:5.1.20
docker buildx imagetools inspect <реестр>/electerm-platform:5.1.20 | grep Digest
```

Полученный digest подставляется в `.env` узла как `APP_IMAGE`. Тег в `.env` не
используется: тег можно перезаписать, digest нет.

## 2. Узел

```bash
scp -r infra/vps root@<адрес>:/opt/setup
ssh root@<адрес>
cd /opt/setup
./setup-server.sh --admin-ip <ваш адрес> --skip-app
```

`--skip-app` на первом проходе нужен потому, что приложению ещё нечего
запускать: `.env` не заполнен. После первого прохода:

```bash
mkdir -p /opt/electerm-platform
cp /opt/setup/.env.sample /opt/electerm-platform/.env
# заполнить: APP_IMAGE, POSTGRES_IMAGE, POSTGRES_PASSWORD, SERVER_SECRET
./setup-server.sh --admin-ip <ваш адрес>
```

`SERVER_SECRET` — случайные 32 байта: `openssl rand -hex 32`. Он подписывает
токены приложения, и его смена разлогинивает всех.

Проверка: `docker compose -f /opt/electerm-platform/docker-compose.yml ps` и
`curl -sI http://127.0.0.1:5577/` возвращает 200. Снаружи порт недоступен, и это
правильно: наружу его отдаст только туннель.

## 3. Туннель

```bash
cloudflared tunnel login
cloudflared tunnel create platform
cp /opt/setup/../cloudflare/config.sample.yml /etc/cloudflared/config.yml
# подставить tunnel id и имя хоста
cloudflared tunnel route dns platform <имя>.<домен>
cloudflared service install
systemctl enable --now cloudflared
```

Проверка: имя открывается из интернета, при этом порт 443 на узле закрыт.

## 4. Политика доступа

В Zero Trust: приложение типа Self-hosted на то же имя хоста, политика с
перечислением адресов почты сотрудников и обязательным вторым фактором.

Из настроек приложения берутся `AUD` и домен команды, они прописываются в `.env`
как `CF_ACCESS_AUD` и `CF_ACCESS_TEAM_DOMAIN`, после чего
`docker compose up -d` перезапускает приложение уже в командном режиме.

Проверка, без которой шаг не считается выполненным: в логах приложения при
старте есть строка `[auth] Cloudflare Access enabled`, а прямой запрос к
`http://127.0.0.1:5577/` с самого узла возвращает 401. Второе важнее первого:
оно доказывает, что приложение проверяет личность само, а не полагается на то,
что запрос пришёл через туннель.

## 5. Меш

На узле поднимается интерфейс `wg0` с адресом `10.99.0.1/24` и портом 51820,
затем для каждой машины выдаётся конфиг:

```bash
./infra/wireguard/new-peer.sh --name winsrv-01 --address 10.99.0.11 \
  --endpoint <имя>.<домен>
```

Вывод переносится на целевую машину. На Windows это конфиг для клиента
WireGuard; после подключения проверяется `ping 10.99.0.1`.

## 6. Windows-цели

```powershell
.\setup-windows-target.ps1 -EnsureSsh
.\install-pubkey-on-server.ps1 -User <администратор>
.\harden-ssh.ps1
.\setup-windows-target.ps1 -Harden
.\setup-windows-target.ps1 -CreateUsers 'ivanov','petrov'
```

Многосеансовый RDP на серверных версиях (перезагрузка, начинается 120-дневный
льготный период, дальше нужны лицензии RDS):

```powershell
.\setup-windows-target.ps1 -InstallSessionHost
```

**Шаг, способный отрезать доступ.** Сужение доступа до подсети меша выполняется
только после того, как машина отвечает через меш:

```powershell
.\setup-windows-target.ps1 -MeshOnly
```

Скрипт сам проверяет доступность концентратора и откажется применять правила,
если меша нет. Проверять всё равно стоит вручную: на облачной машине потеря
доступа означает пересоздание.

## 7. Приёмка

```powershell
.\scripts\qa\check-target.ps1
node scripts\check-pins.mjs
```

Отчёты складываются в `docs/audit/`. Пока в отчёте есть блокирующие дефекты,
доступ сотрудникам не выдаётся.

## Порядок отзыва доступа у сотрудника

1. Убрать адрес из политики Access — новый вход закрыт немедленно.
2. Перезапустить приложение на узле — активные токены станут недействительны.
   До появления серверного хранилища сессий это единственный способ прервать уже
   выданный токен; его срок жизни иначе 12 часов.
3. Отключить учётную запись на целевых машинах: `Disable-LocalUser`.
