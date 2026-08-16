# Перенос реестра docs/agents/TASKS.md в issues репозитория.
#
# Данные уходят файлами в UTF-8 через gh api, а не аргументами командной строки:
# PowerShell 5.1 перекодирует кириллицу в аргументах по кодовой странице консоли
# и заголовки issues приезжают в мусоре.
#
# Скрипт идемпотентен: issue с таким же заголовком повторно не создаётся.

[CmdletBinding()]
param(
    [string]$Repo = 'ZeroDayEvil/ai-friends'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Invoke-GhJson {
    param([string]$Method, [string]$Endpoint, [hashtable]$Body)

    $tmp = Join-Path $env:TEMP ([guid]::NewGuid().ToString() + '.json')
    $json = $Body | ConvertTo-Json -Depth 6 -Compress
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $raw = & gh api -X $Method $Endpoint --input $tmp 2>&1
        return [string]::Join("`n", $raw)
    }
    finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

$labels = @(
    @{ name = 'agent-1'; color = '1d76db'; description = 'Оркестратор: инфраструктура и сборка' },
    @{ name = 'agent-2'; color = '5319e7'; description = 'Аудит цепочки поставок' },
    @{ name = 'agent-3'; color = '0e8a16'; description = 'Совместимость и приёмка' },
    @{ name = 'blocked'; color = 'b60205'; description = 'Ждёт внешнего ресурса' },
    @{ name = 'wip'; color = 'fbca04'; description = 'В работе' },
    @{ name = 'owner-action'; color = 'd93f0b'; description = 'Требует действий владельца инфраструктуры' }
)

Write-Host '== Метки =='
foreach ($l in $labels) {
    $out = Invoke-GhJson -Method POST -Endpoint "repos/$Repo/labels" -Body $l
    if ($out -match 'already_exists') { Write-Host ("  {0}: уже есть" -f $l.name) }
    elseif ($out -match '"id"') { Write-Host ("  {0}: создана" -f $l.name) }
    else { Write-Host ("  {0}: {1}" -f $l.name, $out) }
}

$issues = @(
    @{
        title  = 'multiuser: PostgreSQL, изоляция процессов и отзыв активных сессий'
        labels = @('agent-1', 'wip')
        body   = @'
Осталась последняя часть многопользовательскости. Уже сделано: личность через
проверку токена Cloudflare Access, владение сессиями и проверка прав на машину
на сервере.

Осталось:
- перевести хранилище с файлового на PostgreSQL, чтобы несколько экземпляров
  платформы работали с общим состоянием;
- изолировать процессы сессий между сотрудниками;
- отзывать активные сессии при снятии прав, сейчас снятие права не разрывает
  уже открытое подключение.

Внешних ресурсов не требует, можно делать сразу. Проект: `docs/design/fork.md`.
'@
    },
    @{
        title  = 'vps-infra: выделенный Linux-узел под панель'
        labels = @('agent-1', 'blocked', 'owner-action')
        body   = @'
Сервер `202.155.8.133` обследован 16.08.2026 и признан непригодным для боевой
панели: бесплатный хостинг с автоматической регистрацией, все сайты под одним
пользователем `www-root` без изоляции, среди соседних зон есть похожие на
инфраструктуру доставки вредоносного ПО, а панель, запасной вход и серверы имён
находятся на том же узле.

Нужен выделенный сервер: Ubuntu 24.04, 2 vCPU, 4 ГБ RAM, 60-80 ГБ SSD, root по
ключу. Заказан, ожидается выдача.

Отчёт: `docs/audit/vps-inventory-2026-08-16.md`. Порядок развёртывания:
`docs/design/runbook.md`.
'@
    },
    @{
        title  = 'panel-deploy: размещение PHP-панели, работающей с AnibusBase'
        labels = @('agent-1', 'blocked', 'owner-action')
        body   = @'
Панель — существующее PHP-приложение, работающее с базой `AnibusBase`, а не
Node-форк платформы. Кода пока нет, размещать нечего.

Технически площадка проверена: PHP 8.3 с `pdo_mysql` есть, база достижима,
каталог под домен пуст. Но размещение приостановлено до выделенного сервера по
причинам из задачи про `vps-infra`.

Комплект для безопасного развёртывания на ISPmanager без задевания чужих сайтов:
`infra/vps/ispmanager/` вместе с `SAFETY.md` и `rollback.md`.
'@
    },
    @{
        title  = 'cf-access: включить Zero Trust и поднять туннель'
        labels = @('agent-1', 'blocked', 'owner-action')
        body   = @'
Код готов: конфигурация туннеля, проверка токена Access на стороне приложения и
декларативная автоматизация в `infra/cloudflare/`. Без действительного токена
приложение отвечает 401 на любой запрос, включая WebSocket.

Состояние аккаунта проверено чтением 16.08.2026: зон нет, Zero Trust не включён,
два домена не зарегистрированы.

От владельца нужно: включить Zero Trust и сообщить team name, добавить домен в
Cloudflare со сменой серверов имён, дать список адресов почты сотрудников для
политики доступа.

Отчёт: `docs/audit/cloudflare-readiness-2026-08-16.md`.
'@
    },
    @{
        title  = 'dns-delegation: три дефекта делегирования доменов'
        labels = @('agent-1', 'blocked', 'owner-action')
        body   = @'
Найдены дефекты, которые чинятся только у регистраторов владельцем:

1. glue-запись `ns2.hydradns.click` указывает на `127.0.0.1`, то есть второй
   сервер имён нерабочий и резервирования нет;
2. `hydradns.inc` не существует как зона, делегировать на него нельзя;
3. прямые домены зависят от того же узла, который признан непригодным.

Инструкция с точными значениями записей: `docs/design/dns-cloudflare-setup.md`.
'@
    },
    @{
        title  = 'mesh: узел-концентратор WireGuard'
        labels = @('agent-1', 'blocked')
        body   = @'
Скрипты меша готовы и проверены на синтаксис. Нужен узел-концентратор с
постоянным адресом — тот же выделенный сервер, что и для панели.

После подъёма концентратора доступ к машинам по SSH и VNC ограничивается
подсетью меша вместо открытых портов.
'@
    },
    @{
        title  = 'compat-matrix: приёмка на Win10, Win11, Server 2016/2019/2022'
        labels = @('agent-3', 'blocked', 'owner-action')
        body   = @'
Server 2025 принят полностью: дефект устранён, подъём после перезагрузки
проверен на практике, приёмка даёт FAIL=0.

Для пяти остальных систем нет машин. Нужны Win10, Win11, Server 2016, 2019, 2022
с доступом администратора, по одной на систему, можно последовательно на одной и
той же машине с откатом.

Отчёт по принятой системе: `docs/audit/qa-2026-08-15-windows-target.md`.
'@
    },
    @{
        title  = 'Реестр контейнеров для образа платформы'
        labels = @('owner-action')
        body   = @'
Образ платформы собирается локально из закреплённых версий. Чтобы серверы брали
готовый образ, а не собирали его у себя, нужен реестр. GitHub Packages подойдёт
и отдельной оплаты для приватного репозитория не требует.

После появления реестра публикация образа добавляется в CI отдельным шагом с
проверкой, что теги неизменяемые.
'@
    },
    @{
        title  = 'Абьюз на бесплатном хостинге 202.155.8.133'
        labels = @('owner-action')
        body   = @'
По тому же адресу живут фишинговые и похожие на вредоносные домены. Пока это так,
блокировка адреса или зоны провайдером унесёт вместе с ними любой наш сервис,
размещённый рядом.

Отсюда решение переносить боевые службы на выделенный сервер. Если на этом узле
что-то остаётся, риск нужно принять осознанно и вынести из него всё, что связано
с доступом к машинам сотрудников.

Подробности: `docs/audit/vps-inventory-2026-08-16.md`.
'@
    },
    @{
        title  = 'Защита ветки main требует тарифа GitHub Pro'
        labels = @('owner-action')
        body   = @'
Запрос на включение защиты `main` отвечает 403: «Upgrade to GitHub Pro or make
this repository public to enable this feature». Тариф аккаунта — GitHub Free.

Подписка Copilot тарифицируется отдельно и прав на приватные репозитории не даёт,
повышение её уровня этот отказ не снимает.

Варианты:
- GitHub Pro, около $4 в месяц: репозиторий остаётся приватным, включаются защита
  ветки и обязательные проверки;
- сделать репозиторий публичным: защита бесплатна, но наружу уйдут адреса
  серверов и отчёты обследований из `docs/audit`, поэтому не рекомендуется;
- работать без защиты: CI на пул-реквестах запускается и падения видны, не
  блокируется только само слияние.

Пока действует третий вариант.
'@
    }
)

Write-Host ''
Write-Host '== Задачи =='
$existing = (& gh api "repos/$Repo/issues?state=all&per_page=100" | ConvertFrom-Json)
$existingTitles = @($existing | ForEach-Object { $_.title })

foreach ($i in $issues) {
    if ($existingTitles -contains $i.title) {
        Write-Host ("  уже есть: {0}" -f $i.title)
        continue
    }
    $out = Invoke-GhJson -Method POST -Endpoint "repos/$Repo/issues" -Body $i
    $obj = $null
    try { $obj = $out | ConvertFrom-Json } catch { }
    if ($obj -and $obj.number) { Write-Host ("  #{0}  {1}" -f $obj.number, $i.title) }
    else { Write-Host ("  ОШИБКА: {0}`n    {1}" -f $i.title, $out) }
}
