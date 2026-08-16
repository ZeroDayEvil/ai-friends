# Аудит цепочки поставок electerm (Агент 2)

Дата: 2026-08-15  
Режим проверки: **только статический анализ**, без запуска скачанного кода (`npm install`, `cargo`, `.sh`, `.bat`, docker-образов и бинарников).

## 1) Зафиксированные HEAD SHA

- `electerm-web`: `ab011d652e3750cb21b8f49bc0f3504f283036cd`
- `electerm`: `0cd7196514b24fe0f696cd1ea8210857b2218070`
- `electerm-web-docker`: `8c8599159ff6cf11d63276a69a14c73ccd86bf9a`
- `ironrdp-wasm`: `103e36ba0bcfeb1950b2ff2d94cc4897588fcfc9`
- `rdpjs`: `b41e45ee6fef23672d1d5972d14b0d099bf89933`
- `electerm-sync-server-cloudflare`: `f37fe9fed9cead82e63a07e4b1cb18b4d875fdc4`
- `electerm-sync-server-edgeone`: `c6655bd78540e65ed8b45ce6e6ce49b397868f32`
- `lite-http-tunnel`: `12e400aa1c1be81b66d27b4844118ed57cc7dbb0`
- `websockify`: `3dd228b81ade1ff76a27ad12eed6e78df8c6f8a6`
- `goproxy`: `e6d6a821db80e7f47ee6e981a144984e1d4ddb3d`

---

## 2) Ключевые находки (с вердиктами)

### F-01. README предлагает запуск удалённого скрипта через pipe в shell

- **Что это:** документированная установка через `curl|bash` / `wget|bash`.
- **Место:** `C:\audit-workspace\electerm-web\README.md:126`, `:131`; также Windows-вариант `:137-138`.
- **Откуда качается:** `https://electerm.org/scripts/one-line-web.sh` и `https://electerm.org/scripts/one-line-web.bat`.
- **Риск:** удалённый код с внешнего домена (вне GitHub), без подписи/чек-суммы, с последующим исполнением.
- **Вердикт:** **вырезать**. Внутри контура не использовать.

### F-02. `one-line-web.sh` разворачивает непинованный HEAD и запускает `npm install`

- **Что это:** shell-скрипт установки Linux/macOS.
- **Место:** `C:\audit-workspace\one-line-web.sh:81` (clone `--depth 1`), `:86` (`npm install`), `:89` (`npm run build`), `:112` (`node ./src/app/app.js`).
- **Откуда качается:** `https://github.com/electerm/electerm-web.git` + npm-реестр(ы) из lock-файла.
- **Риск:** неповторяемая поставка (ветка `main`), выполнение install-скриптов дерева зависимостей.
- **Вердикт:** **вырезать**.

### F-03. `one-line-web.bat` делает то же для Windows

- **Что это:** batch-установщик.
- **Место:** `C:\audit-workspace\one-line-web.bat:67` (clone `--depth 1`), `:80` (`npm install`), `:87` (`npm run build`), `:114` (запуск приложения).
- **Откуда качается:** GitHub + npm-реестр.
- **Риск:** те же риски непинованной поставки и исполнения чужих install-скриптов.
- **Вердикт:** **вырезать**.

### F-04. В lock-файле есть неофициальный npm mirror

- **Что это:** часть tarball-URL ведёт на `registry.npmmirror.com`.
- **Место:** `C:\audit-workspace\electerm-web\package-lock.json:110` (первый пример), далее аналогично; обнаружено 53 `resolved`-записи на этот хост.
- **Откуда качается:** `https://registry.npmmirror.com/...`.
- **Риск:** обход официального источника (`registry.npmjs.org`), рост риска подмены артефактов.
- **Вердикт:** **заменить официальным источником** (`registry.npmjs.org`) и перегенерировать lock.

### F-05. У корневого проекта есть install-хук

- **Что это:** root install script.
- **Место:** `C:\audit-workspace\electerm-web\package.json:15` (`"install": "node build/bin/install"`), код скрипта — `C:\audit-workspace\electerm-web\build\bin\install.js:5-9`.
- **Откуда качается:** локальный скрипт, но запускается в ходе `npm install`.
- **Риск:** любой `npm install` уже является исполнением кода до runtime.
- **Вердикт:** **закрепить версию** + на CI/сборке использовать `npm ci --ignore-scripts` и явный whitelist.

### F-06. Нативные модули с install-скриптами и prebuilt-бинарниками

- **Что это:** install-хуки у `node-pty` и транзитивно у `@serialport/bindings-cpp`.
- **Место:**
  - `C:\audit-workspace\electerm-web\package-lock.json:7988` (`node-pty` hasInstallScript),
  - `C:\audit-workspace\electerm-web\package-lock.json:2260` (`@serialport/bindings-cpp` hasInstallScript),
  - `C:\audit-workspace\npm-src\node-pty-1.2.0-beta.15\package\package.json:42-43`,
  - `C:\audit-workspace\npm-src\bindings-cpp-13.0.0\package\package.json:57-61`.
- **Откуда качается:** tarball-ы с `https://registry.npmjs.org` (`node-pty`, `@serialport/bindings-cpp`), внутри уже лежат prebuilt `*.node`/DLL/EXE/WASM.
- **Риск:** поставка бинарных артефактов без локальной воспроизводимой сборки; install-хуки исполняются при установке.
- **Вердикт:** **закрепить версию** (в реестре и lock), по возможности собирать из исходников в доверенном CI.

### F-07. В коде есть механизм динамической догрузки npm-модулей во время работы

- **Что это:** runtime загрузчик пакетов и рекурсивный fetch зависимостей.
- **Место:**
  - `C:\audit-workspace\electerm-web\src\app\lib\npm.js:8` (реестр), `:12` (GET `latest`), `:47-53` (скачивание tarball),
  - `C:\audit-workspace\electerm-web\src\app\lib\custom-require.js:43`, `:58` (вызов `downloadPackage`).
- **Откуда качается:** по умолчанию `https://registry.npmjs.org` (или произвольный `NPM_REGISTRY` из env).
- **Риск:** удалённая догрузка и импорт кода в runtime (не только на этапе сборки).
- **Вердикт:** **вырезать** (или жёстко отключить в production).

### F-08. Sync-функции используют внешние API GitHub/Gitee и cloud endpoint

- **Что это:** сетевые endpoint-ы синхронизации закладок/данных.
- **Место:**
  - `C:\audit-workspace\npm-src\electerm-sync-2.0.1\package\dist\esm\electerm-sync.mjs:30` (`https://api.github.com`),
  - `...:32` (`https://gitee.com/api/v5`),
  - `C:\audit-workspace\npm-src\electerm-react-5.1.20\package\client\components\setting-sync\setting-sync-form.jsx:70` (`https://sync.electerm.org/api/sync`).
- **Откуда качается/куда ходит:** внешние API GitHub/Gitee/electerm cloud.
- **Риск:** вывод пользовательских данных за периметр.
- **Вердикт:** **заменить официальным источником** (в данном случае — self-hosted sync endpoint) для внутреннего контура.

### F-09. Дефолтные AI endpoint-ы включают внешние SaaS

- **Что это:** предустановленные URL для AI-провайдеров.
- **Место:**
  - `C:\audit-workspace\electerm-web\src\app\lib\view.js:24` (`https://ai.electerm.org/api/ai`),
  - `C:\audit-workspace\electerm-web\src\app\common\default-setting.js:62` (`https://api.atlascloud.ai/v1`),
  - `C:\audit-workspace\npm-src\electerm-react-5.1.20\package\client\components\ai\ai-config-props.js:17-121` (OpenAI/Groq/Mistral/etc.).
- **Откуда качается/куда ходит:** внешние AI API.
- **Риск:** утечка промптов/секретов/текстов команд при включении AI-функций.
- **Вердикт:** **вырезать** (или оставить только внутренний endpoint).

### F-10. Канал проверки обновлений и mirror-URL в клиентском коде

- **Что это:** fallback и mirror для загрузки релизов.
- **Место:**
  - `C:\audit-workspace\npm-src\electerm-react-5.1.20\package\client\common\constants.js:204-206`,
  - `C:\audit-workspace\npm-src\electerm-react-5.1.20\package\client\common\update-check.js:77`, `:81`, `:83`.
- **Откуда качается:** `electerm-mirror.html5beta.com`, `master.dl.sourceforge.net`, `electerm-store.html5beta.com`.
- **Риск:** обновления не из официального единственного канала.
- **Вердикт:** **вырезать** (или перевести на строго pinned внутренний канал).

### F-11. Docker-образы указаны тегами без digest

- **Что это:** mutable image references.
- **Место:**
  - `C:\audit-workspace\electerm-web-docker\Dockerfile.ubuntu:3` (`FROM node:24`),
  - `C:\audit-workspace\electerm-web-docker\docker-compose.yml:5` (`zxdong262/electerm-web:latest`),
  - `C:\audit-workspace\electerm-web-docker\run.sh:13` (`zxdong262/electerm-web`),
  - `C:\audit-workspace\lite-http-tunnel\Dockerfile:1` (`FROM node:16`),
  - `C:\audit-workspace\websockify\docker\Dockerfile:1` (`FROM python`).
- **Откуда качается:** Docker Hub/OCI registry по изменяемым тегам.
- **Риск:** дрейф артефактов и невозможность воспроизведения.
- **Вердикт:** **закрепить версию** (через `@sha256:...`).

### F-12. Dockerfile для electerm-web строит образ из непинованного исходника

- **Что это:** build-time clone и install внутри контейнера.
- **Место:** `C:\audit-workspace\electerm-web-docker\Dockerfile.ubuntu:40-44`.
- **Откуда качается:** `https://github.com/electerm/electerm-web.git` (HEAD), npm registry.
- **Риск:** supply-chain drift при каждой сборке образа.
- **Вердикт:** **заменить официальным источником** (пинованный commit/архив + pinned digest base image).

### F-13. В `rdpjs` есть крупный сгенерированный JS-артефакт

- **Что это:** файл с признаками Emscripten-generated кода.
- **Место:** `C:\audit-workspace\rdpjs\rdp\core\rle.js:1-2` (комментарии о Emscripten), размер ~501 KB.
- **Откуда качается:** уже лежит в репозитории как готовый артефакт.
- **Риск:** сложность ревью, риск незаметной подмены, слабая воспроизводимость.
- **Вердикт:** **вырезать** (или хранить только исходники + воспроизводимую сборку в CI).

### F-14. Лицензии и способ поставки у референсов отличаются по риску

- **Что это:** сравнение `websockify` vs `goproxy` (только как референсы подхода).
- **Место:**
  - `websockify`: `C:\audit-workspace\websockify\COPYING:1` (LGPL-3.0),
  - `goproxy`: `C:\audit-workspace\goproxy\LICENSE:1` (GPL-3.0), `README.md:95-102` (автоустановка через `curl`/`bash`).
- **Откуда качается:** GitHub и install-скрипты.
- **Риск:** copyleft-ограничения + небезопасный bootstrap.
- **Вердикт:**
  - `websockify` — **оставить** только как reference design, код не копировать в закрытый продукт.
  - `goproxy` — **вырезать**.

---

## 3) Построчный разбор скриптов `electerm.org` (без выполнения)

### `one-line-web.sh` (`sha256:3257acf987052e3b9cd87f8f1f9f5a7ac3724dd69ea8357f3916746364a3fd59`)

- `4-34`: функция проверки наличия бинарей (`git`, `node`, `npm`, `python3`).
- `17`: подсказывает установку `fnm` через `curl ... | bash` (ещё один удалённый bootstrap).
- `37-72`: проверка версии Node (>=20) и системных build-tools.
- `81`: `git clone --depth 1 https://github.com/electerm/electerm-web.git`.
- `86`: `npm install` (исполнение install/postinstall скриптов дерева зависимостей).
- `89`: `npm run build`.
- `92`: копирование `.sample.env` в `.env`.
- `95-109`: генерация `SERVER_SECRET`, вычисление `DB_PATH`, правка `.env`.
- `112`: запуск `NODE_ENV=production node ./src/app/app.js`.

### `one-line-web.bat` (`sha256:2ae67621a1ff51f1b2422c869ea4bf23f28a72dc5bdc74e91c2f60c07a1060e5`)

- `10-62`: проверки `git/node/npm/python3` и build-tools.
- `67`: `git clone --depth 1 https://github.com/electerm/electerm-web.git`.
- `80`: `call npm install`.
- `87`: `call npm run build`.
- `94`: `copy .sample.env .env`.
- `101-110`: генерация `SERVER_SECRET`, установка `DB_PATH`, правка `.env`.
- `114`: запуск `node ./src/app/app.js`.

---

## 4) Адреса в коде и конфигах: что нужно для работы, а что нет

Ниже — только операционно значимые endpoint-ы (документационные ссылки на wiki/README не перечисляю повторно).

- `https://registry.npmjs.org` — `C:\audit-workspace\electerm-web\src\app\lib\npm.js:8,12`; **не требуется** для штатной работы терминала, нужен только механизму динамической догрузки модулей.
- `https://api.github.com` / `https://gitee.com/api/v5` — `C:\audit-workspace\npm-src\electerm-sync-2.0.1\package\dist\esm\electerm-sync.mjs:30,32`; **нужно только** для sync в gist.
- `https://sync.electerm.org/api/sync` — `C:\audit-workspace\npm-src\electerm-react-5.1.20\package\client\components\setting-sync\setting-sync-form.jsx:70`; **опционально**, заменить self-hosted.
- `https://ai.electerm.org/api/ai` — `C:\audit-workspace\electerm-web\src\app\lib\view.js:24`; **опционально** (AI-фича), для закрытого контура отключить.
- `https://api.atlascloud.ai/v1` + прочие AI-провайдеры — `C:\audit-workspace\electerm-web\src\app\common\default-setting.js:62`, `C:\audit-workspace\npm-src\electerm-react-5.1.20\package\client\components\ai\ai-config-props.js:17-121`; **опционально**, высокий риск утечки данных.
- `https://electerm-mirror.html5beta.com`, `https://master.dl.sourceforge.net/project/electerm.mirror`, `https://electerm-store.html5beta.com` — `...update-check.js:77,81,83`; **не нужно** для базовой работы терминала, это канал автообновлений/зеркал.

---

## 5) Docker-образы без digest

- `node:24` — `C:\audit-workspace\electerm-web-docker\Dockerfile.ubuntu:3`
- `zxdong262/electerm-web:latest` — `C:\audit-workspace\electerm-web-docker\docker-compose.yml:5`
- `zxdong262/electerm-web` (implicit `latest`) — `C:\audit-workspace\electerm-web-docker\run.sh:13`
- `node:16` — `C:\audit-workspace\lite-http-tunnel\Dockerfile:1`
- `python` — `C:\audit-workspace\websockify\docker\Dockerfile:1`

Вердикт для всех: **закрепить версию** через digest.

---

## 6) Собранные артефакты в репозиториях и воспроизводимость

- `C:\audit-workspace\rdpjs\rdp\core\rle.js` — сгенерированный Emscripten-артефакт (`:1-2`), исходный pipeline в этом репозитории явно не описан → воспроизводимость **не подтверждена**.
- `C:\audit-workspace\ironrdp-wasm` — готового `pkg/*.wasm` в git нет; есть скрипт сборки `bin/build.js:22` (`wasm-pack build`) → артефакт можно собирать локально/в CI.

---

## 7) Что проверить не удалось и почему

1. **Фактическое поведение install-скриптов при установке** — не проверялось, потому что запуск `npm install`/`npm ci` прямо запрещён брифом.
2. **Содержимое prebuilt-бинарников (`*.node`, `*.dll`, `*.wasm`) на предмет закладок** — без их исполнения и без отдельного реверса можно подтвердить только источник и хеши, но не безопасность бинаря.
3. **Полная карта всех URL внутри минифицированных/сгенерированных blob-файлов и внешних npm-пакетов** — покрыты ключевые runtime endpoint-ы и критичные компоненты, но exhaustive coverage по всей транзитивной экосистеме npm без исполнения ограничена.
4. **Доступ к `electerm.org` через встроенный WebFetch** — инструмент вернул `500`; скрипты были получены прямой загрузкой с хоста в отдельную рабочую папку для статического чтения.

