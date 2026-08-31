# Политика зависимостей и закрепления версий

## Принципы

1. Источником считается только официальный репозиторий проекта или официальный
   реестр пакетов. Скрипты установки со сторонних доменов и зеркала не
   используются, даже если так написано в документации проекта.
2. Всё закрепляется точной версией: npm — через `package-lock.json` и `npm ci`,
   docker — через digest (`image@sha256:...`), а не тег, git — через коммит,
   а не ветку. Тег и ветка могут быть переписаны, digest и коммит — нет.
3. Установка выполняется с `--ignore-scripts`. Пакеты, которым скрипты
   действительно нужны для сборки, перечисляются явным белым списком с
   обоснованием.
4. Обновление зависимостей — отдельное изменение с отдельным ревью. Автоматические
   обновления запрещены: неконтролируемое обновление это ровно тот риск, от
   которого мы уходим.
5. Во время работы приложение не должно обращаться наружу, кроме адресов,
   перечисленных в egress-политике. Всё остальное блокируется файрволом на узле,
   чтобы забытый вызов не прошёл незамеченным.

## Почему `--ignore-scripts`

`npm install` выполняет `preinstall`, `install` и `postinstall` любого пакета в
дереве зависимостей с правами текущего пользователя. Это основной путь атаки на
цепочку поставок в npm: компрометация одного транзитивного пакета даёт исполнение
кода на машине сборки. Нативные модули этим механизмом скачивают готовые
бинарники, поэтому для них нужен либо явный белый список, либо сборка из
исходников у нас.

## Схема `externals.json`

```json
{
  "version": 1,
  "generated": "2026-08-15",
  "items": [
    {
      "id": "electerm-web",
      "kind": "git",
      "official_source": "https://github.com/electerm/electerm-web",
      "pin": "commit:<sha>",
      "license": "MIT",
      "network_at_runtime": [],
      "install_scripts": false,
      "verdict": "keep",
      "notes": "основа форка"
    }
  ]
}
```

Поля:

- `kind` — `git`, `npm`, `docker`, `binary`, `script`, `endpoint`;
- `pin` — `commit:<sha>`, `version:<x.y.z>`, `digest:sha256:<...>`, `sha256:<...>`;
- `network_at_runtime` — адреса, к которым обращается компонент в работе;
- `install_scripts` — есть ли исполняемые скрипты установки;
- `verdict` — `keep`, `replace`, `pin`, `remove`.

## Импортированные деревья

`apps/electerm-web` — это не локальная рабочая копия, а намеренно
версионируемый снимок upstream. Каждый непосредственный каталог в `apps/` и,
при появлении, в `vendor/` обязан иметь ровно один `security/*.lock.json`.
У lock-файла есть `external_id` из `externals.json` и `source_root`; claim
несуществующего, вложенного, пересекающегося или повторно заявленного дерева
отвергается.

`security/upstream.lock.json` фиксирует:

- полный Git commit и tree SHA;
- exact raw Git commit content в canonical base64, его SHA-256, tree, parent,
  author, committer и UTF-8 message;
- commit-bound URL, размер и SHA-256 архива GitHub codeload;
- точный список файлов, их размеры, SHA-256 и Git blob SHA-1;
- MIT-лицензию и результат проверки подписи коммита.

`node scripts/check-pins.mjs` только читает JSON и байты файлов. Он не
устанавливает пакеты, не вызывает lifecycle-скрипты и не импортирует код из
`apps/electerm-web`. Он локально реконструирует `tree <len>\0...` и
`commit <len>\0...` из lock-файла, требует равенства полученного commit SHA-1
external pin и равенства raw commit `tree` header реконструированному source
tree. Он сверяет весь снимок с lock-файлом, отвергает ссылки и не позволяет
добавить незафиксированный файл. При импорте архив дополнительно проверяется
на reparse path до извлечения.

`node scripts/check-pins.mjs --online` добавляет bounded read-only проверку
только с `api.github.com` и `codeload.github.com`: Git commit/tree metadata и
архив сверяются с lock-файлом, с лимитом 5 MiB на JSON и 64 MiB на архив.
CI выполняет оба режима; ни один не извлекает или исполняет upstream-код.
Отдельная ShellCheck job анализирует только shell-скрипты, принадлежащие этому
репозиторию: immutable upstream shell-файлы покрывает hash/policy verifier, а
не стиль чужого исходного кода.

Намеренные исключения лежат в `security/policy-exceptions.json`. Каждое
исключение ограничено конкретным путём и SHA-256 неизменённого upstream-файла;
широких исключений для `apps/`, `node_modules` или generated/vendor деревьев
нет. Поэтому новый lifecycle hook, registry mirror или плавающая зависимость
не могут стать разрешёнными из-за старого исключения.

Переход от патчей 5.1.20 описан в
[`security/electerm-web-migration-ledger.md`](electerm-web-migration-ledger.md).

## Проверка в CI

Workflow `.github/workflows/ci.yml` падает, если:

- в `externals.json` есть запись с `pin`, не соответствующим формату;
- в репозитории появился docker-образ, указанный по тегу без digest;
- в коде встречается `curl ... | bash`, `iwr ... | iex` или подобный шаблон;
- lifecycle-скрипт, registry host или плавающая зависимость не имеют
  hash-bound исключения;
- байты или Git mode импортированного дерева не совпадают с его lock-файлом;
- raw commit, tree, external pin или commit-bound archive metadata не
  совпадают друг с другом;
- под `apps/*` или `vendor/*` появляется дерево без ровно одного lock-файла;
- когда они будут закреплённо добавлены, `osv-scanner` или `trivy` находят
  уязвимости уровня high и выше.
