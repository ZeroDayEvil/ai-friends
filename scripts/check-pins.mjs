#!/usr/bin/env node
/**
 * Проверка политики зависимостей из security/README.md.
 *
 * Запуск: node scripts/check-pins.mjs
 * Код возврата 1, если найдено нарушение.
 *
 * Проверяется три вещи:
 *   1. структура security/externals.json и формат пинов;
 *   2. отсутствие исполнения скачанного кода на лету (curl | bash и аналоги);
 *   3. образы контейнеров закреплены digest-ом, а не тегом.
 *
 * Текстовые файлы документации из проверки 2 исключены сознательно: там такие
 * команды приводятся как примеры того, чего делать нельзя.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, extname, relative, sep } from 'node:path'

const root = process.cwd()
const problems = []
const SCANNED_EXT = new Set(['.sh', '.bash', '.ps1', '.psm1', '.yml', '.yaml', '.cmd', '.bat', '.mjs', '.js'])
const SKIP_DIRS = new Set(['.git', 'node_modules', 'apps', 'dist', 'build', 'docs'])

function walk (dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else out.push(full)
  }
  return out
}

// --- 1. Реестр внешних зависимостей ---------------------------------------
const PIN_RE = /^(commit:[0-9a-f]{7,40}|commit:pending|version:\d+\.\d+\.\d+|digest:sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64}|none)$/
const KINDS = new Set(['git', 'npm', 'docker', 'binary', 'script', 'endpoint'])
const VERDICTS = new Set(['keep', 'replace', 'pin', 'remove'])

let registry
try {
  registry = JSON.parse(readFileSync(join(root, 'security', 'externals.json'), 'utf8'))
} catch (err) {
  problems.push(`security/externals.json не читается: ${err.message}`)
}

if (registry) {
  if (registry.version !== 1) problems.push('externals.json: ожидается "version": 1')
  if (!Array.isArray(registry.items)) {
    problems.push('externals.json: отсутствует массив items')
  } else {
    for (const item of registry.items) {
      const id = item.id ?? '<без id>'
      for (const field of ['id', 'kind', 'official_source', 'pin', 'license', 'verdict']) {
        if (item[field] === undefined) problems.push(`externals.json [${id}]: нет поля ${field}`)
      }
      if (item.kind && !KINDS.has(item.kind)) problems.push(`externals.json [${id}]: недопустимый kind "${item.kind}"`)
      if (item.verdict && !VERDICTS.has(item.verdict)) problems.push(`externals.json [${id}]: недопустимый verdict "${item.verdict}"`)
      if (item.pin && !PIN_RE.test(item.pin)) problems.push(`externals.json [${id}]: пин "${item.pin}" не соответствует формату`)
      if (item.verdict === 'keep' && item.pin === 'none' && item.kind !== 'git') {
        problems.push(`externals.json [${id}]: verdict keep без пина`)
      }
    }
  }
}

// --- 2. Исполнение скачанного кода ----------------------------------------
const PIPE_TO_SHELL = [
  /curl[^\n|]*\|\s*(sudo\s+)?(ba)?sh/i,
  /wget[^\n|]*\|\s*(sudo\s+)?(ba)?sh/i,
  /(iwr|invoke-webrequest)[^\n|]*\|\s*(iex|invoke-expression)/i,
  /\$\((curl|wget)[^)]*\)\s*"?\s*$/i
]

// --- 3. Образы без digest -------------------------------------------------
const IMAGE_RE = /^\s*image:\s*(\S+)/

for (const file of walk(root)) {
  const ext = extname(file)
  if (!SCANNED_EXT.has(ext)) continue
  const rel = relative(root, file).split(sep).join('/')
  const lines = readFileSync(file, 'utf8').split(/\r?\n/)

  lines.forEach((line, i) => {
    if (rel === 'scripts/check-pins.mjs') return // сам файл содержит шаблоны
    // Комментарии пропускаем: в них такие команды приводятся как пример того,
    // чего делать нельзя, и исполниться они не могут.
    const trimmed = line.trim()
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) return
    for (const re of PIPE_TO_SHELL) {
      if (re.test(line)) problems.push(`${rel}:${i + 1}: исполнение скачанного кода на лету: ${line.trim()}`)
    }
    const m = IMAGE_RE.exec(line)
    if (m) {
      const image = m[1]
      const pinned = image.includes('@sha256:') || image.startsWith('${')
      if (!pinned) problems.push(`${rel}:${i + 1}: образ без digest: ${image}`)
    }
  })
}

// --- Результат ------------------------------------------------------------
if (problems.length) {
  console.error(`Найдено нарушений: ${problems.length}\n`)
  for (const p of problems) console.error(`  - ${p}`)
  process.exit(1)
}
console.log('Политика зависимостей соблюдена.')
