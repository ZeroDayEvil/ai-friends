#!/usr/bin/env node
/**
 * Безопасный статический инспектор npm-тарболов.
 *
 * Запуск:
 *   node scripts/security/inspect-npm-tarball.mjs \
 *     --package @electerm/electerm-react --version 5.3.15 \
 *     --out <каталог вне репозитория> [--extract]
 *
 * Зачем отдельный инструмент. Чтобы прочитать чужой пакет, нельзя выполнять
 * `npm install`, `npm pack` и любые скрипты пакета: установка запускает
 * preinstall/install/postinstall с правами текущего пользователя. Здесь пакет
 * скачивается напрямую из официального реестра и разбирается как данные:
 * gzip читает встроенный `node:zlib`, tar -- собственный парсер ниже,
 * сторонних зависимостей нет, ничего из содержимого не исполняется и не
 * импортируется.
 *
 * Что делает по шагам:
 *   1. берёт метаданные версии только с registry.npmjs.org (жёсткий allowlist);
 *   2. проверяет, что dist.tarball ведёт на тот же реестр и на тот же пакет;
 *   3. качает тарбол, фиксирует media type и размер;
 *   4. считает sha512/sha256/sha1 и сверяет sha512 с dist.integrity (SRI),
 *      sha1 -- с dist.shasum, размер -- с Content-Length;
 *   5. разбирает tar и отбраковывает опасные записи: абсолютные пути, выход за
 *      пределы каталога (`..`), буквы дисков, обратные слэши, симлинки,
 *      жёсткие ссылки, устройства, fifo и неизвестные typeflag;
 *   6. только если нарушений нет и передан --extract -- раскладывает обычные
 *      файлы как инертные данные (режим 0600, бит выполнения снимается).
 *
 * Результат -- сводка на stdout и полный inventory.json в каталоге --out.
 * Каталог --out обязан быть вне этого репозитория: чужой код не коммитится.
 */
import { createHash } from 'node:crypto'
import { gunzipSync } from 'node:zlib'
import { mkdirSync, writeFileSync, realpathSync, rmSync } from 'node:fs'
import { dirname, join, resolve, relative, isAbsolute, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const REGISTRY_HOST = 'registry.npmjs.org'
const REGISTRY_ORIGIN = `https://${REGISTRY_HOST}`
const TAR_BLOCK = 512

// Лимиты ресурсов. Враждебный архив может быть маленьким в сжатом виде и
// огромным в распакованном, поэтому ограничивается и то, и другое, причём
// сжатый поток -- по мере чтения, а не после того, как он уже в памяти.
export const MAX_METADATA_BYTES = 8 * 1024 * 1024
export const MAX_TARBALL_BYTES = 64 * 1024 * 1024
export const MAX_UNPACKED_BYTES = 256 * 1024 * 1024
export const MAX_TAR_ENTRIES = 20000
export const MAX_TAR_HEADERS = 60000
export const MAX_ENTRY_BYTES = 64 * 1024 * 1024
const UNPACKED_METADATA_FACTOR = 4
const UNPACKED_SLACK_BYTES = 1024 * 1024

// Коды возврата: по ним вызывающая сторона отличает отказ из-за лимита
// (возможная архивная бомба) от несовпадения хешей и от сетевой ошибки.
export const EXIT = {
  usage: 2,
  network: 3,
  integrity: 4,
  limit: 5,
  archive: 6,
  internal: 7
}

export class AuditError extends Error {
  constructor (message, code = EXIT.usage) {
    super(message)
    this.name = 'AuditError'
    this.code = code
  }
}

function fail (message, code = EXIT.usage) {
  throw new AuditError(message, code)
}

/**
 * Предел распаковки для конкретного пакета. Реестр публикует unpackedSize, и
 * это лучший из доступных ориентиров: архив, который распаковывается в разы
 * больше заявленного, к настоящей поставке отношения не имеет.
 */
export function unpackLimitFor (unpackedSize) {
  if (!Number.isInteger(unpackedSize) || unpackedSize <= 0) return MAX_UNPACKED_BYTES
  return Math.min(MAX_UNPACKED_BYTES, unpackedSize * UNPACKED_METADATA_FACTOR + UNPACKED_SLACK_BYTES)
}

function parseArgs (argv) {
  const args = { extract: false }
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]
    if (key === '--extract') { args.extract = true; continue }
    if (!key.startsWith('--')) fail(`неизвестный аргумент ${key}`)
    const value = argv[++i]
    if (value === undefined) fail(`у ${key} нет значения`)
    args[key.slice(2)] = value
  }
  for (const required of ['package', 'version', 'out']) {
    if (!args[required]) fail(`не задан --${required}`)
  }
  if (!/^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i.test(args.package)) fail('недопустимое имя пакета')
  if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(args.version)) fail('версия должна быть точной, без диапазонов')
  return args
}

/** Сеть разрешена только к официальному реестру и только по https. */
function assertRegistryUrl (url, what) {
  let parsed
  try {
    parsed = new URL(url)
  } catch {
    return fail(`${what}: значение не разбирается как URL: ${url}`)
  }
  if (parsed.protocol !== 'https:' || parsed.host !== REGISTRY_HOST) {
    fail(`${what}: источник вне официального реестра: ${url}`, EXIT.network)
  }
  return parsed
}

/**
 * Чтение потока с лимитом по мере поступления данных. Именно здесь ловится
 * сжатый поток произвольной длины: буфер не собирается целиком до проверки,
 * а превышение обрывает соединение через onExceed.
 */
export async function readCappedStream (stream, limit, onExceed, what = 'поток') {
  if (!stream) fail(`${what}: пустое тело ответа`, EXIT.network)
  const chunks = []
  let total = 0
  for await (const chunk of stream) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    total += buf.length
    if (total > limit) {
      if (onExceed) onExceed()
      fail(`${what}: превышен лимит ${limit} байт (получено больше ${total - buf.length}), чтение прервано`, EXIT.limit)
    }
    chunks.push(buf)
  }
  return Buffer.concat(chunks, total)
}

/**
 * Content-Length -- подсказка, а не гарантия: заголовок может отсутствовать или
 * лгать. Поэтому он только позволяет отказаться раньше, но не заменяет
 * инкрементальную проверку в readCappedStream.
 */
function declaredLength (res, limit, what) {
  const raw = res.headers.get('content-length')
  if (raw === null) return null
  const value = Number(raw)
  if (!Number.isInteger(value) || value < 0) fail(`${what}: некорректный Content-Length "${raw}"`, EXIT.network)
  if (value > limit) fail(`${what}: заявленный размер ${value} больше лимита ${limit} байт`, EXIT.limit)
  return value
}

async function getJson (url) {
  assertRegistryUrl(url, 'метаданные')
  const controller = new AbortController()
  const res = await fetch(url, {
    redirect: 'error',
    signal: controller.signal,
    headers: { accept: 'application/json' }
  })
  if (!res.ok) fail(`реестр ответил ${res.status} на ${url}`, EXIT.network)
  declaredLength(res, MAX_METADATA_BYTES, 'метаданные')
  const bytes = await readCappedStream(res.body, MAX_METADATA_BYTES, () => controller.abort(), 'метаданные')
  let body
  try {
    body = JSON.parse(bytes.toString('utf8'))
  } catch (err) {
    fail(`метаданные не разбираются как JSON: ${err.message}`, EXIT.network)
  }
  return { body, contentType: res.headers.get('content-type') }
}

async function getBytes (url) {
  assertRegistryUrl(url, 'тарбол')
  const controller = new AbortController()
  const res = await fetch(url, { redirect: 'error', signal: controller.signal })
  if (!res.ok) fail(`реестр ответил ${res.status} на ${url}`, EXIT.network)
  const contentLength = declaredLength(res, MAX_TARBALL_BYTES, 'тарбол')
  const bytes = await readCappedStream(res.body, MAX_TARBALL_BYTES, () => controller.abort(), 'тарбол')
  return {
    bytes,
    contentType: res.headers.get('content-type'),
    contentLength
  }
}

/**
 * Распаковка с жёстким потолком выходного буфера. Без него gzip-бомба в
 * несколько килобайт разворачивается в гигабайты и выносит процесс.
 */
export function gunzipCapped (buf, limit) {
  try {
    return gunzipSync(buf, { maxOutputLength: limit })
  } catch (err) {
    if (err?.code === 'ERR_BUFFER_TOO_LARGE' || err instanceof RangeError) {
      fail(`распакованный размер превышает лимит ${limit} байт: похоже на архивную бомбу`, EXIT.limit)
    }
    fail(`не удалось распаковать gzip: ${err.message}`, EXIT.archive)
  }
}

function digests (buf) {
  return {
    sha512_base64: createHash('sha512').update(buf).digest('base64'),
    sha512_hex: createHash('sha512').update(buf).digest('hex'),
    sha256_hex: createHash('sha256').update(buf).digest('hex'),
    sha1_hex: createHash('sha1').update(buf).digest('hex')
  }
}

// --- разбор tar ------------------------------------------------------------
// Формат ustar/pax: заголовок 512 байт, затем содержимое, выровненное по 512.

function str (buf, start, len) {
  const raw = buf.subarray(start, start + len)
  const end = raw.indexOf(0)
  return raw.subarray(0, end === -1 ? raw.length : end).toString('utf8').trim()
}

function octal (buf, start, len) {
  // Расширение GNU: если старший бит выставлен, число закодировано base-256.
  if (buf[start] & 0x80) {
    let value = 0n
    for (let i = start; i < start + len; i++) value = (value << 8n) + BigInt(buf[i] & 0xff)
    return Number(value & 0x7fffffffffffffn)
  }
  const text = str(buf, start, len).replace(/[^0-7]/g, '')
  return text ? parseInt(text, 8) : 0
}

function headerChecksumOk (block) {
  let signed = 0
  let unsigned = 0
  for (let i = 0; i < TAR_BLOCK; i++) {
    const byte = i >= 148 && i < 156 ? 0x20 : block[i]
    unsigned += byte & 0xff
    signed += (byte & 0x80) ? (byte & 0xff) - 256 : byte & 0xff
  }
  const declared = octal(block, 148, 8)
  return declared === unsigned || declared === signed
}

const TYPE_NAMES = {
  0: 'file',
  '\u0000': 'file',
  1: 'hardlink',
  2: 'symlink',
  3: 'chardev',
  4: 'blockdev',
  5: 'directory',
  6: 'fifo',
  7: 'contiguous',
  x: 'pax-header',
  g: 'pax-global',
  L: 'gnu-longname',
  K: 'gnu-longlink'
}

function parsePax (text) {
  const out = {}
  let offset = 0
  while (offset < text.length) {
    const space = text.indexOf(' ', offset)
    if (space === -1) break
    const len = parseInt(text.slice(offset, space), 10)
    if (!Number.isFinite(len) || len <= 0) break
    const record = text.slice(space + 1, offset + len).replace(/\n$/, '')
    const eq = record.indexOf('=')
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1)
    offset += len
  }
  return out
}

function padded (size) {
  return size + ((TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK)
}

export function parseTar (buf, limits = {}) {
  const maxEntries = limits.maxEntries ?? MAX_TAR_ENTRIES
  const maxHeaders = limits.maxHeaders ?? MAX_TAR_HEADERS
  const maxEntryBytes = limits.maxEntryBytes ?? MAX_ENTRY_BYTES
  const maxTotalBytes = limits.maxTotalBytes ?? MAX_UNPACKED_BYTES

  const entries = []
  let offset = 0
  let headers = 0
  let declaredTotal = 0
  let pendingName = null
  let pendingLink = null
  let pendingPax = {}

  while (offset + TAR_BLOCK <= buf.length) {
    const block = buf.subarray(offset, offset + TAR_BLOCK)
    if (block.every((b) => b === 0)) break
    if (!headerChecksumOk(block)) fail(`битая контрольная сумма заголовка tar по смещению ${offset}`, EXIT.archive)

    // Служебные заголовки (pax, GNU long name) тоже считаются: иначе архив из
    // одних заголовков крутит цикл сколько угодно долго.
    if (++headers > maxHeaders) fail(`заголовков tar больше лимита ${maxHeaders}`, EXIT.limit)

    const typeflag = String.fromCharCode(block[156] || 0x30)
    const size = octal(block, 124, 12)

    // Лимиты проверяются до любых выделений и до сдвига смещения.
    if (!Number.isInteger(size) || size < 0) fail(`некорректный размер записи tar по смещению ${offset}`, EXIT.archive)
    if (size > maxEntryBytes) fail(`запись tar по смещению ${offset} заявляет ${size} байт при лимите ${maxEntryBytes}`, EXIT.limit)
    declaredTotal += size
    if (declaredTotal > maxTotalBytes) fail(`суммарный заявленный размер записей tar превысил ${maxTotalBytes} байт`, EXIT.limit)

    const dataStart = offset + TAR_BLOCK
    const dataEnd = dataStart + size
    if (dataEnd > buf.length) fail(`запись tar выходит за пределы архива по смещению ${offset}`, EXIT.archive)
    const next = dataStart + padded(size)

    const prefix = str(block, 345, 155)
    const base = str(block, 0, 100)
    let name = prefix ? `${prefix}/${base}` : base
    let linkname = str(block, 157, 100)

    if (typeflag === 'L') {
      pendingName = str(buf, dataStart, size)
      offset = next
      continue
    }
    if (typeflag === 'K') {
      pendingLink = str(buf, dataStart, size)
      offset = next
      continue
    }
    if (typeflag === 'x' || typeflag === 'g') {
      pendingPax = { ...pendingPax, ...parsePax(buf.subarray(dataStart, dataEnd).toString('utf8')) }
      offset = next
      continue
    }

    if (pendingName) { name = pendingName; pendingName = null }
    if (pendingLink) { linkname = pendingLink; pendingLink = null }
    if (pendingPax.path) name = pendingPax.path
    if (pendingPax.linkpath) linkname = pendingPax.linkpath
    pendingPax = {}

    const isFile = typeflag === '0' || typeflag === '\u0000' || typeflag === '7'
    if (entries.length >= maxEntries) fail(`записей tar больше лимита ${maxEntries}`, EXIT.limit)
    entries.push({
      name,
      type: TYPE_NAMES[typeflag] ?? `unknown(${typeflag})`,
      typeflag,
      size,
      mode: octal(block, 100, 8),
      uid: octal(block, 108, 8),
      gid: octal(block, 116, 8),
      mtime: octal(block, 136, 12),
      uname: str(block, 265, 32),
      gname: str(block, 297, 32),
      linkname,
      data: isFile ? buf.subarray(dataStart, dataEnd) : null
    })

    offset = next
  }
  return entries
}

// --- проверки безопасности путей -------------------------------------------

const SAFE_TYPES = new Set(['file', 'directory'])

export function pathViolations (entry) {
  const found = []
  const name = entry.name
  if (!SAFE_TYPES.has(entry.type)) found.push(`недопустимый тип записи: ${entry.type}`)
  if (entry.linkname) found.push(`ссылка на ${entry.linkname}`)
  if (name === '' || name === '.') found.push('пустое имя записи')
  if (name.startsWith('/') || name.startsWith('\\')) found.push('абсолютный путь')
  if (/^[a-zA-Z]:/.test(name)) found.push('путь с буквой диска')
  if (name.includes('\\')) found.push('обратный слэш в имени')
  if (name.split('/').some((part) => part === '..')) found.push('выход за пределы каталога (..)')
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f]/.test(name)) found.push('управляющие символы в имени')
  if (entry.type === 'file' && (entry.mode & 0o4000 || entry.mode & 0o2000)) found.push('setuid/setgid бит')
  return found
}

// --- классификация содержимого ---------------------------------------------

const BINARY_EXT = new Set(['.node', '.wasm', '.dll', '.so', '.dylib', '.exe', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.zip', '.gz', '.br', '.mp3', '.mp4', '.pdf'])
const CODE_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.css', '.styl', '.less', '.scss', '.json', '.md', '.yml', '.yaml', '.html', '.txt', '.svg'])

function extname (name) {
  const dot = name.lastIndexOf('.')
  const slash = name.lastIndexOf('/')
  return dot > slash ? name.slice(dot).toLowerCase() : ''
}

function classify (entry) {
  if (entry.type !== 'file') return { class: entry.type, ext: extname(entry.name) }
  const ext = extname(entry.name)
  const data = entry.data ?? Buffer.alloc(0)
  if (data.subarray(0, 8192).includes(0) || BINARY_EXT.has(ext)) return { class: 'binary', ext }

  const text = data.toString('utf8')
  const lines = text.split('\n')
  let longest = 0
  for (const line of lines) if (line.length > longest) longest = line.length

  const generated = /@generated|do not edit|generated by|Emscripten|webpackBootstrap|__webpack_require__/i.test(text.slice(0, 4096)) ||
    /sourceMappingURL=/.test(text.slice(-2048))
  // Минифицированным считаем только то, где длинные строки сочетаются с малым
  // числом переводов строки: одиночная длинная строка в JSON это не минификация.
  const minified = !['.json', '.md', '.svg', '.txt'].includes(ext) &&
    longest >= 500 && data.length > 20 * 1024 && lines.length < data.length / 200

  if (minified) return { class: 'minified', ext, longestLine: longest }
  if (generated) return { class: 'generated', ext, longestLine: longest }
  if (CODE_EXT.has(ext) || ext === '') return { class: 'source', ext, longestLine: longest }
  return { class: 'data', ext, longestLine: longest }
}

// --- извлечение как инертных данных ----------------------------------------

function safeExtract (entries, outRoot) {
  const root = resolve(outRoot)
  mkdirSync(root, { recursive: true })
  const realRoot = realpathSync(root)
  let written = 0
  for (const entry of entries) {
    if (entry.type !== 'file') continue
    const target = resolve(realRoot, entry.name)
    const rel = relative(realRoot, target)
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel) || rel.split(sep).includes('..')) {
      fail(`попытка записи вне каталога назначения: ${entry.name}`, EXIT.archive)
    }
    mkdirSync(dirname(target), { recursive: true })
    // 0600: файл остаётся данными для чтения, бит выполнения из архива не переносится.
    writeFileSync(target, entry.data ?? Buffer.alloc(0), { mode: 0o600 })
    written++
  }
  return written
}

// --- основной сценарий ------------------------------------------------------

async function main () {
  const args = parseArgs(process.argv.slice(2))
  const outRoot = resolve(args.out)
  const fromRepo = relative(resolve(process.cwd()), outRoot)
  if (fromRepo !== '' && !fromRepo.startsWith('..') && !isAbsolute(fromRepo)) {
    fail('--out должен указывать вне репозитория: чужой код не коммитится')
  }

  const specUrl = `${REGISTRY_ORIGIN}/${args.package.replace('/', '%2f')}/${args.version}`
  const meta = await getJson(specUrl)
  const dist = meta.body?.dist ?? {}
  if (meta.body?.version !== args.version) fail(`реестр вернул версию ${meta.body?.version}`, EXIT.integrity)
  if (!dist.tarball || !dist.integrity) fail('в метаданных нет dist.tarball/dist.integrity', EXIT.integrity)

  const tarballUrl = assertRegistryUrl(dist.tarball, 'dist.tarball')
  const expectedSuffix = `/${args.package}/-/${args.package.split('/').pop()}-${args.version}.tgz`
  if (!decodeURIComponent(tarballUrl.pathname).endsWith(expectedSuffix)) {
    fail(`dist.tarball не соответствует пакету и версии: ${tarballUrl.pathname}`, EXIT.integrity)
  }

  const download = await getBytes(dist.tarball)
  const sums = digests(download.bytes)

  const [algo, expected] = String(dist.integrity).split('-')
  if (algo !== 'sha512') fail(`ожидается SRI sha512, получено ${algo}`, EXIT.integrity)
  if (sums.sha512_base64 !== expected) fail('SHA-512 тарбола не совпал с dist.integrity: архив не тот, что опубликован', EXIT.integrity)
  if (dist.shasum && sums.sha1_hex !== dist.shasum) fail('SHA-1 не совпал с dist.shasum', EXIT.integrity)
  if (download.contentLength !== null && download.contentLength !== download.bytes.length) {
    fail(`Content-Length ${download.contentLength} не равен фактическому размеру ${download.bytes.length}`, EXIT.integrity)
  }

  // Потолок распаковки выводится из unpackedSize в метаданных: даже пройдя
  // проверку хеша, архив не должен разворачиваться в разы больше заявленного.
  const unpackLimit = unpackLimitFor(dist.unpackedSize)
  const tar = gunzipCapped(download.bytes, unpackLimit)
  const entries = parseTar(tar, { maxTotalBytes: unpackLimit })

  const violations = []
  for (const entry of entries) {
    for (const problem of pathViolations(entry)) violations.push({ entry: entry.name, problem })
  }

  const inventory = entries.map((entry) => {
    const info = classify(entry)
    return {
      path: entry.name,
      type: entry.type,
      class: info.class,
      ext: info.ext,
      size: entry.size,
      mode: '0' + entry.mode.toString(8),
      linkname: entry.linkname || null,
      longest_line: info.longestLine ?? null,
      sha256: entry.type === 'file' ? createHash('sha256').update(entry.data ?? Buffer.alloc(0)).digest('hex') : null
    }
  })

  const byType = {}
  const byClass = {}
  for (const item of inventory) {
    byType[item.type] = (byType[item.type] ?? 0) + 1
    byClass[item.class] = (byClass[item.class] ?? 0) + 1
  }

  const report = {
    package: args.package,
    version: args.version,
    checked_at: new Date().toISOString().slice(0, 10),
    registry: {
      metadata_url: specUrl,
      metadata_content_type: meta.contentType,
      tarball_url: dist.tarball,
      tarball_content_type: download.contentType,
      tarball_content_length: download.contentLength ? Number(download.contentLength) : null
    },
    published: {
      integrity: dist.integrity,
      shasum: dist.shasum ?? null,
      file_count: dist.fileCount ?? null,
      unpacked_size: dist.unpackedSize ?? null,
      attestations_url: dist.attestations?.url ?? null,
      signature_keyid: dist.signatures?.[0]?.keyid ?? null,
      git_head: meta.body.gitHead ?? null,
      repository: meta.body.repository?.url ?? null,
      license: meta.body.license ?? null,
      scripts: meta.body.scripts ?? null,
      dependencies: meta.body.dependencies ?? null
    },
    computed: {
      tarball_bytes: download.bytes.length,
      sha512_base64: sums.sha512_base64,
      sha512_hex: sums.sha512_hex,
      sha256_hex: sums.sha256_hex,
      sha1_hex: sums.sha1_hex,
      integrity_match: true,
      shasum_match: dist.shasum ? sums.sha1_hex === dist.shasum : null,
      unpacked_bytes: inventory.reduce((sum, item) => sum + item.size, 0),
      entry_count: inventory.length,
      file_count: byType.file ?? 0
    },
    limits: {
      max_tarball_bytes: MAX_TARBALL_BYTES,
      max_unpacked_bytes: MAX_UNPACKED_BYTES,
      effective_unpack_limit: unpackLimit,
      max_tar_entries: MAX_TAR_ENTRIES,
      max_entry_bytes: MAX_ENTRY_BYTES,
      unpacked_within_declared: dist.unpackedSize
        ? tar.length <= unpackLimit && inventory.reduce((sum, item) => sum + item.size, 0) === dist.unpackedSize
        : null
    },
    entry_types: byType,
    entry_classes: byClass,
    violations,
    entries: inventory
  }

  mkdirSync(outRoot, { recursive: true })

  if (args.extract) {
    if (violations.length) fail(`распаковка отменена: нарушений ${violations.length}`, EXIT.archive)
    const extractRoot = join(outRoot, 'extracted')
    try {
      report.extracted_files = safeExtract(entries, extractRoot)
    } catch (err) {
      // Частично распакованное дерево не оставляем: оно уже содержит чужие
      // файлы, а проверки на нём не завершились.
      rmSync(extractRoot, { recursive: true, force: true })
      throw err
    }
  }

  writeFileSync(join(outRoot, 'inventory.json'), JSON.stringify(report, null, 2))
  const { entries: _full, ...summary } = report
  console.log(JSON.stringify(summary, null, 2))
}

// Запускаем сценарий только при прямом вызове: при импорте (например, из проверки
// отбраковки вредоносных архивов) выполняется лишь загрузка чистых функций.
const invokedDirectly = process.argv[1] &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))

if (invokedDirectly) {
  main().catch((err) => {
    const known = err instanceof AuditError
    console.error(`inspect-npm-tarball: ${known ? err.message : (err?.stack ?? String(err))}`)
    process.exit(known ? err.code : EXIT.internal)
  })
}
