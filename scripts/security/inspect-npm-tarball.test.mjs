#!/usr/bin/env node
/**
 * Проверки отбраковки для inspect-npm-tarball.mjs.
 *
 * Запуск: node scripts/security/inspect-npm-tarball.test.mjs
 * Код возврата 1, если хотя бы одна проверка провалилась.
 *
 * Все данные генерируются здесь же из собственных байтов: сеть не используется,
 * чужие архивы не скачиваются, ничего из содержимого не исполняется. Проверяется
 * ровно то, что инструмент отказывается работать с враждебным вводом:
 *   1. сжатый поток, превышающий лимит, обрывается по мере чтения;
 *   2. gzip-бомба (маленькая в сжатом виде) не разворачивается в память;
 *   3. tar с завышенными размерами и числом записей отбраковывается до выделений;
 *   4. записи с traversal, ссылками, устройствами и setuid не проходят;
 *   5. корректный архив проходит без нарушений.
 */
import { gzipSync } from 'node:zlib'
import {
  parseTar,
  pathViolations,
  readCappedStream,
  gunzipCapped,
  unpackLimitFor,
  AuditError,
  EXIT,
  MAX_UNPACKED_BYTES
} from './inspect-npm-tarball.mjs'

let failures = 0
let checks = 0

function report (ok, label, detail = '') {
  checks++
  if (!ok) failures++
  console.log(`${ok ? 'OK      ' : 'ПРОВАЛ  '} ${label}${detail ? ' -- ' + detail : ''}`)
}

/** Ожидаем AuditError с конкретным кодом возврата. */
async function expectFail (label, code, fn) {
  try {
    await fn()
    report(false, label, 'ошибка не выброшена')
  } catch (err) {
    if (err instanceof AuditError && err.code === code) {
      report(true, label, `код ${err.code}`)
    } else {
      report(false, label, `ожидался AuditError код ${code}, получено ${err?.name}: ${err?.message}`)
    }
  }
}

async function expectPass (label, fn) {
  try {
    const value = await fn()
    report(true, label, typeof value === 'string' ? value : '')
  } catch (err) {
    report(false, label, `неожиданная ошибка ${err?.name}: ${err?.message}`)
  }
}

// --- сборка tar из собственных байтов ---------------------------------------

function header (name, { type = '0', size = 0, mode = 0o644, linkname = '' } = {}) {
  const b = Buffer.alloc(512)
  b.write(name.slice(0, 100), 0, 'utf8')
  b.write(mode.toString(8).padStart(7, '0') + '\0', 100)
  b.write('0000000\0', 108)
  b.write('0000000\0', 116)
  b.write(size.toString(8).padStart(11, '0') + '\0', 124)
  b.write('00000000000\0', 136)
  b.write('        ', 148)
  b.write(type, 156)
  b.write(linkname.slice(0, 100), 157, 'utf8')
  b.write('ustar\0', 257)
  b.write('00', 263)
  let sum = 0
  for (let i = 0; i < 512; i++) sum += b[i]
  b.write(sum.toString(8).padStart(6, '0') + '\0 ', 148)
  return b
}

function tarOf (specs) {
  const parts = []
  for (const s of specs) {
    const data = Buffer.from(s.data ?? '')
    parts.push(header(s.name, { ...s, size: s.declaredSize ?? data.length }))
    if (data.length) {
      parts.push(data, Buffer.alloc((512 - (data.length % 512)) % 512))
    }
  }
  parts.push(Buffer.alloc(1024))
  return Buffer.concat(parts)
}

async function * chunked (totalBytes, chunkSize = 64 * 1024) {
  let sent = 0
  while (sent < totalBytes) {
    const size = Math.min(chunkSize, totalBytes - sent)
    sent += size
    yield Buffer.alloc(size, 0x41)
  }
}

// --- 1. Сжатый поток сверх лимита -------------------------------------------

console.log('--- поток сверх лимита ---')

let aborted = false
await expectFail('поток на 1 МиБ при лимите 256 КиБ прерывается', EXIT.limit, () =>
  readCappedStream(chunked(1024 * 1024), 256 * 1024, () => { aborted = true }, 'тестовый поток')
)
report(aborted, 'при превышении вызван обрыв соединения (abort)')

await expectPass('поток в пределах лимита читается целиком', async () => {
  const buf = await readCappedStream(chunked(200 * 1024), 256 * 1024, null, 'тестовый поток')
  if (buf.length !== 200 * 1024) throw new Error(`получено ${buf.length} байт`)
  return `${buf.length} байт`
})

// Граница: ровно лимит проходит, лимит + 1 байт уже нет.
await expectPass('размер ровно по лимиту проходит', () =>
  readCappedStream(chunked(4096), 4096, null, 'тестовый поток')
)
await expectFail('лимит + 1 байт отбраковывается', EXIT.limit, () =>
  readCappedStream(chunked(4097), 4096, null, 'тестовый поток')
)

// --- 2. gzip-бомба -----------------------------------------------------------

console.log('\n--- gzip-бомба ---')

// 16 МиБ нулей сжимаются в десятки килобайт: классический перекос, из-за
// которого распаковка без потолка выносит процесс.
const bomb = gzipSync(Buffer.alloc(16 * 1024 * 1024))
console.log(`         фикстура: сжато ${bomb.length} байт, распакуется в ${16 * 1024 * 1024}`)
report(bomb.length < 64 * 1024, 'фикстура действительно мала в сжатом виде', `${bomb.length} байт`)

await expectFail('бомба не распаковывается при лимите 1 МиБ', EXIT.limit, () =>
  gunzipCapped(bomb, 1024 * 1024)
)

await expectPass('обычный gzip в пределах лимита распаковывается', () => {
  const out = gunzipCapped(gzipSync(Buffer.from('привет')), 1024 * 1024)
  if (out.toString('utf8') !== 'привет') throw new Error('содержимое не совпало')
  return 'содержимое совпало'
})

await expectFail('мусор вместо gzip даёт код архива', EXIT.archive, () =>
  gunzipCapped(Buffer.from('это не gzip'), 1024 * 1024)
)

// --- 3. Потолок распаковки из метаданных -------------------------------------

console.log('\n--- потолок из метаданных ---')

report(unpackLimitFor(1633407) < MAX_UNPACKED_BYTES,
  'для реального unpackedSize потолок жёстче абсолютного', `${unpackLimitFor(1633407)} байт`)
report(unpackLimitFor(undefined) === MAX_UNPACKED_BYTES,
  'без unpackedSize используется абсолютный потолок')
report(unpackLimitFor(10 * 1024 * 1024 * 1024) === MAX_UNPACKED_BYTES,
  'завышенный unpackedSize не поднимает потолок выше абсолютного')

await expectFail('архив сверх потолка из метаданных отбраковывается', EXIT.limit, () =>
  gunzipCapped(gzipSync(Buffer.alloc(4 * 1024 * 1024)), unpackLimitFor(100 * 1024))
)

// --- 4. Лимиты tar -----------------------------------------------------------

console.log('\n--- лимиты tar ---')

await expectFail('запись с завышенным заявленным размером', EXIT.limit, () =>
  parseTar(tarOf([{ name: 'package/big', declaredSize: 8 * 1024 * 1024 }]), { maxEntryBytes: 1024 })
)

await expectFail('суммарный заявленный размер сверх лимита', EXIT.limit, () =>
  parseTar(
    tarOf([
      { name: 'package/a', data: 'x'.repeat(600) },
      { name: 'package/b', data: 'x'.repeat(600) },
      { name: 'package/c', data: 'x'.repeat(600) }
    ]),
    { maxTotalBytes: 1000 }
  )
)

await expectFail('число записей сверх лимита', EXIT.limit, () =>
  parseTar(
    tarOf(Array.from({ length: 12 }, (_, i) => ({ name: `package/f${i}.js`, data: 'x' }))),
    { maxEntries: 5 }
  )
)

await expectFail('число заголовков сверх лимита', EXIT.limit, () =>
  parseTar(
    tarOf(Array.from({ length: 12 }, (_, i) => ({ name: `package/f${i}.js`, data: 'x' }))),
    { maxHeaders: 4 }
  )
)

await expectFail('запись, выходящая за пределы архива', EXIT.archive, () =>
  parseTar(tarOf([{ name: 'package/short', declaredSize: 4096 }]))
)

// --- 5. Опасные записи -------------------------------------------------------

console.log('\n--- опасные записи ---')

const hostile = [
  ['выход за каталог (..)', { name: 'package/../../evil.js', data: 'x' }],
  ['абсолютный путь', { name: '/etc/cron.d/evil', data: 'x' }],
  ['буква диска', { name: 'C:/Windows/evil.dll', data: 'x' }],
  ['обратный слэш', { name: 'package\\..\\evil.js', data: 'x' }],
  ['симлинк', { name: 'package/link', type: '2', linkname: '/etc/passwd' }],
  ['жёсткая ссылка', { name: 'package/hard', type: '1', linkname: '/etc/shadow' }],
  ['символьное устройство', { name: 'package/dev', type: '3' }],
  ['блочное устройство', { name: 'package/blk', type: '4' }],
  ['fifo', { name: 'package/pipe', type: '6' }],
  ['setuid-бит', { name: 'package/suid', mode: 0o4755, data: 'x' }],
  ['setgid-бит', { name: 'package/sgid', mode: 0o2755, data: 'x' }]
]

for (const [label, spec] of hostile) {
  const problems = parseTar(tarOf([spec])).flatMap(pathViolations)
  report(problems.length > 0, `отбракован: ${label}`, problems.join('; '))
}

// --- 6. Чистый архив ---------------------------------------------------------

console.log('\n--- чистый архив ---')

const benign = parseTar(tarOf([
  { name: 'package/package.json', data: '{"name":"x"}' },
  { name: 'package/client/a.js', data: 'export default 1\n' },
  { name: 'package/client', type: '5' }
]))
report(benign.length === 3, 'разобраны все записи', `${benign.length} записей`)
report(benign.flatMap(pathViolations).length === 0, 'нарушений в чистом архиве нет')

// --- Итог --------------------------------------------------------------------

console.log(`\nПроверок: ${checks}, провалов: ${failures}`)
if (failures) {
  console.error('Проверки отбраковки не пройдены.')
  process.exit(1)
}
console.log('Все проверки отбраковки пройдены.')
