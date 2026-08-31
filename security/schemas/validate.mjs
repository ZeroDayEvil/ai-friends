#!/usr/bin/env node
/**
 * Проверка схем контракта плоскости управления и примеров к ним.
 *
 * Запуск: node security/schemas/validate.mjs
 * Код возврата 1, если найдено нарушение.
 *
 * Зависимостей нет намеренно. Готовый валидатор JSON Schema — это дерево из
 * десятков пакетов, которое пришлось бы закреплять по политике из
 * security/README.md и обновлять отдельным ревью. Ради проверки полутора
 * десятков файлов такая цена не оправдана, а «схемы есть, но никто их ни разу
 * не применял» — состояние, ради ухода от которого этот файл и написан.
 *
 * Реализовано подмножество Draft 2020-12, которым пользуются наши схемы:
 * $ref (URN с фрагментом-указателем и фрагмент относительно текущего $id),
 * $defs, type, enum, const, properties, patternProperties,
 * additionalProperties, propertyNames, required, dependentRequired,
 * minProperties, maxProperties, items, prefixItems, contains, minItems,
 * maxItems, uniqueItems, minimum, maximum, exclusiveMinimum,
 * exclusiveMaximum, multipleOf, minLength, maxLength, pattern, format,
 * allOf, anyOf, oneOf, not, if/then/else, а также логические схемы true и
 * false.
 *
 * Три свойства, которые здесь важнее полноты.
 *
 * 1. Отказ по умолчанию. Неизвестное ключевое слово в схеме, неизвестное имя
 *    типа и неизвестное имя формата — ошибка, а не пропуск. Молча
 *    проигнорированное ограничение опаснее отсутствующего: по файлу кажется,
 *    что проверка есть.
 *
 * 2. Только собственные свойства. Доступ к полям экземпляра и схемы идёт через
 *    дескрипторы, а не через obj[key]. Разбор JSON создаёт "__proto__"
 *    собственным свойством, но соседние имена вроде "constructor" разрешаются
 *    по цепочке прототипов, и тогда отсутствующее в документе поле выглядит
 *    существующим, а отсутствующая подсхема — заданной. Имена "__proto__",
 *    "constructor" и "prototype" в экземпляре отвергаются до проверки схемы.
 *
 * 3. Разбор времени, а не сопоставление с образцом. Образец пропускает
 *    2026-02-30 и 2026-01-01T25:00:00Z. В журнале аудита, который
 *    упорядочивается по времени, несуществующая дата — это запись, которую
 *    нельзя поместить на ось.
 *
 * Часть ограничений контракта связывает несколько полей и на языке схем не
 * выражается: совпадение срока с парой отметок времени, совпадение подписанной
 * привязки с полями запроса, соответствие объявленного класса адреса самому
 * адресу. Они реализованы отдельными инвариантами ниже и перечислены в README.
 */
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const examplesDir = join(here, 'examples')

const ID_RE = /^urn:ai-friends:schema:agent:v1:[a-z][a-z0-9-]*$/

const KNOWN = new Set([
  '$schema', '$id', '$defs', '$ref', '$comment',
  'title', 'description', 'default', 'examples', 'deprecated',
  'format',
  'type', 'enum', 'const',
  'properties', 'patternProperties', 'additionalProperties', 'propertyNames',
  'required', 'dependentRequired', 'minProperties', 'maxProperties',
  'items', 'prefixItems', 'contains', 'minItems', 'maxItems', 'uniqueItems',
  'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf',
  'minLength', 'maxLength', 'pattern',
  'allOf', 'anyOf', 'oneOf', 'not', 'if', 'then', 'else'
])

const KNOWN_FORMATS = new Set(['date-time'])
const TYPES = new Set(['null', 'boolean', 'object', 'array', 'number', 'string', 'integer'])
const POISON_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

const APPLICATORS_OBJ = ['properties', 'patternProperties', '$defs']
const APPLICATORS_ARR = ['allOf', 'anyOf', 'oneOf', 'prefixItems']
const APPLICATORS_ONE = ['additionalProperties', 'propertyNames', 'items', 'contains', 'not', 'if', 'then', 'else']

const problems = []
const registry = new Map()

// --- Доступ только к собственным свойствам --------------------------------

function hasOwn (obj, key) {
  return obj !== null && typeof obj === 'object' && Object.hasOwn(obj, key)
}

function getOwn (obj, key) {
  if (!hasOwn(obj, key)) return undefined
  return Object.getOwnPropertyDescriptor(obj, key).value
}

function ownKeys (obj) {
  return Object.keys(obj)
}

// --- Разбор времени по RFC 3339 -------------------------------------------

const DATE_TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/

function isLeapYear (year) {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0
}

function daysInMonth (year, month) {
  const table = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  if (month === 2 && isLeapYear(year)) return 29
  return table[month - 1]
}

/**
 * Строгий разбор отметки времени, возвращает миллисекунды эпохи или null.
 * Смещения не принимаются: журнал упорядочивается по времени, а локальные
 * смещения дают неоднозначный порядок. Шестидесятая секунда не принимается
 * тоже — RFC 3339 допускает её для високосной секунды, но представить её
 * объектом Date нельзя, и одно мгновение получило бы две несравнимые записи.
 */
function parseTimestamp (value) {
  if (typeof value !== 'string') return null
  const m = DATE_TIME_RE.exec(value)
  if (!m) return null
  const year = Number(m[1])
  const month = Number(m[2])
  const day = Number(m[3])
  const hour = Number(m[4])
  const minute = Number(m[5])
  const second = Number(m[6])
  if (month < 1 || month > 12) return null
  if (day < 1 || day > daysInMonth(year, month)) return null
  if (hour > 23 || minute > 59 || second > 59) return null
  const fraction = m[7] ? Number(`0.${m[7]}`) : 0
  return Date.UTC(year, month - 1, day, hour, minute, second) + Math.round(fraction * 1000)
}

// --- Разбор и классификация адресов ---------------------------------------

function parseIpv4 (value) {
  const parts = value.split('.')
  if (parts.length !== 4) return null
  const octets = []
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null
    const n = Number(part)
    if (n > 255) return null
    octets.push(n)
  }
  return octets
}

/**
 * Класс адреса вычисляется разбором, а не сопоставлением с текстом. Значения
 * mesh и control_plane зависят от развёртывания и из самого адреса не
 * выводятся: для них проверяется лишь то, что адрес не публичный и не
 * служебный, иначе объявить публичный адрес относящимся к меш-сети означало бы
 * обойти проверку.
 */
function classifyAddress (value) {
  if (typeof value !== 'string') return null
  const bare = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value
  const v4 = parseIpv4(bare)
  if (v4) {
    const [a, b] = v4
    if (bare === '169.254.169.254') return 'metadata'
    if (a === 127) return 'loopback'
    if (a === 169 && b === 254) return 'link_local'
    if (a === 10) return 'private'
    if (a === 172 && b >= 16 && b <= 31) return 'private'
    if (a === 192 && b === 168) return 'private'
    if (a === 100 && b >= 64 && b <= 127) return 'private'
    return 'public'
  }
  if (!/^[0-9a-fA-F:]+$/.test(bare)) return null
  const lower = bare.toLowerCase()
  if (lower === '::1' || lower === '::') return 'loopback'
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return 'link_local'
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return 'private'
  return 'public'
}

const DEPLOYMENT_CLASSES = new Set(['mesh', 'control_plane'])

function classMatches (declared, address) {
  const computed = classifyAddress(address)
  if (computed === null) return { ok: false, computed: 'неразбираемый' }
  if (DEPLOYMENT_CLASSES.has(declared)) {
    return { ok: computed !== 'public' && computed !== 'metadata', computed }
  }
  return { ok: declared === computed, computed }
}

// --- Загрузка схем ---------------------------------------------------------

function loadSchemas () {
  const files = readdirSync(here).filter((f) => f.endsWith('.json')).sort()
  for (const file of files) {
    let doc
    try {
      doc = JSON.parse(readFileSync(join(here, file), 'utf8'))
    } catch (err) {
      problems.push(`${file}: не разбирается как JSON: ${err.message}`)
      continue
    }
    if (getOwn(doc, '$schema') !== 'https://json-schema.org/draft/2020-12/schema') {
      problems.push(`${file}: ожидается $schema Draft 2020-12`)
    }
    const id = getOwn(doc, '$id')
    if (typeof id !== 'string' || !ID_RE.test(id)) {
      problems.push(`${file}: $id "${id}" не соответствует urn:ai-friends:schema:agent:v1:<имя>`)
      continue
    }
    if (registry.has(id)) problems.push(`${file}: $id "${id}" уже занят`)
    registry.set(id, doc)
  }
  return files
}

// --- Разрешение ссылок -----------------------------------------------------

function unescapePointerToken (token) {
  return token.replace(/~1/g, '/').replace(/~0/g, '~')
}

function walkPointer (root, pointer, where) {
  if (pointer === '' || pointer === undefined) return root
  if (!pointer.startsWith('/')) throw new Error(`${where}: фрагмент "${pointer}" не является указателем JSON`)
  let node = root
  for (const raw of pointer.slice(1).split('/')) {
    const token = unescapePointerToken(raw)
    if (!hasOwn(node, token)) throw new Error(`${where}: указатель "${pointer}" никуда не ведёт`)
    node = getOwn(node, token)
  }
  return node
}

function resolveRef (ref, baseId, where) {
  const hash = ref.indexOf('#')
  const id = hash === -1 ? ref : ref.slice(0, hash)
  const fragment = hash === -1 ? '' : ref.slice(hash + 1)
  const targetId = id === '' ? baseId : id
  const root = registry.get(targetId)
  if (!root) throw new Error(`${where}: схема "${targetId}" не найдена`)
  return { schema: walkPointer(root, fragment, where), baseId: targetId }
}

// --- Структурная самопроверка схем ----------------------------------------

let refsChecked = 0

function auditSchema (node, baseId, where) {
  if (typeof node === 'boolean') return
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    problems.push(`${where}: подсхема должна быть объектом или логическим значением`)
    return
  }
  for (const key of ownKeys(node)) {
    if (!KNOWN.has(key)) problems.push(`${where}: неизвестное ключевое слово "${key}"`)
  }
  const format = getOwn(node, 'format')
  if (format !== undefined && !KNOWN_FORMATS.has(format)) {
    problems.push(`${where}: неизвестное имя формата "${format}": валидатор не умеет его проверять`)
  }
  const declaredType = getOwn(node, 'type')
  if (declaredType !== undefined) {
    const list = Array.isArray(declaredType) ? declaredType : [declaredType]
    for (const t of list) {
      if (!TYPES.has(t)) problems.push(`${where}: неизвестное имя типа "${t}"`)
    }
  }
  const ref = getOwn(node, '$ref')
  if (typeof ref === 'string') {
    try {
      resolveRef(ref, baseId, where)
      refsChecked += 1
    } catch (err) {
      problems.push(err.message)
    }
  }
  for (const key of APPLICATORS_OBJ) {
    const holder = getOwn(node, key)
    if (holder && typeof holder === 'object' && !Array.isArray(holder)) {
      for (const name of ownKeys(holder)) auditSchema(getOwn(holder, name), baseId, `${where}/${key}/${name}`)
    }
  }
  for (const key of APPLICATORS_ARR) {
    const list = getOwn(node, key)
    if (Array.isArray(list)) list.forEach((sub, i) => auditSchema(sub, baseId, `${where}/${key}/${i}`))
  }
  for (const key of APPLICATORS_ONE) {
    if (hasOwn(node, key)) auditSchema(getOwn(node, key), baseId, `${where}/${key}`)
  }
  const pattern = getOwn(node, 'pattern')
  if (typeof pattern === 'string') {
    try {
      new RegExp(pattern, 'u')
    } catch (err) {
      problems.push(`${where}: pattern не компилируется: ${err.message}`)
    }
  }
  const required = getOwn(node, 'required')
  const properties = getOwn(node, 'properties')
  const patternProperties = getOwn(node, 'patternProperties')
  if (Array.isArray(required) && properties !== undefined && getOwn(node, 'additionalProperties') === false) {
    for (const name of required) {
      const declared = hasOwn(properties, name) ||
        (patternProperties && ownKeys(patternProperties).some((p) => new RegExp(p, 'u').test(name)))
      if (!declared) problems.push(`${where}: поле "${name}" требуется, но не объявлено при закрытой схеме`)
    }
  }
}

// --- Валидация экземпляра --------------------------------------------------

function canonical (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  const keys = ownKeys(value).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(getOwn(value, k))}`).join(',')}}`
}

function typeOf (value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number'
  return typeof value
}

function typeMatches (value, expected) {
  const actual = typeOf(value)
  if (expected === 'number') return actual === 'number' || actual === 'integer'
  return actual === expected
}

function scanPoisonKeys (value, path, errors) {
  if (Array.isArray(value)) {
    value.forEach((item, i) => scanPoisonKeys(item, `${path}/${i}`, errors))
    return
  }
  if (value === null || typeof value !== 'object') return
  for (const key of ownKeys(value)) {
    if (POISON_KEYS.has(key)) {
      errors.push(`${path}/${key}: запрещённое имя поля "${key}"`)
      continue
    }
    scanPoisonKeys(getOwn(value, key), `${path}/${key}`, errors)
  }
}

function validate (value, schema, baseId, path, errors, depth = 0) {
  if (depth > 64) {
    errors.push(`${path}: превышена глубина разбора схемы`)
    return
  }
  if (schema === true) return
  if (schema === false) {
    errors.push(`${path}: значение запрещено схемой`)
    return
  }
  let base = baseId
  const ref = getOwn(schema, '$ref')
  if (typeof ref === 'string') {
    const resolved = resolveRef(ref, base, path)
    validate(value, resolved.schema, resolved.baseId, path, errors, depth + 1)
  }
  const ownId = getOwn(schema, '$id')
  if (typeof ownId === 'string') base = ownId

  const declaredType = getOwn(schema, 'type')
  if (declaredType !== undefined) {
    const types = Array.isArray(declaredType) ? declaredType : [declaredType]
    if (!types.some((t) => typeMatches(value, t))) {
      errors.push(`${path}: тип ${typeOf(value)}, ожидался ${types.join(' или ')}`)
      return
    }
  }
  if (hasOwn(schema, 'const') && canonical(value) !== canonical(getOwn(schema, 'const'))) {
    errors.push(`${path}: ожидалось ${JSON.stringify(getOwn(schema, 'const'))}`)
  }
  const enumeration = getOwn(schema, 'enum')
  if (enumeration !== undefined) {
    const wanted = enumeration.map(canonical)
    if (!wanted.includes(canonical(value))) errors.push(`${path}: ${JSON.stringify(value)} вне перечисления`)
  }

  const kind = typeOf(value)

  if (kind === 'string') {
    const chars = [...value]
    const minLength = getOwn(schema, 'minLength')
    const maxLength = getOwn(schema, 'maxLength')
    const pattern = getOwn(schema, 'pattern')
    const format = getOwn(schema, 'format')
    if (minLength !== undefined && chars.length < minLength) errors.push(`${path}: короче ${minLength}`)
    if (maxLength !== undefined && chars.length > maxLength) errors.push(`${path}: длиннее ${maxLength}`)
    if (pattern !== undefined && !new RegExp(pattern, 'u').test(value)) {
      errors.push(`${path}: не подходит под pattern ${pattern}`)
    }
    if (format === 'date-time' && parseTimestamp(value) === null) {
      errors.push(`${path}: "${value}" не является отметкой времени RFC 3339 в UTC`)
    }
  }

  if (kind === 'number' || kind === 'integer') {
    const minimum = getOwn(schema, 'minimum')
    const maximum = getOwn(schema, 'maximum')
    const exclusiveMinimum = getOwn(schema, 'exclusiveMinimum')
    const exclusiveMaximum = getOwn(schema, 'exclusiveMaximum')
    const multipleOf = getOwn(schema, 'multipleOf')
    if (minimum !== undefined && value < minimum) errors.push(`${path}: меньше ${minimum}`)
    if (maximum !== undefined && value > maximum) errors.push(`${path}: больше ${maximum}`)
    if (exclusiveMinimum !== undefined && value <= exclusiveMinimum) errors.push(`${path}: не больше ${exclusiveMinimum}`)
    if (exclusiveMaximum !== undefined && value >= exclusiveMaximum) errors.push(`${path}: не меньше ${exclusiveMaximum}`)
    if (multipleOf !== undefined) {
      const ratio = value / multipleOf
      if (Math.abs(ratio - Math.round(ratio)) > 1e-9) errors.push(`${path}: не кратно ${multipleOf}`)
    }
  }

  if (kind === 'array') {
    const prefix = Array.isArray(getOwn(schema, 'prefixItems')) ? getOwn(schema, 'prefixItems') : []
    prefix.forEach((sub, i) => {
      if (i < value.length) validate(value[i], sub, base, `${path}/${i}`, errors, depth + 1)
    })
    if (hasOwn(schema, 'items')) {
      const items = getOwn(schema, 'items')
      for (let i = prefix.length; i < value.length; i += 1) {
        validate(value[i], items, base, `${path}/${i}`, errors, depth + 1)
      }
    }
    const minItems = getOwn(schema, 'minItems')
    const maxItems = getOwn(schema, 'maxItems')
    if (minItems !== undefined && value.length < minItems) errors.push(`${path}: элементов меньше ${minItems}`)
    if (maxItems !== undefined && value.length > maxItems) errors.push(`${path}: элементов больше ${maxItems}`)
    if (getOwn(schema, 'uniqueItems') === true) {
      const seen = new Set()
      for (const item of value) {
        const key = canonical(item)
        if (seen.has(key)) {
          errors.push(`${path}: повторяющийся элемент ${key}`)
          break
        }
        seen.add(key)
      }
    }
    if (hasOwn(schema, 'contains')) {
      const contains = getOwn(schema, 'contains')
      const ok = value.some((item) => {
        const probe = []
        validate(item, contains, base, `${path}/*`, probe, depth + 1)
        return probe.length === 0
      })
      if (!ok) {
        const wanted = hasOwn(contains, 'const')
          ? ` ${JSON.stringify(getOwn(contains, 'const'))}`
          : ''
        errors.push(`${path}: нет элемента, подходящего под contains${wanted}`)
      }
    }
  }

  if (kind === 'object') {
    const names = ownKeys(value)
    const properties = getOwn(schema, 'properties')
    const patternProperties = getOwn(schema, 'patternProperties')
    const additional = hasOwn(schema, 'additionalProperties') ? getOwn(schema, 'additionalProperties') : undefined
    const propertyNames = hasOwn(schema, 'propertyNames') ? getOwn(schema, 'propertyNames') : undefined
    for (const name of getOwn(schema, 'required') ?? []) {
      if (!names.includes(name)) errors.push(`${path}: нет обязательного поля "${name}"`)
    }
    const minProperties = getOwn(schema, 'minProperties')
    const maxProperties = getOwn(schema, 'maxProperties')
    if (minProperties !== undefined && names.length < minProperties) errors.push(`${path}: полей меньше ${minProperties}`)
    if (maxProperties !== undefined && names.length > maxProperties) errors.push(`${path}: полей больше ${maxProperties}`)
    const dependentRequired = getOwn(schema, 'dependentRequired')
    if (dependentRequired) {
      for (const name of ownKeys(dependentRequired)) {
        if (!names.includes(name)) continue
        for (const dep of getOwn(dependentRequired, name)) {
          if (!names.includes(dep)) errors.push(`${path}: поле "${name}" требует "${dep}"`)
        }
      }
    }
    for (const name of names) {
      const child = getOwn(value, name)
      let covered = false
      if (properties && hasOwn(properties, name)) {
        covered = true
        validate(child, getOwn(properties, name), base, `${path}/${name}`, errors, depth + 1)
      }
      if (patternProperties) {
        for (const pattern of ownKeys(patternProperties)) {
          if (new RegExp(pattern, 'u').test(name)) {
            covered = true
            validate(child, getOwn(patternProperties, pattern), base, `${path}/${name}`, errors, depth + 1)
          }
        }
      }
      if (!covered && additional !== undefined) {
        if (additional === false) errors.push(`${path}: неизвестное поле "${name}"`)
        else validate(child, additional, base, `${path}/${name}`, errors, depth + 1)
      }
      if (propertyNames !== undefined) {
        validate(name, propertyNames, base, `${path}/${name}<имя>`, errors, depth + 1)
      }
    }
  }

  for (const sub of getOwn(schema, 'allOf') ?? []) validate(value, sub, base, path, errors, depth + 1)

  const anyOf = getOwn(schema, 'anyOf')
  if (Array.isArray(anyOf)) {
    const collected = []
    const ok = anyOf.some((sub) => {
      const probe = []
      validate(value, sub, base, path, probe, depth + 1)
      collected.push(...probe)
      return probe.length === 0
    })
    if (!ok) errors.push(`${path}: ни один вариант anyOf не подошёл (${collected.slice(0, 3).join('; ')})`)
  }

  const oneOf = getOwn(schema, 'oneOf')
  if (Array.isArray(oneOf)) {
    let matched = 0
    const collected = []
    for (const sub of oneOf) {
      const probe = []
      validate(value, sub, base, path, probe, depth + 1)
      if (probe.length === 0) matched += 1
      else collected.push(...probe)
    }
    if (matched !== 1) {
      errors.push(`${path}: под oneOf подошло вариантов: ${matched}, требуется ровно один (${collected.slice(0, 3).join('; ')})`)
    }
  }

  if (hasOwn(schema, 'not')) {
    const probe = []
    validate(value, getOwn(schema, 'not'), base, path, probe, depth + 1)
    if (probe.length === 0) errors.push(`${path}: значение подошло под not`)
  }

  if (hasOwn(schema, 'if')) {
    const probe = []
    validate(value, getOwn(schema, 'if'), base, path, probe, depth + 1)
    const branch = probe.length === 0 ? getOwn(schema, 'then') : getOwn(schema, 'else')
    if (branch !== undefined) validate(value, branch, base, path, errors, depth + 1)
  }
}

// --- Инварианты, не выразимые схемой --------------------------------------

function at (root, ...keys) {
  let node = root
  for (const key of keys) {
    if (!hasOwn(node, key)) return undefined
    node = getOwn(node, key)
  }
  return node
}

function sameShape (a, b) {
  return canonical(a) === canonical(b)
}

const INVARIANTS = {
  'urn:ai-friends:schema:agent:v1:token': [
    function tokenTtlMatchesWindow (doc, errors) {
      const ttl = at(doc, 'af_ttl')
      const nbf = at(doc, 'nbf')
      const exp = at(doc, 'exp')
      if (typeof ttl !== 'number' || typeof nbf !== 'number' || typeof exp !== 'number') return
      if (exp - nbf !== ttl) errors.push(`af_ttl=${ttl} не совпадает с exp − nbf=${exp - nbf}`)
    },
    function execBindingMatchesToken (doc, errors) {
      const binding = at(doc, 'af_binding')
      if (binding === undefined) return
      const pairs = [
        ['af_request_id', 'request_id'],
        ['af_approval_id', 'approval_id'],
        ['af_args_hash', 'args_hash'],
        ['sid', 'session_id'],
        ['af_policy', 'policy']
      ]
      for (const [outer, inner] of pairs) {
        const left = at(doc, outer)
        const right = at(binding, inner)
        if (left === undefined || right === undefined) continue
        if (!sameShape(left, right)) errors.push(`af_binding.${inner} не совпадает с ${outer}`)
      }
      const sub = at(doc, 'sub')
      const actor = at(binding, 'actor', 'id')
      if (sub !== undefined && actor !== undefined && sub !== actor) {
        errors.push(`af_binding.actor.id=${actor} не совпадает с sub=${sub}`)
      }
    }
  ],
  'urn:ai-friends:schema:agent:v1:approval': [
    function approvalTtlMatchesWindow (doc, errors) {
      const ttl = at(doc, 'ttl_seconds')
      const from = parseTimestamp(at(doc, 'approved_at'))
      const to = parseTimestamp(at(doc, 'expires_at'))
      if (typeof ttl !== 'number' || from === null || to === null) return
      const actual = (to - from) / 1000
      if (actual !== ttl) errors.push(`ttl_seconds=${ttl} не совпадает с expires_at − approved_at=${actual}`)
    },
    function approvalUsesWithinLimit (doc, errors) {
      const uses = at(doc, 'uses')
      const max = at(doc, 'max_uses')
      if (typeof uses !== 'number' || typeof max !== 'number') return
      if (uses > max) errors.push(`uses=${uses} превышает max_uses=${max}`)
    }
  ],
  'urn:ai-friends:schema:agent:v1:share': [
    function shareExpiryMatchesTtl (doc, errors) {
      const ttl = at(doc, 'ttl_seconds')
      const from = parseTimestamp(at(doc, 'created_at'))
      const to = parseTimestamp(at(doc, 'expires_at'))
      if (typeof ttl !== 'number' || from === null || to === null) return
      const actual = (to - from) / 1000
      if (actual !== ttl) errors.push(`ttl_seconds=${ttl} не совпадает с expires_at − created_at=${actual}`)
    },
    function shareAddressClassMatches (doc, errors) {
      const address = at(doc, 'bind', 'address')
      const declared = at(doc, 'bind', 'address_class')
      if (address === undefined || declared === undefined) return
      const verdict = classMatches(declared, address)
      if (!verdict.ok) errors.push(`bind.address_class=${declared} не соответствует адресу ${address} (класс ${verdict.computed})`)
    }
  ],
  'urn:ai-friends:schema:agent:v1:connect-request': [
    function connectAuthorizationBindsRequest (doc, errors) {
      const auth = at(doc, 'authorization')
      if (auth === undefined) return
      const pairs = [
        ['profile_ref', 'profile_ref'],
        ['target', 'target'],
        ['hop_via', 'hop_via'],
        ['actor', 'actor'],
        ['request_id', 'request_id'],
        ['approval_id', 'approval_id']
      ]
      for (const [outer, inner] of pairs) {
        const left = at(doc, outer)
        const right = at(auth, inner)
        if (left === undefined && right === undefined) continue
        if (!sameShape(left, right)) errors.push(`authorization.${inner} не совпадает с полем запроса ${outer}`)
      }
      const targetProtocol = at(doc, 'target', 'protocol')
      const authProtocol = at(auth, 'protocol')
      if (targetProtocol !== undefined && authProtocol !== undefined && targetProtocol !== authProtocol) {
        errors.push(`authorization.protocol=${authProtocol} не совпадает с target.protocol=${targetProtocol}`)
      }
    }
  ],
  'urn:ai-friends:schema:agent:v1:egress-decision': [
    function egressAddressClassMatches (doc, errors) {
      const list = at(doc, 'resolved_ips')
      if (!Array.isArray(list)) return
      list.forEach((entry, i) => {
        const address = at(entry, 'address')
        const declared = at(entry, 'class')
        if (address === undefined || declared === undefined) return
        const verdict = classMatches(declared, address)
        if (!verdict.ok) errors.push(`resolved_ips/${i}: класс ${declared} не соответствует адресу ${address} (класс ${verdict.computed})`)
      })
    },
    function egressExceptionCoversAddress (doc, errors) {
      if (at(doc, 'decision') !== 'allow') return
      const list = at(doc, 'resolved_ips')
      if (!Array.isArray(list)) return
      const offending = list.filter((entry) => at(entry, 'class') !== 'public')
      if (offending.length === 0) return
      const exception = at(doc, 'resource_exception')
      if (exception === undefined) return
      const permitted = at(exception, 'permitted_address')
      const port = at(exception, 'permitted_port')
      for (const entry of offending) {
        if (at(entry, 'address') !== permitted) {
          errors.push(`resource_exception разрешает ${permitted}, но среди адресов есть непубличный ${at(entry, 'address')}`)
        }
        if (at(entry, 'class') !== at(exception, 'permitted_class')) {
          errors.push(`resource_exception разрешает класс ${at(exception, 'permitted_class')}, а адрес ${at(entry, 'address')} относится к классу ${at(entry, 'class')}`)
        }
      }
      const requestedPort = at(doc, 'requested', 'port')
      if (requestedPort !== undefined && port !== undefined && requestedPort !== port) {
        errors.push(`resource_exception разрешает порт ${port}, запрошен ${requestedPort}`)
      }
    }
  ],
  'urn:ai-friends:schema:agent:v1:audit-event': [
    function auditRecordedNotBeforeOccurred (doc, errors) {
      const occurred = parseTimestamp(at(doc, 'occurred_at'))
      const recorded = parseTimestamp(at(doc, 'recorded_at'))
      if (occurred === null || recorded === null) return
      if (recorded < occurred) errors.push('recorded_at раньше occurred_at: запись доставлена до того, как событие произошло')
    },
    function auditCheckpointRangeConsistent (doc, errors) {
      const checkpoint = at(doc, 'checkpoint')
      if (checkpoint === undefined) return
      const from = at(checkpoint, 'from_seq')
      const to = at(checkpoint, 'to_seq')
      const count = at(checkpoint, 'count')
      if (typeof from !== 'number' || typeof to !== 'number' || typeof count !== 'number') return
      if (to < from) errors.push('checkpoint.to_seq меньше from_seq')
      else if (to - from + 1 !== count) errors.push(`checkpoint.count=${count} не совпадает с размером диапазона ${to - from + 1}`)
    }
  ],
  'urn:ai-friends:schema:agent:v1:tool-request': [
    function requestDeadlineAfterIssue (doc, errors) {
      const issued = parseTimestamp(at(doc, 'issued_at'))
      const deadline = parseTimestamp(at(doc, 'deadline'))
      if (issued === null || deadline === null) return
      if (deadline <= issued) errors.push('deadline не позже issued_at: запрос просрочен в момент подачи')
    }
  ],
  'urn:ai-friends:schema:agent:v1:tool-result': [
    function resultFinishedAfterStart (doc, errors) {
      const started = parseTimestamp(at(doc, 'started_at'))
      const finished = parseTimestamp(at(doc, 'finished_at'))
      if (started === null || finished === null) return
      if (finished < started) errors.push('finished_at раньше started_at')
    }
  ]
}

function runInvariants (schemaId, instance, errors) {
  for (const check of INVARIANTS[schemaId] ?? []) {
    try {
      check(instance, errors)
    } catch (err) {
      errors.push(`инвариант ${check.name} прерван: ${err.message}`)
    }
  }
}

// --- Прогон ---------------------------------------------------------------

const files = loadSchemas()
for (const [id, doc] of registry) auditSchema(doc, id, id)

let cases = []
try {
  cases = JSON.parse(readFileSync(join(examplesDir, 'index.json'), 'utf8')).cases
} catch (err) {
  problems.push(`examples/index.json не читается: ${err.message}`)
}

const listed = new Set(cases.map((c) => c.file))
for (const file of readdirSync(examplesDir)) {
  if (file !== 'index.json' && !listed.has(file)) problems.push(`examples/${file}: не перечислен в index.json`)
}

let checked = 0
let invariantCases = 0
for (const testCase of cases) {
  const where = `examples/${testCase.file}`
  let instance
  try {
    instance = JSON.parse(readFileSync(join(examplesDir, testCase.file), 'utf8'))
  } catch (err) {
    problems.push(`${where}: не читается: ${err.message}`)
    continue
  }
  let target
  try {
    target = resolveRef(testCase.schema, '', where)
  } catch (err) {
    problems.push(`${where}: ${err.message}`)
    continue
  }
  const errors = []
  try {
    scanPoisonKeys(instance, '', errors)
    validate(instance, target.schema, target.baseId, '', errors)
    runInvariants(testCase.schema, instance, errors)
  } catch (err) {
    problems.push(`${where}: разбор прерван: ${err.message}`)
    continue
  }
  checked += 1
  if (testCase.invariant) invariantCases += 1
  if (testCase.valid && errors.length) {
    problems.push(`${where}: пример должен быть корректным, но нарушений ${errors.length}: ${errors.slice(0, 4).join('; ')}`)
  }
  if (!testCase.valid && errors.length === 0) {
    problems.push(`${where}: пример должен быть отвергнут (${testCase.note ?? 'без пояснения'}), но прошёл проверку`)
  }
}

if (problems.length) {
  console.error(`Найдено нарушений: ${problems.length}\n`)
  for (const p of problems) console.error(`  - ${p}`)
  process.exit(1)
}
console.log(`Схем: ${files.length}. Ссылок проверено: ${refsChecked}. Примеров проверено: ${checked}, из них на инвариантах: ${invariantCases}. Нарушений нет.`)
