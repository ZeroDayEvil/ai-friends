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
 * exclusiveMaximum, multipleOf, minLength, maxLength, pattern, allOf, anyOf,
 * oneOf, not, if/then/else, а также логические схемы true и false.
 *
 * Ключевое слово format трактуется как аннотация, то есть не проверяется. Это
 * поведение Draft 2020-12 по умолчанию, и полагаться на него нельзя: там, где
 * формат важен, в схеме рядом стоит pattern.
 *
 * Неизвестное ключевое слово в схеме — ошибка, а не пропуск. Молча
 * проигнорированное ограничение опаснее отсутствующего: по файлу кажется, что
 * проверка есть.
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

const APPLICATORS_OBJ = ['properties', 'patternProperties', '$defs']
const APPLICATORS_ARR = ['allOf', 'anyOf', 'oneOf', 'prefixItems']
const APPLICATORS_ONE = ['additionalProperties', 'propertyNames', 'items', 'contains', 'not', 'if', 'then', 'else']

const problems = []
const registry = new Map()

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
    if (doc.$schema !== 'https://json-schema.org/draft/2020-12/schema') {
      problems.push(`${file}: ожидается $schema Draft 2020-12`)
    }
    if (typeof doc.$id !== 'string' || !ID_RE.test(doc.$id)) {
      problems.push(`${file}: $id "${doc.$id}" не соответствует urn:ai-friends:schema:agent:v1:<имя>`)
      continue
    }
    if (registry.has(doc.$id)) problems.push(`${file}: $id "${doc.$id}" уже занят`)
    registry.set(doc.$id, doc)
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
    if (node === null || typeof node !== 'object' || !(token in node)) {
      throw new Error(`${where}: указатель "${pointer}" никуда не ведёт`)
    }
    node = node[token]
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
  for (const key of Object.keys(node)) {
    if (!KNOWN.has(key)) problems.push(`${where}: неизвестное ключевое слово "${key}"`)
  }
  if (typeof node.$ref === 'string') {
    try {
      resolveRef(node.$ref, baseId, where)
      refsChecked += 1
    } catch (err) {
      problems.push(err.message)
    }
  }
  for (const key of APPLICATORS_OBJ) {
    if (node[key] && typeof node[key] === 'object') {
      for (const [name, sub] of Object.entries(node[key])) auditSchema(sub, baseId, `${where}/${key}/${name}`)
    }
  }
  for (const key of APPLICATORS_ARR) {
    if (Array.isArray(node[key])) node[key].forEach((sub, i) => auditSchema(sub, baseId, `${where}/${key}/${i}`))
  }
  for (const key of APPLICATORS_ONE) {
    if (node[key] !== undefined) auditSchema(node[key], baseId, `${where}/${key}`)
  }
  if (typeof node.pattern === 'string') {
    try {
      new RegExp(node.pattern)
    } catch (err) {
      problems.push(`${where}: pattern не компилируется: ${err.message}`)
    }
  }
  if (node.required !== undefined && node.properties !== undefined && node.additionalProperties === false) {
    for (const name of node.required) {
      const declared = name in node.properties ||
        (node.patternProperties && Object.keys(node.patternProperties).some((p) => new RegExp(p).test(name)))
      if (!declared) problems.push(`${where}: поле "${name}" требуется, но не объявлено при закрытой схеме`)
    }
  }
}

// --- Валидация экземпляра --------------------------------------------------

function canonical (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  const keys = Object.keys(value).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`
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
  if (typeof schema.$ref === 'string') {
    const resolved = resolveRef(schema.$ref, base, path)
    validate(value, resolved.schema, resolved.baseId, path, errors, depth + 1)
  }
  if (typeof schema.$id === 'string') base = schema.$id

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    if (!types.some((t) => typeMatches(value, t))) {
      errors.push(`${path}: тип ${typeOf(value)}, ожидался ${types.join(' или ')}`)
      return
    }
  }
  if (schema.const !== undefined && canonical(value) !== canonical(schema.const)) {
    errors.push(`${path}: ожидалось ${JSON.stringify(schema.const)}`)
  }
  if (schema.enum !== undefined) {
    const wanted = schema.enum.map(canonical)
    if (!wanted.includes(canonical(value))) errors.push(`${path}: ${JSON.stringify(value)} вне перечисления`)
  }

  const kind = typeOf(value)

  if (kind === 'string') {
    const chars = [...value]
    if (schema.minLength !== undefined && chars.length < schema.minLength) errors.push(`${path}: короче ${schema.minLength}`)
    if (schema.maxLength !== undefined && chars.length > schema.maxLength) errors.push(`${path}: длиннее ${schema.maxLength}`)
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(value)) {
      errors.push(`${path}: не подходит под pattern ${schema.pattern}`)
    }
  }

  if (kind === 'number' || kind === 'integer') {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path}: меньше ${schema.minimum}`)
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path}: больше ${schema.maximum}`)
    if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) errors.push(`${path}: не больше ${schema.exclusiveMinimum}`)
    if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) errors.push(`${path}: не меньше ${schema.exclusiveMaximum}`)
    if (schema.multipleOf !== undefined) {
      const ratio = value / schema.multipleOf
      if (Math.abs(ratio - Math.round(ratio)) > 1e-9) errors.push(`${path}: не кратно ${schema.multipleOf}`)
    }
  }

  if (kind === 'array') {
    const prefix = Array.isArray(schema.prefixItems) ? schema.prefixItems : []
    prefix.forEach((sub, i) => {
      if (i < value.length) validate(value[i], sub, base, `${path}/${i}`, errors, depth + 1)
    })
    if (schema.items !== undefined) {
      for (let i = prefix.length; i < value.length; i += 1) {
        validate(value[i], schema.items, base, `${path}/${i}`, errors, depth + 1)
      }
    }
    if (schema.minItems !== undefined && value.length < schema.minItems) errors.push(`${path}: элементов меньше ${schema.minItems}`)
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${path}: элементов больше ${schema.maxItems}`)
    if (schema.uniqueItems === true) {
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
    if (schema.contains !== undefined) {
      const ok = value.some((item) => {
        const probe = []
        validate(item, schema.contains, base, `${path}/*`, probe, depth + 1)
        return probe.length === 0
      })
      if (!ok) errors.push(`${path}: нет элемента, подходящего под contains`)
    }
  }

  if (kind === 'object') {
    const names = Object.keys(value)
    for (const name of schema.required ?? []) {
      if (!names.includes(name)) errors.push(`${path}: нет обязательного поля "${name}"`)
    }
    if (schema.minProperties !== undefined && names.length < schema.minProperties) errors.push(`${path}: полей меньше ${schema.minProperties}`)
    if (schema.maxProperties !== undefined && names.length > schema.maxProperties) errors.push(`${path}: полей больше ${schema.maxProperties}`)
    for (const [name, list] of Object.entries(schema.dependentRequired ?? {})) {
      if (names.includes(name)) {
        for (const dep of list) {
          if (!names.includes(dep)) errors.push(`${path}: поле "${name}" требует "${dep}"`)
        }
      }
    }
    for (const name of names) {
      let covered = false
      if (schema.properties && name in schema.properties) {
        covered = true
        validate(value[name], schema.properties[name], base, `${path}/${name}`, errors, depth + 1)
      }
      for (const [pattern, sub] of Object.entries(schema.patternProperties ?? {})) {
        if (new RegExp(pattern, 'u').test(name)) {
          covered = true
          validate(value[name], sub, base, `${path}/${name}`, errors, depth + 1)
        }
      }
      if (!covered && schema.additionalProperties !== undefined) {
        if (schema.additionalProperties === false) errors.push(`${path}: неизвестное поле "${name}"`)
        else validate(value[name], schema.additionalProperties, base, `${path}/${name}`, errors, depth + 1)
      }
      if (schema.propertyNames !== undefined) {
        validate(name, schema.propertyNames, base, `${path}/${name}<имя>`, errors, depth + 1)
      }
    }
  }

  for (const sub of schema.allOf ?? []) validate(value, sub, base, path, errors, depth + 1)

  if (Array.isArray(schema.anyOf)) {
    const collected = []
    const ok = schema.anyOf.some((sub) => {
      const probe = []
      validate(value, sub, base, path, probe, depth + 1)
      collected.push(...probe)
      return probe.length === 0
    })
    if (!ok) errors.push(`${path}: ни один вариант anyOf не подошёл (${collected.slice(0, 3).join('; ')})`)
  }

  if (Array.isArray(schema.oneOf)) {
    let matched = 0
    const collected = []
    for (const sub of schema.oneOf) {
      const probe = []
      validate(value, sub, base, path, probe, depth + 1)
      if (probe.length === 0) matched += 1
      else collected.push(...probe)
    }
    if (matched !== 1) {
      errors.push(`${path}: под oneOf подошло вариантов: ${matched}, требуется ровно один (${collected.slice(0, 3).join('; ')})`)
    }
  }

  if (schema.not !== undefined) {
    const probe = []
    validate(value, schema.not, base, path, probe, depth + 1)
    if (probe.length === 0) errors.push(`${path}: значение подошло под not`)
  }

  if (schema.if !== undefined) {
    const probe = []
    validate(value, schema.if, base, path, probe, depth + 1)
    const branch = probe.length === 0 ? schema.then : schema.else
    if (branch !== undefined) validate(value, branch, base, path, errors, depth + 1)
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
    validate(instance, target.schema, target.baseId, '', errors)
  } catch (err) {
    problems.push(`${where}: разбор прерван: ${err.message}`)
    continue
  }
  checked += 1
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
console.log(`Схем: ${files.length}. Ссылок проверено: ${refsChecked}. Примеров проверено: ${checked}. Нарушений нет.`)
