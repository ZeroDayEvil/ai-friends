#!/usr/bin/env node

import { createHash, timingSafeEqual } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, extname, join, posix, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { gunzipSync } from 'node:zlib'

export const TARGET = Object.freeze({
  repository: 'https://github.com/electerm/electerm-web',
  commit: 'f1deaf02fead7faa1bfb4381f69fbb734ea7f95f',
  packageVersion: '5.3.15',
  packageJsonUrl: 'https://raw.githubusercontent.com/electerm/electerm-web/f1deaf02fead7faa1bfb4381f69fbb734ea7f95f/package.json',
  packageLockUrl: 'https://raw.githubusercontent.com/electerm/electerm-web/f1deaf02fead7faa1bfb4381f69fbb734ea7f95f/package-lock.json',
  packageJsonSha256: 'edb4199c3a30b5fcc8a2856a949161f95aa5c162b4605207ddb8e3ffcbabd61a',
  packageLockSha256: '3a2953e0c45f4c942ba826b7ea915e5ad24e56bb31d35828954859ec84d5113c',
  expectedSerializedEntries: 1582
})

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url))
const REPOSITORY_ROOT = resolve(SCRIPT_DIR, '..', '..')
const DEFAULT_OUTPUT = join(
  REPOSITORY_ROOT,
  'security',
  'manifests',
  'npm-audit-electerm-web-5.3.15-f1deaf02.json'
)
const DEFAULT_CACHE = join(tmpdir(), 'ai-friends-npm-audit', TARGET.commit)
const LIFECYCLE_NAMES = [
  'preinstall',
  'install',
  'postinstall',
  'prepublish',
  'prepublishOnly',
  'prepare'
]
const INSTALL_SCRIPT_NAMES = new Set(['preinstall', 'install', 'postinstall'])
const ALLOWED_GITHUB_HOSTS = new Set(['raw.githubusercontent.com'])
const ALLOWED_REGISTRY_HOSTS = new Set(['registry.npmjs.org'])
const SUPPORTED_LOCKFILE_VERSIONS = new Set([2, 3])
const HIGH_PRIVILEGE_NAME = /(?:^|[-_/@])(?:ssh\d*|sftp|ftp|pty|serialport|rdp|vnc|spice|proxy|socks(?:v\d+)?|tar|archive|jsonwebtoken|express|multer|bash|sync|gist|gitee|mcp|extension|shell|terminal|websocket|crypto|tls)(?=$|[-_/@])/i
const FORBIDDEN_LICENSE = /\b(?:AGPL|GPL|SSPL|BUSL)(?:-\d+(?:\.\d+)*)?(?:-only|-or-later)?\b|UNLICENSED|SEE LICENSE/i
const EXACT_VERSION = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
const SOURCE_EXTENSIONS = new Set([
  '.c',
  '.cc',
  '.cjs',
  '.cpp',
  '.cts',
  '.gyp',
  '.gypi',
  '.h',
  '.hpp',
  '.js',
  '.json',
  '.jsx',
  '.mjs',
  '.mts',
  '.node-gyp',
  '.ps1',
  '.py',
  '.sh',
  '.ts',
  '.tsx'
])
const BINARY_EXTENSIONS = new Set([
  '.a',
  '.dll',
  '.dylib',
  '.exe',
  '.jar',
  '.lib',
  '.node',
  '.so',
  '.wasm'
])
const MANDATED_REVIEW_PACKAGES = new Set([
  '@novnc/novnc',
  'ironrdp-wasm',
  'spice-client'
])
const FEATURE_REPLACEMENTS = Object.freeze([
  {
    id: 'cloud-sync-remote-providers',
    directRoots: ['electerm-sync', 'gist-wrapper', 'gitee-client'],
    retainedSharedRoots: ['axios'],
    preservedProductCapabilities: ['AI', 'MCP', 'HTTP', 'FTP', 'self-hosted-sync'],
    assumption: 'Replace GitHub/Gitee/cloud sync adapters with a pinned self-hosted implementation.'
  },
  {
    id: 'runtime-npm-loader',
    directRoots: ['tar'],
    retainedSharedRoots: ['axios'],
    preservedProductCapabilities: ['AI', 'MCP', 'HTTP', 'FTP', 'reviewed-bundled-extensions'],
    assumption: 'Replace runtime npm download/extraction with a reviewed bundled extension catalog; keep shared HTTP/AI transport.'
  },
  {
    id: 'dynamic-config-extension-hook',
    directRoots: [],
    retainedSharedRoots: [],
    preservedProductCapabilities: ['AI', 'MCP', 'HTTP', 'FTP', 'reviewed-bundled-extensions'],
    assumption: 'Replace arbitrary config.js appExtend callbacks in repository code; no dedicated npm root is removable.'
  },
  {
    id: 'mcp-local-server-hardening',
    directRoots: [],
    retainedSharedRoots: ['express'],
    preservedProductCapabilities: ['AI', 'MCP', 'HTTP', 'FTP'],
    assumption: 'Keep the repository-owned MCP implementation and shared HTTP server dependency while requiring authentication and allowlisted tools.'
  },
  {
    id: 'node-bash-shell-helper',
    directRoots: ['node-bash'],
    retainedSharedRoots: [],
    preservedProductCapabilities: ['AI', 'MCP', 'HTTP', 'FTP', 'terminal'],
    assumption: 'Replace node-bash in filesystem size helpers with argument-vector subprocess calls; it is not an MCP dependency.'
  }
])

class AuditError extends Error {
  constructor (code, message) {
    super(message)
    this.name = 'AuditError'
    this.code = code
  }
}

function errorCode (error) {
  if (error instanceof AuditError) return error.code
  if (error && typeof error === 'object' && typeof error.code === 'string') {
    return error.code
  }
  return 'unexpected-error'
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function compareText (left, right) {
  const a = String(left)
  const b = String(right)
  return a < b ? -1 : (a > b ? 1 : 0)
}

function canonicalize (value) {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (value && typeof value === 'object') {
    const sorted = {}
    for (const key of Object.keys(value).sort()) sorted[key] = canonicalize(value[key])
    return sorted
  }
  return value
}

export function stableStringify (value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`
}

function writeAtomic (filePath, data) {
  mkdirSync(dirname(filePath), { recursive: true })
  const temporary = `${filePath}.${process.pid}.tmp`
  writeFileSync(temporary, data)
  renameSync(temporary, filePath)
}

function parseJson (buffer, label) {
  try {
    return JSON.parse(buffer.toString('utf8'))
  } catch (error) {
    throw new AuditError('malformed-json', `${label}: ${error.message}`)
  }
}

function validateHttpsHost (rawUrl, allowedHosts, code) {
  let parsed
  try {
    parsed = new URL(rawUrl)
  } catch {
    throw new AuditError(code, `Invalid URL: ${rawUrl}`)
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.port !== '' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    !allowedHosts.has(parsed.hostname)
  ) {
    throw new AuditError(code, `URL is outside the allowed source: ${rawUrl}`)
  }
  return parsed
}

async function fetchBounded (rawUrl, allowedHosts, options = {}) {
  validateHttpsHost(rawUrl, allowedHosts, 'forbidden-network-source')
  const maxBytes = options.maxBytes ?? 16 * 1024 * 1024
  const response = await fetch(rawUrl, {
    headers: {
      accept: options.accept ?? 'application/octet-stream',
      'user-agent': 'ai-friends-static-npm-audit/1'
    },
    redirect: 'error',
    signal: AbortSignal.timeout(options.timeoutMs ?? 30000)
  })
  if (!response.ok) {
    throw new AuditError(`http-${response.status}`, `HTTP ${response.status} for ${rawUrl}`)
  }
  if (response.url !== rawUrl) {
    throw new AuditError('unexpected-redirect', `Response URL changed for ${rawUrl}`)
  }
  const declaredLength = Number(response.headers.get('content-length'))
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new AuditError('response-too-large', `Response exceeds ${maxBytes} bytes`)
  }
  if (!response.body) throw new AuditError('empty-response-body', `No response body for ${rawUrl}`)

  const chunks = []
  let total = 0
  const reader = response.body.getReader()
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) {
      await reader.cancel()
      throw new AuditError('response-too-large', `Response exceeds ${maxBytes} bytes`)
    }
    chunks.push(Buffer.from(value))
  }
  return Buffer.concat(chunks, total)
}

function cacheFile (cacheDir, namespace, rawUrl, extension) {
  return join(cacheDir, namespace, `${sha256(rawUrl)}${extension}`)
}

async function readOfficialInput (source, expectedSource, expectedSha256, cacheDir, offline) {
  if (source !== expectedSource) {
    throw new AuditError('unexpected-github-source', `Expected exact pinned URL ${expectedSource}`)
  }
  validateHttpsHost(source, ALLOWED_GITHUB_HOSTS, 'forbidden-github-source')
  const file = cacheFile(cacheDir, 'github', source, '.json')
  if (existsSync(file)) {
    const cached = readFileSync(file)
    if (sha256(cached) === expectedSha256) return { data: cached, source }
    unlinkSync(file)
    if (offline) throw new AuditError('cached-input-digest-mismatch', `Cached input does not match ${expectedSha256}`)
  }
  if (offline) throw new AuditError('offline-cache-miss', `No cached GitHub input for ${source}`)
  const data = await fetchBounded(source, ALLOWED_GITHUB_HOSTS, {
    accept: 'application/json',
    maxBytes: 8 * 1024 * 1024
  })
  if (sha256(data) !== expectedSha256) {
    throw new AuditError('github-input-digest-mismatch', `Pinned input does not match ${expectedSha256}`)
  }
  writeAtomic(file, data)
  return { data, source }
}

function registryVersionUrl (name, version) {
  const encodedName = encodeURIComponent(name).replace(/^%40/, '@')
  return `https://registry.npmjs.org/${encodedName}/${encodeURIComponent(version)}`
}

async function readRegistryMetadata (coordinate, cacheDir, offline) {
  const url = registryVersionUrl(coordinate.name, coordinate.version)
  const file = cacheFile(cacheDir, 'registry-metadata', url, '.json')
  if (existsSync(file)) {
    const cached = readFileSync(file)
    try {
      const metadata = parseJson(cached, `${coordinate.name}@${coordinate.version} registry metadata`)
      return {
        status: 'available',
        registryUrl: url,
        metadataSha256: sha256(cached),
        value: metadata
      }
    } catch (error) {
      unlinkSync(file)
      if (offline) throw error
    }
  }
  if (offline) {
    return {
      status: 'unknown',
      error: 'offline-cache-miss',
      registryUrl: url
    }
  }
  const data = await fetchBounded(url, ALLOWED_REGISTRY_HOSTS, {
    accept: 'application/json',
    maxBytes: 8 * 1024 * 1024
  })
  const metadata = parseJson(data, `${coordinate.name}@${coordinate.version} registry metadata`)
  writeAtomic(file, data)
  return {
    status: 'available',
    registryUrl: url,
    metadataSha256: sha256(data),
    value: metadata
  }
}

async function rateLimitedMap (items, worker, options = {}) {
  const concurrency = Math.max(1, Math.min(options.concurrency ?? 4, 8))
  const delayMs = Math.max(options.delayMs ?? 75, 0)
  const results = new Array(items.length)
  let cursor = 0
  let nextStart = 0

  async function waitForSlot () {
    const now = Date.now()
    const wait = Math.max(0, nextStart - now)
    nextStart = Math.max(nextStart, now) + delayMs
    if (wait > 0) await new Promise(resolve => setTimeout(resolve, wait))
  }

  async function runWorker () {
    while (true) {
      const index = cursor++
      if (index >= items.length) return
      await waitForSlot()
      results[index] = await worker(items[index], index)
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, runWorker))
  return results
}

function packageNameFromPath (packagePath) {
  if (packagePath === '') return null
  const marker = 'node_modules/'
  const index = packagePath.lastIndexOf(marker)
  if (index === -1) return null
  const remainder = packagePath.slice(index + marker.length)
  const parts = remainder.split('/')
  if (parts[0].startsWith('@') && parts.length >= 2) return `${parts[0]}/${parts[1]}`
  return parts[0] || null
}

function coordinateKey (name, version) {
  return `${name}\u0000${version}`
}

function normalizedCoordinate (packagePath, record) {
  const name = typeof record.name === 'string' ? record.name : packageNameFromPath(packagePath)
  const version = typeof record.version === 'string' ? record.version : null
  if (!name || !version) return null
  return { name, version, key: coordinateKey(name, version) }
}

function normalizeStringArray (value) {
  if (typeof value === 'string') return [value]
  if (!Array.isArray(value)) return null
  return value.filter(item => typeof item === 'string').sort()
}

function normalizeBin (value, packageName) {
  if (typeof value === 'string') return packageName ? { [packageName]: value } : { unknown: value }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const result = {}
  for (const [name, target] of Object.entries(value).sort(([a], [b]) => compareText(a, b))) {
    if (typeof target === 'string') result[name] = target
  }
  return Object.keys(result).length ? result : null
}

function normalizeRepository (value) {
  if (typeof value === 'string') return value
  if (value && typeof value === 'object' && typeof value.url === 'string') return value.url
  return null
}

function normalizeLicenseDeclaration (manifest) {
  if (!manifest || typeof manifest !== 'object') return null
  if (typeof manifest.license === 'string') return manifest.license
  if (
    manifest.license &&
    typeof manifest.license === 'object' &&
    typeof manifest.license.type === 'string'
  ) {
    return manifest.license.type
  }
  if (!Array.isArray(manifest.licenses)) return null
  const types = [...new Set(manifest.licenses
    .map(license => typeof license === 'string' ? license : license?.type)
    .filter(type => typeof type === 'string' && type.trim() !== '')
    .map(type => type.trim()))].sort()
  if (types.length === 0) return null
  if (types.length === 1) return types[0]
  return `(${types.join(' OR ')})`
}

function lifecycleScripts (scripts) {
  if (!scripts || typeof scripts !== 'object' || Array.isArray(scripts)) return {}
  const selected = {}
  for (const name of LIFECYCLE_NAMES) {
    if (typeof scripts[name] === 'string') selected[name] = scripts[name]
  }
  return selected
}

function metadataNativeIndicators (metadata) {
  if (!metadata || typeof metadata !== 'object') return []
  const indicators = new Set()
  if (metadata.gypfile === true) indicators.add('gypfile')
  if (metadata.binary && typeof metadata.binary === 'object') indicators.add('binary-metadata')
  const searchable = JSON.stringify({
    scripts: metadata.scripts,
    dependencies: metadata.dependencies,
    optionalDependencies: metadata.optionalDependencies
  })
  for (const [name, pattern] of [
    ['node-gyp', /\bnode-gyp\b/i],
    ['node-gyp-build', /\bnode-gyp-build\b/i],
    ['node-pre-gyp', /\bnode-pre-gyp\b/i],
    ['prebuild-install', /\bprebuild-install\b/i],
    ['prebuildify', /\bprebuildify\b/i]
  ]) {
    if (pattern.test(searchable)) indicators.add(name)
  }
  return [...indicators].sort()
}

function resolvedSource (resolved) {
  if (typeof resolved !== 'string') return { host: null, scheme: null }
  try {
    const parsed = new URL(resolved)
    return {
      host: parsed.hostname || null,
      scheme: parsed.protocol.replace(/:$/, '') || null
    }
  } catch {
    const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(resolved)?.[1] ?? null
    return { host: null, scheme }
  }
}

function resolveDependencyPath (parentPath, dependencyName, packageMap) {
  let current = parentPath
  while (true) {
    const candidate = current
      ? `${current}/node_modules/${dependencyName}`
      : `node_modules/${dependencyName}`
    if (packageMap.has(candidate)) return candidate
    if (!current) break
    const nested = current.lastIndexOf('/node_modules/')
    current = nested === -1 ? '' : current.slice(0, nested)
  }
  return null
}

function edgeNames (record, includeDevelopment) {
  const result = new Set()
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    if (!record[field] || typeof record[field] !== 'object') continue
    for (const name of Object.keys(record[field])) result.add(name)
  }
  if (includeDevelopment && record.devDependencies && typeof record.devDependencies === 'object') {
    for (const name of Object.keys(record.devDependencies)) result.add(name)
  }
  return [...result].sort()
}

function traverseFromRoots (packageMap, roots, includeDevelopment) {
  const reached = new Set()
  const unresolved = []
  const queue = []
  for (const rootName of [...roots].sort()) {
    const packagePath = resolveDependencyPath('', rootName, packageMap)
    if (packagePath) queue.push(packagePath)
    else unresolved.push({ from: '', name: rootName })
  }
  while (queue.length) {
    const packagePath = queue.shift()
    if (reached.has(packagePath)) continue
    reached.add(packagePath)
    const record = packageMap.get(packagePath)
    for (const name of edgeNames(record, includeDevelopment)) {
      const target = resolveDependencyPath(packagePath, name, packageMap)
      if (target && !reached.has(target)) queue.push(target)
      else if (!target) {
        const optionalPeer = record.peerDependencies?.[name] !== undefined &&
          record.peerDependenciesMeta?.[name]?.optional === true &&
          record.dependencies?.[name] === undefined &&
          record.optionalDependencies?.[name] === undefined
        if (!optionalPeer) unresolved.push({ from: packagePath, name })
      }
    }
  }
  return {
    reached,
    unresolved: unresolved.sort((a, b) => compareText(
      `${a.from}\u0000${a.name}`,
      `${b.from}\u0000${b.name}`
    ))
  }
}

function buildReachability (packageJson, packageMap) {
  const runtimeRoots = new Set([
    ...Object.keys(packageJson.dependencies ?? {}),
    ...Object.keys(packageJson.optionalDependencies ?? {})
  ])
  const developmentRoots = new Set(Object.keys(packageJson.devDependencies ?? {}))
  const runtime = traverseFromRoots(packageMap, runtimeRoots, false)
  const development = traverseFromRoots(packageMap, developmentRoots, false)
  const direct = new Map()

  for (const [scope, dependencies] of [
    ['runtime', packageJson.dependencies],
    ['optional', packageJson.optionalDependencies],
    ['dev', packageJson.devDependencies]
  ]) {
    for (const name of Object.keys(dependencies ?? {}).sort()) {
      const packagePath = resolveDependencyPath('', name, packageMap)
      if (!packagePath) continue
      const detail = direct.get(packagePath) ?? { names: [], scopes: [], specs: [] }
      detail.names.push(name)
      detail.scopes.push(scope)
      detail.specs.push(dependencies[name])
      direct.set(packagePath, detail)
    }
  }

  return { runtime, development, direct }
}

function directSpecRisk (spec) {
  if (typeof spec !== 'string') return []
  const risks = []
  if (/^(?:git(?:\+[^:]+)?|github:|https?:|file:|link:)/i.test(spec)) {
    risks.push('git-or-url-declared-source')
  }
  if (!EXACT_VERSION.test(spec)) risks.push('floating-declared-spec')
  return risks
}

function parseSri (integrity) {
  if (typeof integrity !== 'string' || integrity.trim() === '') {
    throw new AuditError('missing-integrity', 'No dist.integrity value')
  }
  const priorities = new Map([
    ['sha512', 4],
    ['sha384', 3],
    ['sha256', 2],
    ['sha1', 1]
  ])
  const candidates = integrity.trim().split(/\s+/).map(token => {
    const match = /^(sha(?:1|256|384|512))-([A-Za-z0-9+/=]+)(?:\?.*)?$/.exec(token)
    if (!match || !priorities.has(match[1])) return null
    return { algorithm: match[1], digest: Buffer.from(match[2], 'base64') }
  }).filter(Boolean).sort((a, b) => priorities.get(b.algorithm) - priorities.get(a.algorithm))
  if (!candidates.length) throw new AuditError('unsupported-integrity', `Unsupported SRI: ${integrity}`)
  return candidates
}

export function verifyIntegrity (buffer, integrity) {
  const candidates = parseSri(integrity)
  const strongest = candidates[0].algorithm
  for (const candidate of candidates.filter(candidate => candidate.algorithm === strongest)) {
    const actual = createHash(candidate.algorithm).update(buffer).digest()
    if (
      actual.byteLength === candidate.digest.byteLength &&
      timingSafeEqual(actual, candidate.digest)
    ) {
      return { algorithm: candidate.algorithm, verified: true }
    }
  }
  throw new AuditError('integrity-mismatch', 'Downloaded bytes do not match dist.integrity')
}

function parseTarNumber (field) {
  if (field[0] & 0x80) {
    let value = BigInt(field[0] & 0x7f)
    for (let index = 1; index < field.length; index++) {
      value = (value << 8n) | BigInt(field[index])
    }
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new AuditError('tar-number-too-large', 'Tar number exceeds safe integer range')
    return Number(value)
  }
  const text = field.toString('ascii').replace(/\0.*$/, '').trim()
  if (text === '') return 0
  if (!/^[0-7]+$/.test(text)) throw new AuditError('invalid-tar-number', `Invalid tar number: ${text}`)
  return Number.parseInt(text, 8)
}

function tarText (field) {
  return field.toString('utf8').replace(/\0.*$/, '')
}

function verifyTarHeader (header) {
  const expected = parseTarNumber(header.subarray(148, 156))
  let actual = 0
  for (let index = 0; index < header.length; index++) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index]
  }
  if (actual !== expected) throw new AuditError('invalid-tar-checksum', 'Tar header checksum mismatch')
}

function parsePax (buffer) {
  const values = {}
  let offset = 0
  while (offset < buffer.length) {
    const space = buffer.indexOf(0x20, offset)
    if (space === -1) throw new AuditError('invalid-pax-record', 'PAX record has no length separator')
    const length = Number.parseInt(buffer.subarray(offset, space).toString('ascii'), 10)
    if (!Number.isSafeInteger(length) || length <= 0 || offset + length > buffer.length) {
      throw new AuditError('invalid-pax-record', 'PAX record length is invalid')
    }
    const record = buffer.subarray(space + 1, offset + length - 1).toString('utf8')
    const equals = record.indexOf('=')
    if (equals === -1) throw new AuditError('invalid-pax-record', 'PAX record has no key separator')
    values[record.slice(0, equals)] = record.slice(equals + 1)
    offset += length
  }
  return values
}

function rejectUnsupportedPaxOverrides (values) {
  const structural = Object.keys(values).find(key =>
    key === 'GNU.sparse.size' ||
    key === 'GNU.sparse.realsize' ||
    key.startsWith('GNU.sparse.') ||
    key === 'SCHILY.realsize'
  )
  if (structural) {
    throw new AuditError('unsupported-pax-structure', `Rejected structural PAX key ${structural}`)
  }
}

function paxSize (value) {
  if (value === undefined) return null
  if (!/^(?:0|[1-9]\d*)$/.test(value)) {
    throw new AuditError('invalid-pax-size', `Invalid PAX size ${JSON.stringify(value)}`)
  }
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed)) {
    throw new AuditError('tar-number-too-large', 'PAX size exceeds safe integer range')
  }
  return parsed
}

function validateArchivePath (archivePath, directory = false) {
  const candidate = directory && archivePath.endsWith('/')
    ? archivePath.slice(0, -1)
    : archivePath
  if (
    typeof candidate !== 'string' ||
    candidate === '' ||
    candidate.includes('\0') ||
    candidate.includes('\\') ||
    candidate.startsWith('/') ||
    /^[A-Za-z]:/.test(candidate)
  ) {
    throw new AuditError('unsafe-archive-path', `Unsafe archive path: ${JSON.stringify(archivePath)}`)
  }
  const parts = candidate.split('/')
  if (parts.some(part => part === '..' || part === '')) {
    throw new AuditError('unsafe-archive-path', `Unsafe archive path: ${archivePath}`)
  }
  return candidate
}

export function parseTarGz (compressed, limits = {}) {
  const maxExpandedBytes = limits.maxExpandedBytes ?? 512 * 1024 * 1024
  const maxFiles = limits.maxFiles ?? 100000
  let archive
  try {
    archive = gunzipSync(compressed, { maxOutputLength: maxExpandedBytes })
  } catch (error) {
    throw new AuditError('invalid-or-oversized-gzip', error.message)
  }
  const entries = []
  let offset = 0
  let zeroBlocks = 0
  let pendingPax = {}
  let globalPax = {}
  let pendingLongName = null

  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512)
    offset += 512
    if (header.every(byte => byte === 0)) {
      zeroBlocks++
      if (zeroBlocks >= 2) break
      continue
    }
    zeroBlocks = 0
    verifyTarHeader(header)
    const headerSize = parseTarNumber(header.subarray(124, 136))
    const type = String.fromCharCode(header[156] || 0)
    const appliedPax = { ...globalPax, ...pendingPax }
    const size = ['x', 'g', 'L'].includes(type)
      ? headerSize
      : (paxSize(appliedPax.size) ?? headerSize)
    if (size < 0 || offset + size > archive.length) {
      throw new AuditError('truncated-tar-entry', 'Tar entry exceeds archive bounds')
    }
    const rawName = tarText(header.subarray(0, 100))
    const prefix = tarText(header.subarray(345, 500))
    const headerName = prefix ? `${prefix}/${rawName}` : rawName
    const content = archive.subarray(offset, offset + size)
    const paddedSize = Math.ceil(size / 512) * 512
    if (offset + paddedSize > archive.length) {
      throw new AuditError('truncated-tar-entry', 'Tar entry padding exceeds archive bounds')
    }
    offset += paddedSize

    if (type === 'x' || type === 'g') {
      const values = parsePax(content)
      rejectUnsupportedPaxOverrides(values)
      if (type === 'g') globalPax = { ...globalPax, ...values }
      else pendingPax = values
      continue
    }
    if (type === 'L') {
      pendingLongName = content.toString('utf8').replace(/\0.*$/, '').replace(/\n$/, '')
      continue
    }
    if (['1', '2', '3', '4', '6'].includes(type)) {
      throw new AuditError('unsafe-tar-entry-type', `Rejected link or device entry type ${type}`)
    }
    if (!['\0', '0', '5'].includes(type)) {
      throw new AuditError('unsupported-tar-entry-type', `Rejected tar entry type ${JSON.stringify(type)}`)
    }

    const archivePath = validateArchivePath(
      appliedPax.path ?? pendingLongName ?? headerName,
      type === '5'
    )
    pendingPax = {}
    pendingLongName = null
    if (type === '5') continue
    entries.push({ path: archivePath, content: Buffer.from(content), size })
    if (entries.length > maxFiles) throw new AuditError('too-many-archive-files', `Archive exceeds ${maxFiles} files`)
  }
  return { entries, expandedBytes: archive.byteLength }
}

function lineExcerpt (line) {
  return line.replace(/\s+/g, ' ').trim().slice(0, 180)
}

function addSignal (collection, kind, file, lineNumber, line) {
  const signal = collection[kind]
  signal.count++
  if (signal.matches.length < 100) {
    signal.matches.push({
      file,
      line: lineNumber,
      excerpt: lineExcerpt(line)
    })
  } else {
    signal.truncated = true
  }
}

function binaryKind (filePath, content) {
  const extension = extname(filePath).toLowerCase()
  if (extension === '.node') return 'node-addon'
  if (extension === '.wasm' || content.subarray(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d]))) return 'wasm'
  if (extension === '.exe' || extension === '.dll' || content.subarray(0, 2).toString('ascii') === 'MZ') return 'pe'
  if (extension === '.so' || content.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) return 'elf'
  const magic = content.length >= 4 ? content.readUInt32BE(0) : 0
  if (extension === '.dylib' || [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcefaedfe, 0xcffaedfe].includes(magic)) return 'mach-o'
  if (BINARY_EXTENSIONS.has(extension)) return extension.slice(1)
  return null
}

function isLicenseFile (filePath) {
  return /^(?:licen[cs]e|copying|notice|third[-_.]?party)(?:$|[._-])/i.test(basename(filePath))
}

function isSourceFile (filePath, size) {
  if (size > 2 * 1024 * 1024) return false
  if (/\/(?:test|tests|docs?|examples?|fixtures?)\//i.test(filePath)) return false
  if (/\.(?:map|min\.js)$/i.test(filePath)) return false
  return SOURCE_EXTENSIONS.has(extname(filePath).toLowerCase()) || /(?:^|\/)package\.json$/.test(filePath)
}

function referencedInstallFiles (scripts) {
  const references = new Set()
  for (const body of Object.values(scripts)) {
    for (const match of body.matchAll(/(?:^|[\s"'=])((?:\.{0,2}\/)?[A-Za-z0-9_./-]+\.(?:c?m?js|sh|bash|bat|cmd|ps1|py))(?:$|[\s"'])/g)) {
      references.add(match[1].replace(/^\.\//, ''))
      references.add(basename(match[1]))
    }
  }
  return references
}

function externalUrls (text) {
  return [...text.matchAll(/https?:\/\/[^\s"'`<>\\)\]}]+/g)]
    .map(match => match[0].replace(/[.,;:!?]+$/, ''))
}

export function scanPackageArchive (compressed, options = {}) {
  const parsed = parseTarGz(compressed, options)
  const binaries = []
  const licenses = []
  const signals = {
    childProcess: { count: 0, matches: [], truncated: false },
    dynamicCode: { count: 0, matches: [], truncated: false },
    dynamicImport: { count: 0, matches: [], truncated: false },
    networkApi: { count: 0, matches: [], truncated: false },
    prebuiltDownload: { count: 0, matches: [], truncated: false },
    prebuiltLoader: { count: 0, matches: [], truncated: false }
  }
  const urlMap = new Map()
  const networkEvidenceByFile = new Map()
  const packageManifests = []
  let packageManifest = null
  let packageManifestPath = null
  let scannedSourceFiles = 0
  let skippedLargeOrGeneratedSourceFiles = 0

  for (const entry of parsed.entries) {
    const kind = binaryKind(entry.path, entry.content)
    if (kind) {
      binaries.push({
        path: entry.path,
        kind,
        bytes: entry.size,
        sha256: sha256(entry.content)
      })
    }
    if (isLicenseFile(entry.path)) {
      licenses.push({
        path: entry.path,
        bytes: entry.size,
        sha256: sha256(entry.content)
      })
    }
    if (/(?:^|\/)package\.json$/.test(entry.path)) {
      packageManifests.push({
        path: entry.path,
        content: entry.content
      })
    }
    if (!isSourceFile(entry.path, entry.size)) {
      if (SOURCE_EXTENSIONS.has(extname(entry.path).toLowerCase())) skippedLargeOrGeneratedSourceFiles++
      continue
    }
    scannedSourceFiles++
    const text = entry.content.toString('utf8')
    const lines = text.split(/\r?\n/)
    lines.forEach((line, index) => {
      const lineNumber = index + 1
      if (
        /(?:node:)?child_process/.test(line) ||
        /\b(?:exec|execFile|spawn|fork|execSync|spawnSync)\s*\(/.test(line) ||
        /\b(?:child_process|childProcess|proc)\.(?:exec|execFile|spawn|fork|execSync|spawnSync)\s*\(/.test(line)
      ) {
        addSignal(signals, 'childProcess', entry.path, lineNumber, line)
      }
      if (/\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn|compileFunction)/.test(line)) {
        addSignal(signals, 'dynamicCode', entry.path, lineNumber, line)
      }
      if (/\bimport\s*\(/.test(line)) addSignal(signals, 'dynamicImport', entry.path, lineNumber, line)
      if (/\b(?:fetch|axios)\s*\(|\bhttps?\.(?:get|request)\s*\(|\bXMLHttpRequest\b/.test(line)) {
        addSignal(signals, 'networkApi', entry.path, lineNumber, line)
        const evidence = networkEvidenceByFile.get(entry.path) ?? {
          count: 0,
          matches: [],
          truncated: false
        }
        evidence.count++
        if (evidence.matches.length < 5) {
          evidence.matches.push({
            file: entry.path,
            line: lineNumber,
            excerpt: lineExcerpt(line)
          })
        } else {
          evidence.truncated = true
        }
        networkEvidenceByFile.set(entry.path, evidence)
      }
      if (/\b(?:prebuild-install|node-pre-gyp)\b|releases\/download|download.{0,40}(?:binary|prebuild)/i.test(line)) {
        addSignal(signals, 'prebuiltDownload', entry.path, lineNumber, line)
      }
      if (/\b(?:prebuildify|node-gyp-build)\b/i.test(line)) addSignal(signals, 'prebuiltLoader', entry.path, lineNumber, line)
      for (const url of externalUrls(line)) {
        const detail = urlMap.get(url) ?? { url, locations: [], count: 0 }
        detail.count++
        if (detail.locations.length < 5) detail.locations.push({ file: entry.path, line: lineNumber })
        urlMap.set(url, detail)
      }
    })
  }

  const rootCandidates = packageManifests.filter(manifest => manifest.path.split('/').length === 2)
  if (rootCandidates.length === 0) {
    throw new AuditError('missing-package-manifest', 'Npm tarball has no package.json')
  }
  if (rootCandidates.length !== 1) {
    throw new AuditError('ambiguous-package-manifest', `Npm tarball has ${rootCandidates.length} root package.json candidates`)
  }
  const archiveRoot = rootCandidates[0].path.split('/')[0]
  const competingPath = parsed.entries.find(entry => !entry.path.startsWith(`${archiveRoot}/`))
  if (competingPath) {
    throw new AuditError('competing-archive-root', `Archive path is outside ${archiveRoot}/: ${competingPath.path}`)
  }
  packageManifest = parseJson(
    rootCandidates[0].content,
    `${rootCandidates[0].path} in npm tarball`
  )
  packageManifestPath = rootCandidates[0].path
  if (options.expectedName && packageManifest.name !== options.expectedName) {
    throw new AuditError('package-name-mismatch', `Expected ${options.expectedName}, found ${packageManifest.name}`)
  }
  if (options.expectedVersion && packageManifest.version !== options.expectedVersion) {
    throw new AuditError('package-version-mismatch', `Expected ${options.expectedVersion}, found ${packageManifest.version}`)
  }

  const scripts = lifecycleScripts(packageManifest?.scripts)
  const installReferences = referencedInstallFiles(scripts)
  const installTimeNetwork = []
  let installTimeNetworkCount = 0
  let installTimeNetworkTruncated = false
  for (const [file, evidence] of networkEvidenceByFile) {
    const lowerPath = file.toLowerCase()
    if (
      [...installReferences].some(reference => lowerPath.endsWith(reference.toLowerCase())) ||
      /(?:^|\/)(?:pre|post)?install(?:[.-]|\/)/i.test(file) ||
      /\/download(?:[.-]|\/)/i.test(file)
    ) {
      installTimeNetworkCount += evidence.count
      for (const match of evidence.matches) {
        if (installTimeNetwork.length < 100) installTimeNetwork.push(match)
        else installTimeNetworkTruncated = true
      }
      installTimeNetworkTruncated ||= evidence.truncated
    }
  }
  for (const [name, body] of Object.entries(scripts)) {
    if (/https?:\/\/|\b(?:curl|wget|fetch|axios)\b/i.test(body)) {
      installTimeNetworkCount++
      if (installTimeNetwork.length < 100) {
        installTimeNetwork.push({ file: packageManifestPath, line: null, excerpt: `${name}: ${lineExcerpt(body)}` })
      } else {
        installTimeNetworkTruncated = true
      }
    }
  }

  const nativeIndicators = new Set(metadataNativeIndicators(packageManifest))
  if (binaries.some(binary => binary.kind === 'node-addon')) nativeIndicators.add('bundled-node-addon')
  if (binaries.some(binary => ['elf', 'mach-o', 'pe'].includes(binary.kind))) nativeIndicators.add('bundled-native-executable')
  if (binaries.some(binary => binary.kind === 'wasm')) nativeIndicators.add('bundled-wasm')
  if (parsed.entries.some(entry => /(?:^|\/)binding\.gyp$/.test(entry.path))) nativeIndicators.add('binding.gyp')

  return {
    status: 'scanned',
    compressedBytes: compressed.byteLength,
    expandedBytes: parsed.expandedBytes,
    fileCount: parsed.entries.length,
    packageManifestPath,
    lifecycleScripts: scripts,
    nativeIndicators: [...nativeIndicators].sort(),
    binaries: binaries.sort((a, b) => compareText(a.path, b.path)),
    licenseFiles: licenses.sort((a, b) => compareText(a.path, b.path)),
    externalUrls: [...urlMap.values()]
      .sort((a, b) => compareText(a.url, b.url))
      .slice(0, 300),
    externalUrlsTruncated: urlMap.size > 300,
    sourceSignals: signals,
    installTimeNetwork,
    installTimeNetworkCount,
    installTimeNetworkTruncated,
    scannedSourceFiles,
    skippedLargeOrGeneratedSourceFiles
  }
}

async function readVerifiedTarball (metadata, lockIntegrities, cacheDir, offline) {
  const tarballUrl = metadata?.dist?.tarball
  const distIntegrity = metadata?.dist?.integrity
  if (typeof tarballUrl !== 'string') throw new AuditError('missing-dist-tarball', 'Registry metadata has no dist.tarball')
  validateHttpsHost(tarballUrl, ALLOWED_REGISTRY_HOSTS, 'forbidden-tarball-source')
  if (typeof distIntegrity !== 'string') {
    throw new AuditError('missing-dist-integrity', 'Registry metadata has no dist.integrity; tarball was not downloaded')
  }
  const file = cacheFile(cacheDir, 'registry-tarballs', tarballUrl, '.tgz')
  let compressed
  if (existsSync(file)) {
    compressed = readFileSync(file)
    try {
      verifyIntegrity(compressed, distIntegrity)
    } catch (error) {
      unlinkSync(file)
      if (offline) throw error
      compressed = null
    }
  }
  if (!compressed) {
    if (offline) throw new AuditError('offline-cache-miss', `No cached tarball for ${tarballUrl}`)
    compressed = await fetchBounded(tarballUrl, ALLOWED_REGISTRY_HOSTS, {
      maxBytes: 128 * 1024 * 1024,
      timeoutMs: 120000
    })
    verifyIntegrity(compressed, distIntegrity)
    writeAtomic(file, compressed)
  }
  verifyIntegrity(compressed, distIntegrity)
  const lockVerification = []
  for (const integrity of [...lockIntegrities].filter(Boolean).sort()) {
    try {
      verifyIntegrity(compressed, integrity)
      lockVerification.push({ integrity, verified: true })
    } catch (error) {
      lockVerification.push({ integrity, verified: false, error: errorCode(error) })
    }
  }
  return {
    compressed,
    tarballUrl,
    distIntegrity,
    integrityAlgorithm: verifyIntegrity(compressed, distIntegrity).algorithm,
    lockVerification
  }
}

function reviewPriority (coordinate, metadataRecord) {
  const reasons = new Set()
  if (coordinate.directRuntime) reasons.add('direct-runtime')
  if (coordinate.lockHasInstallScript) reasons.add('lock-has-install-script')
  if (HIGH_PRIVILEGE_NAME.test(coordinate.name)) reasons.add('high-privilege-name')
  if (Object.keys(lifecycleScripts(metadataRecord?.scripts)).length) reasons.add('registry-lifecycle-script')
  if (metadataNativeIndicators(metadataRecord).length) reasons.add('registry-native-indicator')
  if (MANDATED_REVIEW_PACKAGES.has(coordinate.name)) reasons.add('mandated-package-family')
  return [...reasons].sort()
}

function addArchivePriority (coordinate) {
  if (
    coordinate.archive?.status === 'scanned' &&
    (
      coordinate.archive.nativeIndicators?.length > 0 ||
      coordinate.archive.binaries?.length > 0
    )
  ) {
    coordinate.priorityReasons = [...new Set([
      ...coordinate.priorityReasons,
      'archive-native-or-binary'
    ])].sort()
  }
}

function metadataSummary (metadataResult) {
  if (metadataResult.status !== 'available') {
    return {
      status: metadataResult.status,
      error: metadataResult.error ?? null,
      registryUrl: metadataResult.registryUrl,
      metadataSha256: null,
      license: null,
      repository: null,
      deprecated: null,
      lifecycleScripts: {},
      bin: null,
      cpu: null,
      os: null,
      nativeIndicators: [],
      dist: null
    }
  }
  const metadata = metadataResult.value
  return {
    status: 'available',
    error: null,
    registryUrl: metadataResult.registryUrl,
    metadataSha256: metadataResult.metadataSha256,
    license: normalizeLicenseDeclaration(metadata),
    repository: normalizeRepository(metadata.repository),
    deprecated: typeof metadata.deprecated === 'string' ? metadata.deprecated : null,
    lifecycleScripts: lifecycleScripts(metadata.scripts),
    bin: normalizeBin(metadata.bin, metadata.name),
    cpu: normalizeStringArray(metadata.cpu),
    os: normalizeStringArray(metadata.os),
    nativeIndicators: metadataNativeIndicators(metadata),
    dist: metadata.dist && typeof metadata.dist === 'object'
      ? {
          integrity: typeof metadata.dist.integrity === 'string' ? metadata.dist.integrity : null,
          tarball: typeof metadata.dist.tarball === 'string' ? metadata.dist.tarball : null,
          shasum: typeof metadata.dist.shasum === 'string' ? metadata.dist.shasum : null,
          fileCount: Number.isSafeInteger(metadata.dist.fileCount) ? metadata.dist.fileCount : null,
          unpackedSize: Number.isSafeInteger(metadata.dist.unpackedSize) ? metadata.dist.unpackedSize : null
        }
      : null
  }
}

function buildCoordinateMap (packageMap, reachability) {
  const coordinates = new Map()
  for (const [packagePath, record] of packageMap) {
    if (packagePath === '') continue
    const coordinate = normalizedCoordinate(packagePath, record)
    if (!coordinate) continue
    const current = coordinates.get(coordinate.key) ?? {
      ...coordinate,
      packagePaths: [],
      lockIntegrities: new Set(),
      lockHasInstallScript: false,
      directRuntime: false
    }
    current.packagePaths.push(packagePath)
    if (typeof record.integrity === 'string') current.lockIntegrities.add(record.integrity)
    current.lockHasInstallScript ||= record.hasInstallScript === true
    current.directRuntime ||= reachability.direct.get(packagePath)?.scopes.includes('runtime') === true
    coordinates.set(coordinate.key, current)
  }
  for (const coordinate of coordinates.values()) coordinate.packagePaths.sort()
  return coordinates
}

async function enrichCoordinates (coordinates, options) {
  const ordered = [...coordinates.values()].sort((a, b) => compareText(a.key, b.key))
  const metadataResults = await rateLimitedMap(ordered, async coordinate => {
    try {
      return await readRegistryMetadata(coordinate, options.cacheDir, options.offline)
    } catch (error) {
      return {
        status: 'unknown',
        error: errorCode(error),
        registryUrl: registryVersionUrl(coordinate.name, coordinate.version)
      }
    }
  }, {
    concurrency: options.metadataConcurrency,
    delayMs: options.registryDelayMs
  })

  ordered.forEach((coordinate, index) => {
    coordinate.metadataResult = metadataResults[index]
    coordinate.metadata = metadataSummary(metadataResults[index])
    coordinate.priorityReasons = reviewPriority(
      coordinate,
      metadataResults[index].status === 'available' ? metadataResults[index].value : null
    )
  })

  const selected = ordered.filter(() => options.scanTarballs === 'all')
  const archiveResults = await rateLimitedMap(selected, async coordinate => {
    if (coordinate.metadataResult.status !== 'available') {
      return { status: 'blocked', error: 'registry-metadata-unavailable' }
    }
    try {
      const verified = await readVerifiedTarball(
        coordinate.metadataResult.value,
        coordinate.lockIntegrities,
        options.cacheDir,
        options.offline
      )
      const scan = scanPackageArchive(verified.compressed, {
        expectedName: coordinate.name,
        expectedVersion: coordinate.version
      })
      return {
        ...scan,
        tarballUrl: verified.tarballUrl,
        distIntegrity: verified.distIntegrity,
        integrityAlgorithm: verified.integrityAlgorithm,
        integrityVerified: true,
        lockIntegrityVerification: verified.lockVerification,
        sha256: sha256(verified.compressed)
      }
    } catch (error) {
      return { status: 'blocked', error: errorCode(error) }
    }
  }, {
    concurrency: options.tarballConcurrency,
    delayMs: options.registryDelayMs
  })
  selected.forEach((coordinate, index) => {
    coordinate.archive = archiveResults[index]
    addArchivePriority(coordinate)
  })
  for (const coordinate of ordered) {
    coordinate.archive ??= {
      status: 'not-selected',
      error: null
    }
  }
  return ordered
}

function sourceDetails (record, metadata, packageName) {
  const lockLicense = normalizeLicenseDeclaration(record)
  return {
    license: lockLicense ?? metadata.license,
    licenseSource: lockLicense ? 'lockfile' : (metadata.license ? 'registry.npmjs.org' : null),
    sourceRepository: metadata.repository,
    deprecation: metadata.deprecated,
    bin: normalizeBin(record.bin, packageName) ?? metadata.bin,
    cpu: normalizeStringArray(record.cpu) ?? metadata.cpu,
    os: normalizeStringArray(record.os) ?? metadata.os
  }
}

function riskFlags (context) {
  const flags = new Set()
  const source = resolvedSource(context.record.resolved)
  if (context.packagePath !== '' && !context.record.integrity) flags.add('missing-lock-integrity')
  if (source.host && source.host !== 'registry.npmjs.org') flags.add('non-official-resolved-host')
  if (source.scheme && !['http', 'https'].includes(source.scheme)) flags.add('git-file-or-non-registry-source')
  for (const spec of context.direct?.specs ?? []) {
    for (const risk of directSpecRisk(spec)) flags.add(risk)
  }
  if (context.hasLifecycleScript) flags.add('has-lifecycle-script')
  if (context.hasInstallScript) flags.add('has-install-script')
  if (context.license && FORBIDDEN_LICENSE.test(context.license)) flags.add('forbidden-license')
  if (context.metadata.status !== 'available' && context.packagePath !== '') flags.add('registry-metadata-unavailable')
  if (context.metadata.deprecated) flags.add('deprecated')
  if (context.highPrivilege) flags.add('high-privilege-surface')
  if (context.nativeIndicators.length) flags.add('native-code')
  if (context.archive?.status === 'blocked') flags.add('archive-review-blocked')
  if (context.archive?.binaries?.some(binary => binary.kind === 'node-addon')) flags.add('bundled-node-addon')
  if (context.archive?.binaries?.some(binary => ['elf', 'mach-o', 'pe'].includes(binary.kind))) flags.add('bundled-native-executable')
  if (context.archive?.binaries?.some(binary => binary.kind === 'wasm') || context.archive?.nativeIndicators?.includes('bundled-wasm')) {
    flags.add('bundled-wasm')
  }
  if (context.archive?.installTimeNetworkCount) flags.add('install-time-network-indicator')
  if (context.archive?.sourceSignals?.childProcess?.count) flags.add('child-process-indicator')
  if (context.archive?.sourceSignals?.dynamicCode?.count) flags.add('dynamic-code-indicator')
  if (context.archive?.sourceSignals?.dynamicImport?.count) flags.add('dynamic-import-indicator')
  if (context.archive?.sourceSignals?.prebuiltDownload?.count) flags.add('prebuilt-download-indicator')
  if (context.archive?.sourceSignals?.prebuiltLoader?.count) flags.add('prebuilt-loader-indicator')
  if (context.archive?.lockIntegrityVerification?.some(result => !result.verified)) flags.add('lock-registry-integrity-mismatch')
  return [...flags].sort()
}

function packageEntry (packagePath, record, reachability, coordinateLookup, packageJson) {
  const coordinate = packagePath === ''
    ? { name: packageJson.name, version: packageJson.version, key: 'root' }
    : normalizedCoordinate(packagePath, record)
  const enriched = coordinate ? coordinateLookup.get(coordinate.key) : null
  const metadata = enriched?.metadata ?? metadataSummary({
    status: packagePath === '' ? 'root-source' : 'unknown',
    error: null,
    registryUrl: null
  })
  const rootScripts = packagePath === '' ? lifecycleScripts(packageJson.scripts) : {}
  const scripts = Object.keys(rootScripts).length ? rootScripts : metadata.lifecycleScripts
  const direct = reachability.direct.get(packagePath) ?? null
  const details = sourceDetails(record, metadata, coordinate?.name)
  const nativeIndicators = new Set([
    ...metadata.nativeIndicators,
    ...(enriched?.archive?.nativeIndicators ?? [])
  ])
  const hasLifecycleScript = Object.keys(scripts).length > 0
  const hasInstallScript = record.hasInstallScript === true ||
    Object.keys(scripts).some(name => INSTALL_SCRIPT_NAMES.has(name))
  const highPrivilege = coordinate?.name ? HIGH_PRIVILEGE_NAME.test(coordinate.name) : false
  const context = {
    packagePath,
    record,
    direct,
    metadata,
    archive: enriched?.archive,
    license: details.license,
    nativeIndicators: [...nativeIndicators],
    hasLifecycleScript,
    hasInstallScript,
    highPrivilege
  }
  const resolved = resolvedSource(record.resolved)
  return {
    entryId: `packages:${packagePath || '<root>'}`,
    entryKind: 'package-path',
    packageId: coordinate ? `${coordinate.name}@${coordinate.version ?? 'unknown'}` : null,
    name: coordinate?.name ?? null,
    version: coordinate?.version ?? null,
    path: packagePath,
    direct: direct !== null,
    directScopes: direct ? [...new Set(direct.scopes)].sort() : [],
    declaredSpecs: direct ? [...new Set(direct.specs)].sort() : [],
    runtimeReachable: packagePath === '' || reachability.runtime.reached.has(packagePath),
    devReachable: packagePath === '' || reachability.development.reached.has(packagePath),
    resolved: typeof record.resolved === 'string' ? record.resolved : null,
    resolvedHost: resolved.host,
    resolvedScheme: resolved.scheme,
    integrity: typeof record.integrity === 'string' ? record.integrity : null,
    license: details.license,
    licenseSource: details.licenseSource,
    hasInstallScript,
    lifecycleScripts: scripts,
    bin: details.bin,
    cpu: details.cpu,
    os: details.os,
    optional: typeof record.optional === 'boolean' ? record.optional : null,
    dev: typeof record.dev === 'boolean' ? record.dev : null,
    nativeIndicators: [...nativeIndicators].sort(),
    sourceRepository: details.sourceRepository,
    deprecation: details.deprecation,
    registryMetadataStatus: metadata.status,
    sourceReviewRef: enriched ? `${enriched.name}@${enriched.version}` : (packagePath === '' ? 'root-package-json' : null),
    riskFlags: riskFlags(context)
  }
}

function legacyEntry (name, record, packageEntryByPath) {
  const expectedPath = `node_modules/${name}`
  const matched = packageEntryByPath.get(expectedPath)
  const resolved = resolvedSource(record.resolved)
  if (matched) {
    return {
      ...matched,
      entryId: `dependencies:${name}`,
      entryKind: 'legacy-root-dependency',
      path: expectedPath
    }
  }
  const version = typeof record.version === 'string' ? record.version : null
  const license = typeof record.license === 'string' ? record.license : null
  return {
    entryId: `dependencies:${name}`,
    entryKind: 'legacy-root-dependency',
    packageId: version ? `${name}@${version}` : name,
    name,
    version,
    path: null,
    direct: false,
    directScopes: [],
    declaredSpecs: [],
    runtimeReachable: null,
    devReachable: null,
    resolved: typeof record.resolved === 'string' ? record.resolved : null,
    resolvedHost: resolved.host,
    resolvedScheme: resolved.scheme,
    integrity: typeof record.integrity === 'string' ? record.integrity : null,
    license,
    licenseSource: license ? 'lockfile' : null,
    hasInstallScript: record.hasInstallScript === true,
    lifecycleScripts: {},
    bin: null,
    cpu: null,
    os: null,
    optional: typeof record.optional === 'boolean' ? record.optional : null,
    dev: typeof record.dev === 'boolean' ? record.dev : null,
    nativeIndicators: [],
    sourceRepository: null,
    deprecation: null,
    registryMetadataStatus: 'unmatched-legacy-entry',
    sourceReviewRef: null,
    riskFlags: [
      ...(!record.integrity ? ['missing-lock-integrity'] : []),
      ...(resolved.host && resolved.host !== 'registry.npmjs.org' ? ['non-official-resolved-host'] : [])
    ].sort()
  }
}

function reviewRecord (coordinate) {
  const archive = coordinate.archive
  const focused = coordinate.priorityReasons.length > 0
  const tier = archive.status === 'scanned'
    ? (focused ? 'focused-static-signals' : 'automated-archive-signals')
    : 'metadata-only-or-blocked'
  return {
    packageId: `${coordinate.name}@${coordinate.version}`,
    name: coordinate.name,
    version: coordinate.version,
    packagePaths: coordinate.packagePaths,
    tier,
    focusReasons: coordinate.priorityReasons,
    registryMetadata: coordinate.metadata,
    archive
  }
}

function removalAnalysis (packageJson, packageMap) {
  const allRoots = new Set([
    ...Object.keys(packageJson.dependencies ?? {}),
    ...Object.keys(packageJson.optionalDependencies ?? {}),
    ...Object.keys(packageJson.devDependencies ?? {})
  ])
  const baseline = traverseFromRoots(packageMap, allRoots, false).reached
  return FEATURE_REPLACEMENTS.map(feature => {
    const removedRoots = feature.directRoots.filter(name => allRoots.has(name)).sort()
    const retainedRoots = new Set([...allRoots].filter(name => !removedRoots.includes(name)))
    const retained = traverseFromRoots(packageMap, retainedRoots, false).reached
    const disappearedPaths = [...baseline].filter(packagePath => !retained.has(packagePath)).sort()
    const disappearedPackages = [...new Set(disappearedPaths.map(packagePath => {
      const record = packageMap.get(packagePath)
      const coordinate = normalizedCoordinate(packagePath, record)
      return coordinate ? `${coordinate.name}@${coordinate.version}` : packagePath
    }))].sort()
    return {
      id: feature.id,
      assumption: feature.assumption,
      preservedProductCapabilities: feature.preservedProductCapabilities,
      removedDirectRoots: removedRoots,
      retainedSharedRoots: feature.retainedSharedRoots,
      disappearedPackagePathCount: disappearedPaths.length,
      disappearedPackageCount: disappearedPackages.length,
      disappearedPackagePaths: disappearedPaths,
      disappearedPackages
    }
  })
}

function countBy (values, selector) {
  const result = {}
  for (const value of values) {
    const key = selector(value) ?? 'unknown'
    result[key] = (result[key] ?? 0) + 1
  }
  return Object.fromEntries(Object.entries(result).sort(([a], [b]) => compareText(a, b)))
}

function validateInputs (packageJson, lockfile, enforceTarget) {
  if (!lockfile || typeof lockfile !== 'object' || Array.isArray(lockfile)) {
    throw new AuditError('malformed-lockfile', 'Lockfile root must be an object')
  }
  if (!SUPPORTED_LOCKFILE_VERSIONS.has(lockfile.lockfileVersion)) {
    throw new AuditError('unsupported-lockfile-version', `Expected lockfile version 2 or 3, got ${lockfile.lockfileVersion}`)
  }
  if (!lockfile.packages || typeof lockfile.packages !== 'object' || Array.isArray(lockfile.packages)) {
    throw new AuditError('malformed-lockfile', 'Lockfile has no packages object')
  }
  if (!lockfile.packages[''] || typeof lockfile.packages[''] !== 'object') {
    throw new AuditError('malformed-lockfile', 'Lockfile has no root package entry')
  }
  if (!packageJson || typeof packageJson !== 'object' || Array.isArray(packageJson)) {
    throw new AuditError('malformed-package-json', 'package.json root must be an object')
  }
  if (enforceTarget && packageJson.version !== TARGET.packageVersion) {
    throw new AuditError('unexpected-package-version', `Expected ${TARGET.packageVersion}, got ${packageJson.version}`)
  }
}

export async function analyzeDocuments (packageJson, lockfile, options = {}) {
  const settings = {
    cacheDir: options.cacheDir ?? DEFAULT_CACHE,
    offline: options.offline ?? false,
    scanTarballs: options.scanTarballs ?? 'all',
    metadataConcurrency: options.metadataConcurrency ?? 4,
    tarballConcurrency: options.tarballConcurrency ?? 2,
    registryDelayMs: options.registryDelayMs ?? 75,
    enforceTarget: options.enforceTarget ?? false,
    fixtureMetadata: options.fixtureMetadata ?? null,
    fixtureArchives: options.fixtureArchives ?? null
  }
  if (!['all', 'none'].includes(settings.scanTarballs)) {
    throw new AuditError('invalid-scan-mode', `Invalid tarball scan mode: ${settings.scanTarballs}`)
  }
  validateInputs(packageJson, lockfile, settings.enforceTarget)
  const packageMap = new Map(Object.entries(lockfile.packages))
  const reachability = buildReachability(packageJson, packageMap)
  const coordinateMap = buildCoordinateMap(packageMap, reachability)
  let coordinates

  if (settings.fixtureMetadata) {
    coordinates = [...coordinateMap.values()].sort((a, b) => compareText(a.key, b.key))
    for (const coordinate of coordinates) {
      const fixture = settings.fixtureMetadata[`${coordinate.name}@${coordinate.version}`]
      coordinate.metadataResult = fixture
        ? {
            status: 'available',
            registryUrl: registryVersionUrl(coordinate.name, coordinate.version),
            metadataSha256: sha256(Buffer.from(stableStringify(fixture))),
            value: fixture
          }
        : {
            status: 'unknown',
            error: 'fixture-metadata-miss',
            registryUrl: registryVersionUrl(coordinate.name, coordinate.version)
          }
      coordinate.metadata = metadataSummary(coordinate.metadataResult)
      coordinate.priorityReasons = reviewPriority(coordinate, fixture)
      const archiveFixture = settings.fixtureArchives?.[`${coordinate.name}@${coordinate.version}`]
      if (archiveFixture) {
        const integrity = fixture?.dist?.integrity
        verifyIntegrity(archiveFixture, integrity)
        coordinate.archive = {
          ...scanPackageArchive(archiveFixture, {
            expectedName: coordinate.name,
            expectedVersion: coordinate.version
          }),
          tarballUrl: fixture.dist.tarball,
          distIntegrity: integrity,
          integrityAlgorithm: verifyIntegrity(archiveFixture, integrity).algorithm,
          integrityVerified: true,
          lockIntegrityVerification: [...coordinate.lockIntegrities].map(lockIntegrity => {
            try {
              verifyIntegrity(archiveFixture, lockIntegrity)
              return { integrity: lockIntegrity, verified: true }
            } catch (error) {
              return { integrity: lockIntegrity, verified: false, error: errorCode(error) }
            }
          }),
          sha256: sha256(archiveFixture)
        }
        addArchivePriority(coordinate)
      } else {
        coordinate.archive = { status: 'not-selected', error: null }
      }
    }
  } else {
    coordinates = await enrichCoordinates(coordinateMap, settings)
  }

  const coordinateLookup = new Map(coordinates.map(coordinate => [coordinate.key, coordinate]))
  const pathEntries = [...packageMap.entries()]
    .sort(([a], [b]) => compareText(a, b))
    .map(([packagePath, record]) => packageEntry(
      packagePath,
      record,
      reachability,
      coordinateLookup,
      packageJson
    ))
  const packageEntryByPath = new Map(pathEntries.map(entry => [entry.path, entry]))
  const legacyEntries = Object.entries(lockfile.dependencies ?? {})
    .sort(([a], [b]) => compareText(a, b))
    .map(([name, record]) => legacyEntry(name, record, packageEntryByPath))
  const entries = [...pathEntries, ...legacyEntries]
  const reviews = coordinates.map(reviewRecord)
  const sourceLockfileVersionMismatch = lockfile.lockfileVersion !== 3
  const counts = {
    manifestEntries: entries.length,
    packagePathEntries: pathEntries.length,
    nonRootPackagePathEntries: pathEntries.filter(entry => entry.path !== '').length,
    legacyRootDependencyEntries: legacyEntries.length,
    uniqueCoordinates: coordinates.length,
    directRuntimePackagePaths: pathEntries.filter(entry => entry.directScopes.includes('runtime')).length,
    directDevPackagePaths: pathEntries.filter(entry => entry.directScopes.includes('dev')).length,
    runtimeReachablePackagePaths: pathEntries.filter(entry => entry.path !== '' && entry.runtimeReachable).length,
    devReachablePackagePaths: pathEntries.filter(entry => entry.path !== '' && entry.devReachable).length,
    hasInstallScriptEntries: pathEntries.filter(entry => entry.hasInstallScript).length,
    lifecycleScriptEntries: pathEntries.filter(entry => Object.keys(entry.lifecycleScripts).length > 0).length,
    nonOfficialResolvedHostEntries: pathEntries.filter(entry => entry.riskFlags.includes('non-official-resolved-host')).length,
    metadataAvailableCoordinates: reviews.filter(review => review.registryMetadata.status === 'available').length,
    scannedArchives: reviews.filter(review => review.archive.status === 'scanned').length,
    blockedArchives: reviews.filter(review => review.archive.status === 'blocked').length,
    bundledNodeAddons: reviews.reduce((sum, review) => sum + (review.archive.binaries?.filter(binary => binary.kind === 'node-addon').length ?? 0), 0),
    bundledNativeExecutables: reviews.reduce((sum, review) => sum + (review.archive.binaries?.filter(binary => ['elf', 'mach-o', 'pe'].includes(binary.kind)).length ?? 0), 0),
    bundledWasmFiles: reviews.reduce((sum, review) => sum + (review.archive.binaries?.filter(binary => binary.kind === 'wasm').length ?? 0), 0)
  }

  if (settings.enforceTarget && entries.length !== TARGET.expectedSerializedEntries) {
    throw new AuditError(
      'unexpected-entry-count',
      `Expected ${TARGET.expectedSerializedEntries} serialized records, got ${entries.length}`
    )
  }

  return {
    schemaVersion: 1,
    target: {
      repository: TARGET.repository,
      commit: TARGET.commit,
      expectedPackageVersion: TARGET.packageVersion,
      observedPackageVersion: packageJson.version ?? null,
      observedLockfileVersion: lockfile.lockfileVersion,
      analyzerSupportedLockfileVersions: [...SUPPORTED_LOCKFILE_VERSIONS].sort(),
      sourceLockfileVersionMismatch,
      serializedEntryDefinition: 'All lockfile.packages records plus top-level lockfile.dependencies records; the latter are retained because the official v2 lockfile serializes both representations.'
    },
    sourcePolicy: {
      githubHosts: [...ALLOWED_GITHUB_HOSTS],
      registryHosts: [...ALLOWED_REGISTRY_HOSTS],
      tarballsRequireRegistryDistIntegrity: true,
      archivesExecuted: false,
      archivesExtractedToFilesystem: false,
      rejectedArchiveEntryTypes: ['hardlink', 'symlink', 'character-device', 'block-device', 'fifo'],
      forbiddenLicensePattern: FORBIDDEN_LICENSE.source
    },
    counts,
    resolvedHosts: countBy(pathEntries.filter(entry => entry.resolved), entry => entry.resolvedHost ?? entry.resolvedScheme),
    riskFlagCounts: countBy(
      pathEntries.flatMap(entry => entry.riskFlags.map(flag => ({ flag }))),
      item => item.flag
    ),
    coverage: {
      tiers: countBy(reviews, review => review.tier),
      blocked: reviews
        .filter(review => review.archive.status === 'blocked' || review.registryMetadata.status !== 'available')
        .map(review => ({
          packageId: review.packageId,
          metadataStatus: review.registryMetadata.status,
          metadataError: review.registryMetadata.error,
          archiveStatus: review.archive.status,
          archiveError: review.archive.error
        }))
    },
    graph: {
      unresolvedRuntimeEdges: reachability.runtime.unresolved,
      unresolvedDevelopmentEdges: reachability.development.unresolved
    },
    removalAnalysis: removalAnalysis(packageJson, packageMap),
    entries,
    sourceReviews: reviews
  }
}

function parseArguments (argv) {
  const options = {
    output: DEFAULT_OUTPUT,
    cacheDir: DEFAULT_CACHE,
    offline: false,
    scanTarballs: 'all',
    metadataConcurrency: 4,
    tarballConcurrency: 2,
    registryDelayMs: 75
  }
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]
    if (argument === '--offline') {
      options.offline = true
      continue
    }
    if (argument === '--help') {
      options.help = true
      continue
    }
    const value = argv[++index]
    if (value === undefined) throw new AuditError('missing-argument-value', `Missing value for ${argument}`)
    if (argument === '--output') options.output = resolve(value)
    else if (argument === '--cache-dir') options.cacheDir = resolve(value)
    else if (argument === '--scan-tarballs') options.scanTarballs = value
    else if (argument === '--metadata-concurrency') options.metadataConcurrency = Number.parseInt(value, 10)
    else if (argument === '--tarball-concurrency') options.tarballConcurrency = Number.parseInt(value, 10)
    else if (argument === '--registry-delay-ms') options.registryDelayMs = Number.parseInt(value, 10)
    else throw new AuditError('unknown-argument', `Unknown argument: ${argument}`)
  }
  for (const name of ['metadataConcurrency', 'tarballConcurrency']) {
    if (!Number.isSafeInteger(options[name]) || options[name] < 1 || options[name] > 8) {
      throw new AuditError('invalid-concurrency', `${name} must be an integer from 1 through 8`)
    }
  }
  if (
    !Number.isSafeInteger(options.registryDelayMs) ||
    options.registryDelayMs < 0 ||
    options.registryDelayMs > 60000
  ) {
    throw new AuditError('invalid-rate-delay', 'registryDelayMs must be an integer from 0 through 60000')
  }
  return options
}

function usage () {
  return [
    'Usage: node scripts/security/npm-audit-electerm-web.mjs [options]',
    '',
    'Options:',
    '  --output <path>',
    '  --cache-dir <path>',
    '  --scan-tarballs <none|all>',
    '  --metadata-concurrency <1-8>',
    '  --tarball-concurrency <1-8>',
    '  --registry-delay-ms <milliseconds>',
    '  --offline',
    '  --help'
  ].join('\n')
}

async function main () {
  const options = parseArguments(process.argv.slice(2))
  if (options.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }
  mkdirSync(options.cacheDir, { recursive: true })
  const [packageJsonInput, packageLockInput] = await Promise.all([
    readOfficialInput(
      TARGET.packageJsonUrl,
      TARGET.packageJsonUrl,
      TARGET.packageJsonSha256,
      options.cacheDir,
      options.offline
    ),
    readOfficialInput(
      TARGET.packageLockUrl,
      TARGET.packageLockUrl,
      TARGET.packageLockSha256,
      options.cacheDir,
      options.offline
    )
  ])
  const packageJson = parseJson(packageJsonInput.data, 'package.json')
  const packageLock = parseJson(packageLockInput.data, 'package-lock.json')
  const manifest = await analyzeDocuments(packageJson, packageLock, {
    ...options,
    enforceTarget: true
  })
  manifest.inputs = {
    packageJson: {
      source: packageJsonInput.source,
      sha256: sha256(packageJsonInput.data),
      bytes: packageJsonInput.data.byteLength
    },
    packageLock: {
      source: packageLockInput.source,
      sha256: sha256(packageLockInput.data),
      bytes: packageLockInput.data.byteLength
    }
  }
  writeAtomic(options.output, stableStringify(manifest))
  process.stdout.write(`${JSON.stringify({
    output: options.output,
    manifestEntries: manifest.counts.manifestEntries,
    packagePathEntries: manifest.counts.packagePathEntries,
    legacyRootDependencyEntries: manifest.counts.legacyRootDependencyEntries,
    uniqueCoordinates: manifest.counts.uniqueCoordinates,
    scannedArchives: manifest.counts.scannedArchives,
    blockedArchives: manifest.counts.blockedArchives
  })}\n`)
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => {
    process.stderr.write(`npm audit failed [${errorCode(error)}]: ${error.message}\n`)
    process.exitCode = 1
  })
}
