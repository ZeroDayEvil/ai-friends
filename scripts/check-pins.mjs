#!/usr/bin/env node
/**
 * Fail-closed dependency and imported-source policy check.
 *
 * This script only reads text, JSON, and file hashes. It never installs,
 * imports, builds, or otherwise executes code from apps/electerm-web.
 *
 * Run: node scripts/check-pins.mjs
 */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, lstatSync, readdirSync, readFileSync } from 'node:fs'
import { basename, extname, join, relative, sep } from 'node:path'

const root = process.cwd()
const problems = []
const SOURCE_ROOT = 'apps/electerm-web'
const IMPORTED_REPOSITORY = 'https://github.com/electerm/electerm-web'
const ALLOWED_REGISTRIES = new Set(['registry.npmjs.org'])
const SCANNED_EXTENSIONS = new Set([
  '.bash', '.bat', '.cjs', '.cmd', '.js', '.jsx', '.mjs', '.ps1', '.psm1',
  '.sh', '.ts', '.tsx', '.yaml', '.yml', '.zsh'
])
const LIFECYCLE_SCRIPTS = new Set([
  'preinstall', 'install', 'postinstall',
  'prepublish', 'preprepare', 'prepare', 'postprepare', 'prepublishOnly',
  'prepack', 'postpack', 'preversion', 'version', 'postversion'
])
const DEPENDENCY_SECTIONS = new Set([
  'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'
])
const UNSUPPORTED_LOCKFILES = new Set(['bun.lock', 'bun.lockb', 'pnpm-lock.yaml', 'yarn.lock'])
const SHA1_RE = /^[0-9a-f]{40}$/
const SHA256_RE = /^[0-9a-f]{64}$/
const EXACT_VERSION_RE = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/

function toPosixRelative (file) {
  return relative(root, file).split(sep).join('/')
}

function normalizeRelativePath (value) {
  if (typeof value !== 'string' || !value || value.startsWith('/') || value.includes('\\')) {
    return null
  }
  const parts = value.split('/')
  if (parts.some(part => !part || part === '.' || part === '..')) {
    return null
  }
  return parts.join('/')
}

function fullPath (relativePath) {
  const normalized = normalizeRelativePath(relativePath)
  if (!normalized) {
    throw new Error(`unsafe relative path: ${String(relativePath)}`)
  }
  return join(root, ...normalized.split('/'))
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function gitBlobSha1 (value) {
  return createHash('sha1')
    .update(`blob ${value.length}\0`)
    .update(value)
    .digest('hex')
}

function fileDigest (file) {
  const bytes = readFileSync(file)
  return {
    bytes,
    sha256: sha256(bytes),
    gitBlobSha1: gitBlobSha1(bytes)
  }
}

function parseJsonBytes (bytes, description) {
  try {
    const text = bytes.toString('utf8').replace(/^\uFEFF/, '')
    return JSON.parse(text)
  } catch (error) {
    problems.push(`${description}: invalid JSON: ${error.message}`)
    return null
  }
}

function readJson (relativePath, description, required = true) {
  const file = fullPath(relativePath)
  if (!existsSync(file)) {
    if (required) problems.push(`${description}: missing ${relativePath}`)
    return null
  }
  try {
    return parseJsonBytes(readFileSync(file), description)
  } catch (error) {
    problems.push(`${description}: cannot read ${relativePath}: ${error.message}`)
    return null
  }
}

function isUnsafeLink (stats) {
  return stats.isSymbolicLink()
}

function isPlainObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function requireArray (object, field, description) {
  if (!Array.isArray(object[field])) {
    problems.push(`${description}: "${field}" must be an array`)
    return []
  }
  return object[field]
}

function checkText (value, description) {
  if (typeof value !== 'string' || !value.trim()) {
    problems.push(`${description}: must be a non-empty string`)
    return false
  }
  return true
}

// --- 1. External dependency register ---------------------------------------

const PIN_RE = /^(commit:[0-9a-f]{40}|commit:pending|version:\d+\.\d+\.\d+|digest:sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64}|none)$/
const KINDS = new Set(['git', 'npm', 'docker', 'binary', 'script', 'endpoint'])
const VERDICTS = new Set(['keep', 'replace', 'pin', 'remove'])

function validateExternals () {
  const registry = readJson('security/externals.json', 'externals.json')
  if (!registry || !isPlainObject(registry)) return null
  if (registry.version !== 1) problems.push('externals.json: expected "version": 1')
  if (!Array.isArray(registry.items)) {
    problems.push('externals.json: missing items array')
    return null
  }

  let electermCommit = null
  for (const item of registry.items) {
    if (!isPlainObject(item)) {
      problems.push('externals.json: every item must be an object')
      continue
    }
    const id = typeof item.id === 'string' ? item.id : '<missing id>'
    for (const field of ['id', 'kind', 'official_source', 'pin', 'license', 'verdict']) {
      if (item[field] === undefined) problems.push(`externals.json [${id}]: missing ${field}`)
    }
    if (item.kind && !KINDS.has(item.kind)) problems.push(`externals.json [${id}]: invalid kind "${item.kind}"`)
    if (item.verdict && !VERDICTS.has(item.verdict)) problems.push(`externals.json [${id}]: invalid verdict "${item.verdict}"`)
    if (item.pin && !PIN_RE.test(item.pin)) problems.push(`externals.json [${id}]: invalid pin "${item.pin}"`)
    if (item.verdict === 'keep' && item.pin === 'none' && item.kind !== 'git') {
      problems.push(`externals.json [${id}]: keep verdict without a pin`)
    }

    if (item.id === 'electerm-web') {
      const match = typeof item.pin === 'string' && /^commit:([0-9a-f]{40})$/.exec(item.pin)
      if (item.kind !== 'git') problems.push('externals.json [electerm-web]: kind must be git')
      if (item.official_source !== IMPORTED_REPOSITORY) {
        problems.push('externals.json [electerm-web]: official_source does not match the imported upstream')
      }
      if (!match) {
        problems.push('externals.json [electerm-web]: must use a full commit pin')
      } else {
        electermCommit = match[1]
      }
    }
  }
  if (!electermCommit) problems.push('externals.json: electerm-web full commit pin is required')
  return electermCommit
}

// --- 2. Explicit policy exceptions -----------------------------------------

const ignoredTreePaths = new Set()
const lifecycleApprovals = new Map()
const floatingManifestApprovals = new Map()
const registryApprovals = new Map()
const usedLifecycleApprovals = new Set()
const usedFloatingApprovals = new Set()
const usedRegistryApprovals = new Set()

function requireImportedPath (value, description) {
  const normalized = normalizeRelativePath(value)
  if (!normalized || !normalized.startsWith(`${SOURCE_ROOT}/`)) {
    problems.push(`${description}: path must be below ${SOURCE_ROOT}/`)
    return null
  }
  return normalized
}

function validateExceptionManifest () {
  const manifest = readJson('security/policy-exceptions.json', 'policy-exceptions.json')
  if (!manifest || !isPlainObject(manifest)) return
  if (manifest.version !== 1) problems.push('policy-exceptions.json: expected "version": 1')

  for (const entry of requireArray(manifest, 'ignored_tree_paths', 'policy-exceptions.json')) {
    if (!isPlainObject(entry)) {
      problems.push('policy-exceptions.json: ignored_tree_paths entries must be objects')
      continue
    }
    const path = requireImportedPath(entry.path, 'policy-exceptions.json ignored_tree_paths')
    const kindValid = checkText(entry.kind, `policy-exceptions.json ignored_tree_paths [${entry.path ?? '<missing>'}] kind`)
    const reasonValid = checkText(entry.reason, `policy-exceptions.json ignored_tree_paths [${entry.path ?? '<missing>'}] reason`)
    if (!path || !kindValid || !reasonValid) continue
    if (ignoredTreePaths.has(path)) {
      problems.push(`policy-exceptions.json: duplicate ignored tree path ${path}`)
      continue
    }
    ignoredTreePaths.add(path)
  }

  for (const entry of requireArray(manifest, 'approved_lifecycle_scripts', 'policy-exceptions.json')) {
    if (!isPlainObject(entry)) {
      problems.push('policy-exceptions.json: approved_lifecycle_scripts entries must be objects')
      continue
    }
    const path = requireImportedPath(entry.path, 'policy-exceptions.json lifecycle approval')
    const scriptValid = checkText(entry.script, `policy-exceptions.json lifecycle approval [${entry.path ?? '<missing>'}] script`)
    const commandValid = typeof entry.command_sha256 === 'string' && SHA256_RE.test(entry.command_sha256)
    const sourceValid = typeof entry.source_sha256 === 'string' && SHA256_RE.test(entry.source_sha256)
    const reasonValid = checkText(entry.reason, `policy-exceptions.json lifecycle approval [${entry.path ?? '<missing>'}] reason`)
    if (!commandValid) problems.push(`policy-exceptions.json lifecycle approval [${entry.path ?? '<missing>'}]: invalid command_sha256`)
    if (!sourceValid) problems.push(`policy-exceptions.json lifecycle approval [${entry.path ?? '<missing>'}]: invalid source_sha256`)
    if (!path || !scriptValid || !commandValid || !sourceValid || !reasonValid) continue
    const key = `${path}\0${entry.script}`
    if (lifecycleApprovals.has(key)) {
      problems.push(`policy-exceptions.json: duplicate lifecycle approval for ${path} ${entry.script}`)
      continue
    }
    lifecycleApprovals.set(key, entry)
  }

  for (const entry of requireArray(manifest, 'approved_floating_dependency_manifests', 'policy-exceptions.json')) {
    if (!isPlainObject(entry)) {
      problems.push('policy-exceptions.json: approved_floating_dependency_manifests entries must be objects')
      continue
    }
    const path = requireImportedPath(entry.path, 'policy-exceptions.json floating dependency approval')
    const sourceValid = typeof entry.source_sha256 === 'string' && SHA256_RE.test(entry.source_sha256)
    const reasonValid = checkText(entry.reason, `policy-exceptions.json floating dependency approval [${entry.path ?? '<missing>'}] reason`)
    if (!sourceValid) problems.push(`policy-exceptions.json floating dependency approval [${entry.path ?? '<missing>'}]: invalid source_sha256`)
    if (!path || !sourceValid || !reasonValid) continue
    if (floatingManifestApprovals.has(path)) {
      problems.push(`policy-exceptions.json: duplicate floating dependency approval for ${path}`)
      continue
    }
    floatingManifestApprovals.set(path, entry)
  }

  for (const entry of requireArray(manifest, 'approved_registry_hosts', 'policy-exceptions.json')) {
    if (!isPlainObject(entry)) {
      problems.push('policy-exceptions.json: approved_registry_hosts entries must be objects')
      continue
    }
    const path = requireImportedPath(entry.path, 'policy-exceptions.json registry approval')
    const sourceValid = typeof entry.source_sha256 === 'string' && SHA256_RE.test(entry.source_sha256)
    const reasonValid = checkText(entry.reason, `policy-exceptions.json registry approval [${entry.path ?? '<missing>'}] reason`)
    if (!sourceValid) problems.push(`policy-exceptions.json registry approval [${entry.path ?? '<missing>'}]: invalid source_sha256`)
    const hosts = Array.isArray(entry.hosts) ? entry.hosts : []
    if (!Array.isArray(entry.hosts) || !hosts.length || hosts.some(host => typeof host !== 'string' || !host)) {
      problems.push(`policy-exceptions.json registry approval [${entry.path ?? '<missing>'}]: hosts must be a non-empty string array`)
    }
    if (!path || !sourceValid || !reasonValid || !hosts.length) continue
    for (const host of hosts) {
      if (typeof host !== 'string' || !host) continue
      const key = `${path}\0${host.toLowerCase()}`
      if (registryApprovals.has(key)) {
        problems.push(`policy-exceptions.json: duplicate registry approval for ${path} ${host}`)
        continue
      }
      registryApprovals.set(key, entry)
    }
  }
}

function isIgnoredTreePath (relativePath) {
  for (const ignored of ignoredTreePaths) {
    if (relativePath === ignored || relativePath.startsWith(`${ignored}/`)) return true
  }
  return false
}

// --- 3. Imported upstream source provenance --------------------------------

let lockedSourceFiles = new Map()

function lockedSourceMatch (repoRelativePath, sourceSha256) {
  const prefix = `${SOURCE_ROOT}/`
  if (!repoRelativePath.startsWith(prefix)) return false
  const lockEntry = lockedSourceFiles.get(repoRelativePath.slice(prefix.length))
  return Boolean(lockEntry && lockEntry.sha256 === sourceSha256)
}

function validateLockFileEntry (entry, seen) {
  if (!isPlainObject(entry)) {
    problems.push('upstream.lock.json: files entries must be objects')
    return
  }
  const path = normalizeRelativePath(entry.path)
  if (!path) problems.push('upstream.lock.json: file entry has an unsafe path')
  if (path && seen.has(path)) problems.push(`upstream.lock.json: duplicate file entry ${path}`)
  if (path) seen.add(path)
  if (typeof entry.mode !== 'string' || !/^100[0-7]{3}$/.test(entry.mode)) {
    problems.push(`upstream.lock.json [${entry.path ?? '<missing>'}]: invalid Git file mode`)
  }
  if (!Number.isInteger(entry.size) || entry.size < 0) {
    problems.push(`upstream.lock.json [${entry.path ?? '<missing>'}]: invalid size`)
  }
  if (typeof entry.sha256 !== 'string' || !SHA256_RE.test(entry.sha256)) {
    problems.push(`upstream.lock.json [${entry.path ?? '<missing>'}]: invalid SHA-256`)
  }
  if (typeof entry.git_blob_sha1 !== 'string' || !SHA1_RE.test(entry.git_blob_sha1)) {
    problems.push(`upstream.lock.json [${entry.path ?? '<missing>'}]: invalid Git blob SHA-1`)
  }
  if (path && SHA256_RE.test(entry.sha256) && SHA1_RE.test(entry.git_blob_sha1) && Number.isInteger(entry.size)) {
    lockedSourceFiles.set(path, entry)
  }
}

function validateSourceTree (sourceDirectory) {
  const seen = new Set()

  function visit (directory) {
    let entries
    try {
      entries = readdirSync(directory).sort()
    } catch (error) {
      problems.push(`upstream source: cannot read ${toPosixRelative(directory)}: ${error.message}`)
      return
    }
    for (const entry of entries) {
      const file = join(directory, entry)
      const repoRelativePath = toPosixRelative(file)
      let stats
      try {
        stats = lstatSync(file)
      } catch (error) {
        problems.push(`upstream source: cannot inspect ${repoRelativePath}: ${error.message}`)
        continue
      }
      if (isUnsafeLink(stats)) {
        problems.push(`upstream source: symlink or reparse path is forbidden: ${repoRelativePath}`)
        continue
      }
      if (isIgnoredTreePath(repoRelativePath)) continue
      if (stats.isDirectory()) {
        visit(file)
        continue
      }
      if (!stats.isFile()) {
        problems.push(`upstream source: unsupported filesystem entry: ${repoRelativePath}`)
        continue
      }
      const sourceRelativePath = repoRelativePath.slice(`${SOURCE_ROOT}/`.length)
      seen.add(sourceRelativePath)
      const expected = lockedSourceFiles.get(sourceRelativePath)
      if (!expected) {
        problems.push(`upstream source: unexpected file outside explicit generated/vendor exceptions: ${repoRelativePath}`)
        continue
      }
      try {
        const digest = fileDigest(file)
        if (digest.bytes.length !== expected.size) {
          problems.push(`upstream source: size mismatch for ${repoRelativePath}`)
        }
        if (digest.sha256 !== expected.sha256) {
          problems.push(`upstream source: SHA-256 mismatch for ${repoRelativePath}`)
        }
        if (digest.gitBlobSha1 !== expected.git_blob_sha1) {
          problems.push(`upstream source: Git blob SHA-1 mismatch for ${repoRelativePath}`)
        }
      } catch (error) {
        problems.push(`upstream source: cannot hash ${repoRelativePath}: ${error.message}`)
      }
    }
  }

  visit(sourceDirectory)
  for (const path of [...lockedSourceFiles.keys()].sort()) {
    if (!seen.has(path)) problems.push(`upstream source: locked file is missing: ${SOURCE_ROOT}/${path}`)
  }
}

function validateIgnoredPathsAreUntracked () {
  for (const ignoredPath of [...ignoredTreePaths].sort()) {
    const ignoredDirectory = fullPath(ignoredPath)
    if (!existsSync(ignoredDirectory)) continue
    let stats
    try {
      stats = lstatSync(ignoredDirectory)
    } catch (error) {
      problems.push(`policy-exceptions.json: cannot inspect ignored path ${ignoredPath}: ${error.message}`)
      continue
    }
    if (isUnsafeLink(stats) || !stats.isDirectory()) {
      problems.push(`policy-exceptions.json: ignored path must be a non-link directory: ${ignoredPath}`)
      continue
    }
    try {
      const output = execFileSync(
        'git',
        ['-c', 'core.quotepath=false', 'ls-files', '-z', '--', ignoredPath],
        { cwd: root, encoding: 'buffer', stdio: ['ignore', 'pipe', 'pipe'] }
      )
      const tracked = output.toString('utf8').split('\0').filter(Boolean)
      if (tracked.length) {
        problems.push(`policy-exceptions.json: tracked files are forbidden below ignored generated/vendor path ${ignoredPath}: ${tracked.join(', ')}`)
      }
    } catch (error) {
      problems.push(`policy-exceptions.json: cannot query Git-tracked files below ${ignoredPath}: ${error.message}`)
    }
  }
}

function buildLockedTreeSha1 () {
  const tree = {
    children: new Map(),
    files: new Map()
  }

  for (const [path, entry] of lockedSourceFiles) {
    const parts = path.split('/')
    const name = parts.pop()
    let cursor = tree
    for (const part of parts) {
      if (cursor.files.has(part)) throw new Error(`file/directory collision at ${path}`)
      if (!cursor.children.has(part)) {
        cursor.children.set(part, {
          children: new Map(),
          files: new Map()
        })
      }
      cursor = cursor.children.get(part)
    }
    if (cursor.children.has(name) || cursor.files.has(name)) {
      throw new Error(`duplicate or file/directory collision at ${path}`)
    }
    cursor.files.set(name, entry)
  }

  function hashTree (node) {
    const entries = []
    for (const [name, entry] of node.files) {
      entries.push({
        mode: entry.mode,
        name,
        sha: entry.git_blob_sha1,
        sortName: Buffer.from(name, 'utf8')
      })
    }
    for (const [name, child] of node.children) {
      entries.push({
        mode: '40000',
        name,
        sha: hashTree(child),
        sortName: Buffer.from(`${name}/`, 'utf8')
      })
    }
    entries.sort((a, b) => Buffer.compare(a.sortName, b.sortName))
    const content = Buffer.concat(entries.map(entry => Buffer.concat([
      Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'),
      Buffer.from(entry.sha, 'hex')
    ])))
    return createHash('sha1')
      .update(`tree ${content.length}\0`)
      .update(content)
      .digest('hex')
  }

  return hashTree(tree)
}

function validateSourceIndex () {
  const expected = new Map()
  for (const [path, entry] of lockedSourceFiles) {
    expected.set(`${SOURCE_ROOT}/${path}`, entry)
  }

  let output
  try {
    output = execFileSync(
      'git',
      ['-c', 'core.quotepath=false', 'ls-files', '-s', '-z', '--', SOURCE_ROOT],
      { cwd: root, encoding: 'buffer', stdio: ['ignore', 'pipe', 'pipe'] }
    )
  } catch (error) {
    problems.push(`upstream source: cannot query staged Git entries: ${error.message}`)
    return
  }

  const actual = new Map()
  for (const record of output.toString('utf8').split('\0').filter(Boolean)) {
    const tab = record.indexOf('\t')
    if (tab < 0) {
      problems.push(`upstream source: malformed Git index entry ${record}`)
      continue
    }
    const [mode, blob, stage] = record.slice(0, tab).split(' ')
    const path = record.slice(tab + 1)
    if (!/^100[0-7]{3}$/.test(mode) || !SHA1_RE.test(blob) || stage !== '0') {
      problems.push(`upstream source: malformed Git index metadata for ${path}`)
      continue
    }
    if (actual.has(path)) {
      problems.push(`upstream source: duplicate Git index entry for ${path}`)
      continue
    }
    actual.set(path, { mode, git_blob_sha1: blob })
  }

  for (const [path, entry] of expected) {
    const actualEntry = actual.get(path)
    if (!actualEntry) {
      problems.push(`upstream source: locked file is not tracked by Git: ${path}`)
      continue
    }
    if (actualEntry.mode !== entry.mode || actualEntry.git_blob_sha1 !== entry.git_blob_sha1) {
      problems.push(`upstream source: Git index mode or blob SHA-1 mismatch for ${path}`)
    }
  }
  for (const path of actual.keys()) {
    if (!expected.has(path)) problems.push(`upstream source: Git index contains an unexpected file: ${path}`)
  }
}

function validateUpstreamLock (electermCommit) {
  const sourceDirectory = fullPath(SOURCE_ROOT)
  const sourcePresent = existsSync(sourceDirectory)
  const lockPresent = existsSync(fullPath('security/upstream.lock.json'))
  if (!sourcePresent) {
    if (lockPresent) problems.push('upstream.lock.json exists but apps/electerm-web is missing')
    return
  }

  let sourceStats
  try {
    sourceStats = lstatSync(sourceDirectory)
  } catch (error) {
    problems.push(`upstream source: cannot inspect ${SOURCE_ROOT}: ${error.message}`)
    return
  }
  if (isUnsafeLink(sourceStats) || !sourceStats.isDirectory()) {
    problems.push(`upstream source: ${SOURCE_ROOT} must be a non-link directory`)
    return
  }
  if (!lockPresent) {
    problems.push('apps/electerm-web is present but security/upstream.lock.json is missing')
    return
  }

  const lock = readJson('security/upstream.lock.json', 'upstream.lock.json')
  if (!lock || !isPlainObject(lock)) return
  if (lock.version !== 1) problems.push('upstream.lock.json: expected "version": 1')
  if (lock.source_root !== SOURCE_ROOT) problems.push(`upstream.lock.json: source_root must be ${SOURCE_ROOT}`)

  const upstream = lock.upstream
  if (!isPlainObject(upstream)) {
    problems.push('upstream.lock.json: upstream must be an object')
  } else {
    if (upstream.repository !== IMPORTED_REPOSITORY) {
      problems.push('upstream.lock.json: upstream repository does not match electerm/electerm-web')
    }
    if (typeof upstream.commit !== 'string' || !SHA1_RE.test(upstream.commit)) {
      problems.push('upstream.lock.json: upstream commit must be a full SHA-1')
    } else if (electermCommit && upstream.commit !== electermCommit) {
      problems.push('upstream.lock.json: upstream commit does not match security/externals.json')
    }
    if (typeof upstream.tree_sha1 !== 'string' || !SHA1_RE.test(upstream.tree_sha1)) {
      problems.push('upstream.lock.json: upstream tree_sha1 must be a full SHA-1')
    }
    if (typeof upstream.archive_sha256 !== 'string' || !SHA256_RE.test(upstream.archive_sha256)) {
      problems.push('upstream.lock.json: upstream archive_sha256 must be a SHA-256')
    }
    if (!Number.isInteger(upstream.archive_regular_file_count) || upstream.archive_regular_file_count < 1) {
      problems.push('upstream.lock.json: upstream archive_regular_file_count must be positive')
    }
  }

  if (!isPlainObject(lock.license_identity) || lock.license_identity.spdx_id !== 'MIT') {
    problems.push('upstream.lock.json: expected MIT license identity')
  }
  const files = Array.isArray(lock.files) ? lock.files : null
  if (!files || !files.length) {
    problems.push('upstream.lock.json: files must be a non-empty array')
    return
  }
  const seen = new Set()
  for (const entry of files) validateLockFileEntry(entry, seen)
  if (upstream && files.length !== upstream.archive_regular_file_count) {
    problems.push('upstream.lock.json: archive_regular_file_count does not match files length')
  }
  if (upstream && SHA1_RE.test(upstream.tree_sha1)) {
    try {
      const derivedTreeSha1 = buildLockedTreeSha1()
      if (derivedTreeSha1 !== upstream.tree_sha1) {
        problems.push('upstream.lock.json: tree_sha1 does not match the locked paths, modes, and blob identities')
      }
    } catch (error) {
      problems.push(`upstream.lock.json: cannot reconstruct the locked Git tree: ${error.message}`)
    }
  }
  validateIgnoredPathsAreUntracked()
  validateSourceIndex()
  validateSourceTree(sourceDirectory)
}

// --- 4. Repository scan -----------------------------------------------------

function walkRepository () {
  const files = []

  function visit (directory) {
    let entries
    try {
      entries = readdirSync(directory).sort()
    } catch (error) {
      problems.push(`repository scan: cannot read ${toPosixRelative(directory)}: ${error.message}`)
      return
    }
    for (const entry of entries) {
      const file = join(directory, entry)
      const repoRelativePath = toPosixRelative(file)
      if (repoRelativePath === '.git') continue
      let stats
      try {
        stats = lstatSync(file)
      } catch (error) {
        problems.push(`repository scan: cannot inspect ${repoRelativePath}: ${error.message}`)
        continue
      }
      if (isUnsafeLink(stats)) {
        problems.push(`repository scan: symlink or reparse path is forbidden: ${repoRelativePath}`)
        continue
      }
      if (isIgnoredTreePath(repoRelativePath)) continue
      if (stats.isDirectory()) {
        visit(file)
      } else if (stats.isFile()) {
        files.push({ file, repoRelativePath })
      } else {
        problems.push(`repository scan: unsupported filesystem entry: ${repoRelativePath}`)
      }
    }
  }

  visit(root)
  return files
}

function isExactDependencySpec (spec) {
  return typeof spec === 'string' && EXACT_VERSION_RE.test(spec)
}

function collectDependencySpecs (value, section, path = []) {
  const specs = []
  if (!isPlainObject(value)) return specs
  for (const [name, spec] of Object.entries(value)) {
    const currentPath = [...path, name]
    if (typeof spec === 'string') {
      specs.push({ section, name: currentPath.join(' > '), spec })
    } else if (isPlainObject(spec)) {
      specs.push(...collectDependencySpecs(spec, section, currentPath))
    } else {
      specs.push({ section, name: currentPath.join(' > '), spec: String(spec) })
    }
  }
  return specs
}

function validatePackageManifests (files) {
  for (const { file, repoRelativePath } of files.filter(item => item.repoRelativePath.endsWith('/package.json') || item.repoRelativePath === 'package.json')) {
    let digest
    let manifest
    try {
      digest = fileDigest(file)
      manifest = parseJsonBytes(digest.bytes, repoRelativePath)
    } catch (error) {
      problems.push(`${repoRelativePath}: cannot read package manifest: ${error.message}`)
      continue
    }
    if (!manifest || !isPlainObject(manifest)) {
      problems.push(`${repoRelativePath}: package manifest must be an object`)
      continue
    }

    const scripts = manifest.scripts
    if (scripts !== undefined && !isPlainObject(scripts)) {
      problems.push(`${repoRelativePath}: scripts must be an object`)
    } else if (scripts) {
      for (const [script, command] of Object.entries(scripts)) {
        if (!LIFECYCLE_SCRIPTS.has(script)) continue
        const key = `${repoRelativePath}\0${script}`
        const approval = lifecycleApprovals.get(key)
        if (typeof command !== 'string') {
          problems.push(`${repoRelativePath}: lifecycle script "${script}" must be a string`)
          continue
        }
        if (!approval) {
          problems.push(`${repoRelativePath}: lifecycle script "${script}" is not approved`)
          continue
        }
        if (approval.command_sha256 !== sha256(Buffer.from(command, 'utf8'))) {
          problems.push(`${repoRelativePath}: lifecycle script "${script}" does not match its approved command hash`)
          continue
        }
        if (approval.source_sha256 !== digest.sha256 || !lockedSourceMatch(repoRelativePath, approval.source_sha256)) {
          problems.push(`${repoRelativePath}: lifecycle script "${script}" is not bound to the immutable upstream source hash`)
          continue
        }
        usedLifecycleApprovals.add(key)
      }
    }

    const floating = []
    for (const section of DEPENDENCY_SECTIONS) {
      if (manifest[section] === undefined) continue
      if (!isPlainObject(manifest[section])) {
        problems.push(`${repoRelativePath}: ${section} must be an object`)
        continue
      }
      floating.push(...collectDependencySpecs(manifest[section], section)
        .filter(item => !isExactDependencySpec(item.spec)))
    }
    for (const section of ['overrides', 'resolutions']) {
      if (manifest[section] === undefined) continue
      if (!isPlainObject(manifest[section])) {
        problems.push(`${repoRelativePath}: ${section} must be an object`)
        continue
      }
      floating.push(...collectDependencySpecs(manifest[section], section)
        .filter(item => !isExactDependencySpec(item.spec)))
    }
    if (floating.length) {
      const approval = floatingManifestApprovals.get(repoRelativePath)
      if (!approval) {
        for (const item of floating) {
          problems.push(`${repoRelativePath}: floating or URL dependency ${item.section}.${item.name}=${item.spec}`)
        }
      } else if (approval.source_sha256 !== digest.sha256 || !lockedSourceMatch(repoRelativePath, approval.source_sha256)) {
        problems.push(`${repoRelativePath}: floating dependency approval is not bound to the immutable upstream source hash`)
      } else {
        usedFloatingApprovals.add(repoRelativePath)
      }
    }
  }
}

function collectResolvedUrls (value, urls = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectResolvedUrls(item, urls)
  } else if (isPlainObject(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (key === 'resolved' && typeof item === 'string') urls.push(item)
      else collectResolvedUrls(item, urls)
    }
  }
  return urls
}

function validatePackageLocks (files) {
  for (const { file, repoRelativePath } of files.filter(item => item.repoRelativePath.endsWith('/package-lock.json') || item.repoRelativePath.endsWith('/npm-shrinkwrap.json') || item.repoRelativePath === 'package-lock.json' || item.repoRelativePath === 'npm-shrinkwrap.json')) {
    let digest
    let lock
    try {
      digest = fileDigest(file)
      lock = parseJsonBytes(digest.bytes, repoRelativePath)
    } catch (error) {
      problems.push(`${repoRelativePath}: cannot read package lock: ${error.message}`)
      continue
    }
    if (!lock || !isPlainObject(lock)) {
      problems.push(`${repoRelativePath}: package lock must be an object`)
      continue
    }
    const hosts = new Map()
    for (const resolved of collectResolvedUrls(lock)) {
      let url
      try {
        url = new URL(resolved)
      } catch {
        problems.push(`${repoRelativePath}: invalid resolved URL ${resolved}`)
        continue
      }
      const host = url.hostname.toLowerCase()
      if (url.protocol !== 'https:' || url.port || !host) {
        problems.push(`${repoRelativePath}: resolved URL must use HTTPS without a custom port: ${resolved}`)
        continue
      }
      hosts.set(host, (hosts.get(host) ?? 0) + 1)
    }
    for (const [host, count] of hosts) {
      if (ALLOWED_REGISTRIES.has(host)) continue
      const key = `${repoRelativePath}\0${host}`
      const approval = registryApprovals.get(key)
      if (approval && approval.source_sha256 === digest.sha256 && lockedSourceMatch(repoRelativePath, approval.source_sha256)) {
        usedRegistryApprovals.add(key)
        continue
      }
      problems.push(`${repoRelativePath}: ${count} resolved package entries use disallowed registry host ${host}`)
    }
  }
}

function validateUnsupportedLockfiles (files) {
  for (const { repoRelativePath } of files) {
    if (UNSUPPORTED_LOCKFILES.has(basename(repoRelativePath))) {
      problems.push(`${repoRelativePath}: unsupported package-manager lockfile; add a parser before allowing it`)
    }
  }
}

const PIPE_TO_SHELL = [
  /\b(?:curl|wget)\b[^\r\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh|fish|pwsh|powershell)\b/i,
  /\b(?:iwr|invoke-webrequest)\b[^\r\n|]*\|\s*(?:iex|invoke-expression)\b/i
]
const DOWNLOAD_TO_EXECUTABLE = [
  /\b(?:curl|wget)\b[^\r\n]*(?:\s-o|\s-O|\s--output(?:=|\s+))[^\r\n]*(?:&&|;)\s*(?:(?:chmod\s+\+x\s+\S+\s*(?:&&|;)\s*)?)(?:\.\/\S+|(?:bash|sh|zsh|pwsh|powershell)\s+\S+)/i,
  /\b(?:iwr|invoke-webrequest)\b[^\r\n]*(?:-outfile|-outf)\s+\S+[^\r\n]*(?:&&|;)\s*(?:&\s*\S+|iex\b|invoke-expression\b)/i
]
const IMAGE_RE = /^\s*image:\s*(\S+)/

function validateTextPolicies (files) {
  for (const { file, repoRelativePath } of files) {
    if (!SCANNED_EXTENSIONS.has(extname(file))) continue
    if (repoRelativePath === 'scripts/check-pins.mjs') continue
    let lines
    try {
      lines = readFileSync(file, 'utf8').split(/\r?\n/)
    } catch (error) {
      problems.push(`${repoRelativePath}: cannot scan text: ${error.message}`)
      continue
    }
    lines.forEach((line, index) => {
      const trimmed = line.trim()
      if (trimmed.startsWith('#') || trimmed.startsWith('//')) return
      for (const pattern of PIPE_TO_SHELL) {
        if (pattern.test(line)) {
          problems.push(`${repoRelativePath}:${index + 1}: downloaded code is piped to an interpreter`)
        }
      }
      for (const pattern of DOWNLOAD_TO_EXECUTABLE) {
        if (pattern.test(line)) {
          problems.push(`${repoRelativePath}:${index + 1}: downloaded file is executed on the same command line`)
        }
      }
      const image = IMAGE_RE.exec(line)
      if (image) {
        const pinned = image[1].includes('@sha256:') || image[1].startsWith('${')
        if (!pinned) problems.push(`${repoRelativePath}:${index + 1}: container image is not pinned by digest: ${image[1]}`)
      }
    })
  }
}

function validateUsedApprovals () {
  for (const key of lifecycleApprovals.keys()) {
    if (!usedLifecycleApprovals.has(key)) {
      const [path, script] = key.split('\0')
      problems.push(`policy-exceptions.json: stale lifecycle approval for ${path} ${script}`)
    }
  }
  for (const path of floatingManifestApprovals.keys()) {
    if (!usedFloatingApprovals.has(path)) {
      problems.push(`policy-exceptions.json: stale floating dependency approval for ${path}`)
    }
  }
  for (const key of registryApprovals.keys()) {
    if (!usedRegistryApprovals.has(key)) {
      const [path, host] = key.split('\0')
      problems.push(`policy-exceptions.json: stale registry approval for ${path} ${host}`)
    }
  }
}

const electermCommit = validateExternals()
validateExceptionManifest()
validateUpstreamLock(electermCommit)
const repositoryFiles = walkRepository()
validatePackageManifests(repositoryFiles)
validatePackageLocks(repositoryFiles)
validateUnsupportedLockfiles(repositoryFiles)
validateTextPolicies(repositoryFiles)
validateUsedApprovals()

if (problems.length) {
  console.error(`Policy violations: ${problems.length}\n`)
  for (const problem of problems) console.error(`  - ${problem}`)
  process.exit(1)
}

console.log('Dependency and imported-source policy passes.')
