#!/usr/bin/env node
/**
 * Fail-closed dependency and imported-source policy check.
 *
 * This script only reads repository data, Git metadata, and optional official
 * GitHub HTTPS responses. It never installs, imports, builds, or executes
 * imported application code.
 *
 * Run: node scripts/check-pins.mjs [--online]
 */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstatSync, readdirSync, readFileSync } from 'node:fs'
import { basename, extname, join, relative, sep } from 'node:path'

const root = process.cwd()
const problems = []
const argumentsSet = new Set(process.argv.slice(2))
const online = argumentsSet.delete('--online')

for (const argument of argumentsSet) {
  problems.push(`unsupported argument: ${argument}`)
}

const IMPORT_ROOT_BASES = ['apps', 'vendor']
const LOCK_FILE_RE = /\.lock\.json$/
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
const REGULAR_GIT_FILE_MODES = new Set(['100644', '100755'])
const SHA1_RE = /^[0-9a-f]{40}$/
const SHA256_RE = /^[0-9a-f]{64}$/
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const EXACT_VERSION_RE = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
const MAX_GITHUB_JSON_BYTES = 5 * 1024 * 1024
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
const ONLINE_TIMEOUT_MS = 30_000

const ignoredTreePaths = new Set()
const lifecycleApprovals = new Map()
const floatingManifestApprovals = new Map()
const registryApprovals = new Map()
const usedLifecycleApprovals = new Set()
const usedFloatingApprovals = new Set()
const usedRegistryApprovals = new Set()

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

function gitObjectSha1 (type, content) {
  return createHash('sha1')
    .update(`${type} ${content.length}\0`)
    .update(content)
    .digest('hex')
}

function gitBlobSha1 (value) {
  return gitObjectSha1('blob', value)
}

function fileDigest (file) {
  const bytes = readFileSync(file)
  return {
    bytes,
    sha256: sha256(bytes),
    gitBlobSha1: gitBlobSha1(bytes)
  }
}

function isUnsafeLink (stats) {
  return stats.isSymbolicLink()
}

function isPlainObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function checkText (value, description) {
  if (typeof value !== 'string' || !value.trim()) {
    problems.push(`${description}: must be a non-empty string`)
    return false
  }
  return true
}

function requireArray (object, field, description) {
  if (!Array.isArray(object[field])) {
    problems.push(`${description}: "${field}" must be an array`)
    return []
  }
  return object[field]
}

function lstatMaybe (file, description) {
  try {
    return lstatSync(file)
  } catch (error) {
    if (error.code !== 'ENOENT') {
      problems.push(`${description}: cannot inspect ${toPosixRelative(file)}: ${error.message}`)
    }
    return null
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
  const stats = lstatMaybe(file, description)
  if (!stats) {
    if (required) problems.push(`${description}: missing ${relativePath}`)
    return null
  }
  if (isUnsafeLink(stats) || !stats.isFile()) {
    problems.push(`${description}: ${relativePath} must be a regular non-link file`)
    return null
  }
  try {
    return parseJsonBytes(readFileSync(file), description)
  } catch (error) {
    problems.push(`${description}: cannot read ${relativePath}: ${error.message}`)
    return null
  }
}

function decodeUtf8Exactly (bytes, description) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    if (!Buffer.from(text, 'utf8').equals(bytes)) {
      problems.push(`${description}: UTF-8 text does not round-trip to the original bytes`)
      return null
    }
    return text
  } catch (error) {
    problems.push(`${description}: invalid UTF-8: ${error.message}`)
    return null
  }
}

function parseGitHubRepository (source, description) {
  if (!checkText(source, description)) return null
  let url
  try {
    url = new URL(source)
  } catch {
    problems.push(`${description}: must be a valid URL`)
    return null
  }
  const path = url.pathname.split('/').filter(Boolean)
  if (
    url.protocol !== 'https:' ||
    url.hostname !== 'github.com' ||
    url.port ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    path.length !== 2
  ) {
    problems.push(`${description}: must be a canonical https://github.com/<owner>/<repo> URL`)
    return null
  }
  const [owner, repository] = path
  const canonical = `https://github.com/${owner}/${repository}`
  if (source !== canonical) {
    problems.push(`${description}: must be canonical without a trailing slash or .git suffix`)
    return null
  }
  return { owner, repository, canonical }
}

function importRootFromPath (value, description) {
  const normalized = normalizeRelativePath(value)
  if (!normalized || !/^(?:apps|vendor)\/[^/]+$/.test(normalized)) {
    problems.push(`${description}: source_root must be an immediate apps/* or vendor/* directory`)
    return null
  }
  return normalized
}

function areOverlappingPaths (left, right) {
  return left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`)
}

// --- 1. External dependency register ---------------------------------------

const PIN_RE = /^(commit:[0-9a-f]{40}|commit:pending|version:\d+\.\d+\.\d+|digest:sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64}|none)$/
const KINDS = new Set(['git', 'npm', 'docker', 'binary', 'script', 'endpoint'])
const VERDICTS = new Set(['keep', 'replace', 'pin', 'remove'])

function validateExternals () {
  const registry = readJson('security/externals.json', 'externals.json')
  const itemsById = new Map()
  if (!registry || !isPlainObject(registry)) return itemsById
  if (registry.version !== 1) problems.push('externals.json: expected "version": 1')
  if (!Array.isArray(registry.items)) {
    problems.push('externals.json: missing items array')
    return itemsById
  }

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
    if (typeof item.id === 'string') {
      if (itemsById.has(item.id)) {
        problems.push(`externals.json: duplicate external id ${item.id}`)
      } else {
        itemsById.set(item.id, item)
      }
    }
  }
  return itemsById
}

function commitPinForExternal (item, description) {
  if (!item || item.kind !== 'git') {
    problems.push(`${description}: external must be a git item`)
    return null
  }
  const match = typeof item.pin === 'string' && /^commit:([0-9a-f]{40})$/.exec(item.pin)
  if (!match) {
    problems.push(`${description}: external must have a full commit pin`)
    return null
  }
  return match[1]
}

// --- 2. Provenance lock discovery and offline verification -----------------

function discoverLockFiles () {
  const securityDirectory = fullPath('security')
  const stats = lstatMaybe(securityDirectory, 'provenance locks')
  if (!stats) {
    problems.push('provenance locks: security directory is missing')
    return []
  }
  if (isUnsafeLink(stats) || !stats.isDirectory()) {
    problems.push('provenance locks: security must be a non-link directory')
    return []
  }

  let names
  try {
    names = readdirSync(securityDirectory).sort()
  } catch (error) {
    problems.push(`provenance locks: cannot read security directory: ${error.message}`)
    return []
  }

  const lockFiles = []
  for (const name of names) {
    if (!LOCK_FILE_RE.test(name)) continue
    const file = join(securityDirectory, name)
    const fileStats = lstatMaybe(file, 'provenance locks')
    if (!fileStats) continue
    if (isUnsafeLink(fileStats) || !fileStats.isFile()) {
      problems.push(`provenance locks: security/${name} must be a regular non-link file`)
      continue
    }
    lockFiles.push(`security/${name}`)
  }
  return lockFiles
}

function validateLockedFileEntries (files, label) {
  const entries = new Map()
  if (!Array.isArray(files) || !files.length) {
    problems.push(`${label}: files must be a non-empty array`)
    return entries
  }

  for (const entry of files) {
    if (!isPlainObject(entry)) {
      problems.push(`${label}: files entries must be objects`)
      continue
    }
    const path = normalizeRelativePath(entry.path)
    if (!path) {
      problems.push(`${label}: file entry has an unsafe path`)
      continue
    }
    if (entries.has(path)) {
      problems.push(`${label}: duplicate file entry ${path}`)
      continue
    }
    if (!REGULAR_GIT_FILE_MODES.has(entry.mode)) {
      problems.push(`${label} [${path}]: mode must be 100644 or 100755`)
    }
    if (!Number.isInteger(entry.size) || entry.size < 0) {
      problems.push(`${label} [${path}]: invalid size`)
    }
    if (typeof entry.sha256 !== 'string' || !SHA256_RE.test(entry.sha256)) {
      problems.push(`${label} [${path}]: invalid SHA-256`)
    }
    if (typeof entry.git_blob_sha1 !== 'string' || !SHA1_RE.test(entry.git_blob_sha1)) {
      problems.push(`${label} [${path}]: invalid Git blob SHA-1`)
    }
    entries.set(path, entry)
  }
  return entries
}

function buildLockedTreeSha1 (files) {
  const rootNode = {
    children: new Map(),
    files: new Map()
  }

  for (const [path, entry] of files) {
    const parts = path.split('/')
    const name = parts.pop()
    let node = rootNode
    for (const part of parts) {
      if (node.files.has(part)) throw new Error(`file/directory collision at ${path}`)
      if (!node.children.has(part)) {
        node.children.set(part, {
          children: new Map(),
          files: new Map()
        })
      }
      node = node.children.get(part)
    }
    if (node.children.has(name) || node.files.has(name)) {
      throw new Error(`duplicate or file/directory collision at ${path}`)
    }
    node.files.set(name, entry)
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
    entries.sort((left, right) => Buffer.compare(left.sortName, right.sortName))
    const content = Buffer.concat(entries.map(entry => Buffer.concat([
      Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'),
      Buffer.from(entry.sha, 'hex')
    ])))
    return gitObjectSha1('tree', content)
  }

  return hashTree(rootNode)
}

function parseRawCommitContent (rawContent, label) {
  if (rawContent.includes(0)) {
    problems.push(`${label}: raw commit content must not contain NUL bytes`)
    return null
  }
  const separator = rawContent.indexOf(Buffer.from('\n\n'))
  if (separator < 1) {
    problems.push(`${label}: raw commit content must contain a header/message separator`)
    return null
  }
  const headersText = decodeUtf8Exactly(rawContent.subarray(0, separator), `${label}: commit headers`)
  const messageBytes = rawContent.subarray(separator + 2)
  const message = decodeUtf8Exactly(messageBytes, `${label}: commit message`)
  if (headersText === null || message === null) return null
  if (headersText.includes('\r')) {
    problems.push(`${label}: commit headers must use LF line endings`)
    return null
  }

  const valuesByHeader = new Map()
  let previousHeader = null
  const lines = headersText.split('\n')
  for (const line of lines) {
    if (line.startsWith(' ')) {
      if (!previousHeader) problems.push(`${label}: malformed continued commit header`)
      continue
    }
    const firstSpace = line.indexOf(' ')
    if (firstSpace < 1) {
      problems.push(`${label}: malformed commit header "${line}"`)
      previousHeader = null
      continue
    }
    const key = line.slice(0, firstSpace)
    const value = line.slice(firstSpace + 1)
    if (!/^[a-z][a-z0-9-]*$/.test(key) || !value) {
      problems.push(`${label}: malformed commit header "${line}"`)
      previousHeader = null
      continue
    }
    if (!valuesByHeader.has(key)) valuesByHeader.set(key, [])
    valuesByHeader.get(key).push(value)
    previousHeader = key
  }

  const tree = valuesByHeader.get('tree') ?? []
  const parents = valuesByHeader.get('parent') ?? []
  const authors = valuesByHeader.get('author') ?? []
  const committers = valuesByHeader.get('committer') ?? []
  if (lines[0] !== `tree ${tree[0] ?? ''}` || tree.length !== 1 || !SHA1_RE.test(tree[0] ?? '')) {
    problems.push(`${label}: raw commit must start with exactly one full tree header`)
  }
  if (parents.some(parent => !SHA1_RE.test(parent))) {
    problems.push(`${label}: raw commit contains an invalid parent SHA-1`)
  }
  if (authors.length !== 1 || !authors[0]) {
    problems.push(`${label}: raw commit must contain exactly one author header`)
  }
  if (committers.length !== 1 || !committers[0]) {
    problems.push(`${label}: raw commit must contain exactly one committer header`)
  }
  if (
    tree.length !== 1 ||
    !SHA1_RE.test(tree[0] ?? '') ||
    parents.some(parent => !SHA1_RE.test(parent)) ||
    authors.length !== 1 ||
    committers.length !== 1
  ) {
    return null
  }
  return {
    treeSha1: tree[0],
    parents,
    author: authors[0],
    committer: committers[0],
    message,
    messageBytes
  }
}

function isExactBase64 (value) {
  return typeof value === 'string' &&
    value.length > 0 &&
    BASE64_RE.test(value) &&
    Buffer.from(value, 'base64').toString('base64') === value
}

function validateCommitObject (object, commit, treeSha1, label) {
  if (!isPlainObject(object)) {
    problems.push(`${label}: commit_object must be an object`)
    return null
  }
  if (object.object_format !== 'git-sha1') {
    problems.push(`${label}: commit_object.object_format must be git-sha1`)
  }
  if (object.raw_content_encoding !== 'base64') {
    problems.push(`${label}: commit_object.raw_content_encoding must be base64`)
  }
  if (!isExactBase64(object.raw_content_base64)) {
    problems.push(`${label}: commit_object.raw_content_base64 must be canonical base64`)
    return null
  }
  const rawContent = Buffer.from(object.raw_content_base64, 'base64')
  if (typeof object.raw_content_sha256 !== 'string' || !SHA256_RE.test(object.raw_content_sha256)) {
    problems.push(`${label}: commit_object.raw_content_sha256 must be a SHA-256`)
  } else if (object.raw_content_sha256 !== sha256(rawContent)) {
    problems.push(`${label}: commit_object.raw_content_sha256 does not match raw content`)
  }

  const parsed = parseRawCommitContent(rawContent, label)
  if (!parsed) return null
  if (object.tree_sha1 !== parsed.treeSha1) {
    problems.push(`${label}: commit_object.tree_sha1 does not match the raw tree header`)
  }
  if (!Array.isArray(object.parents) || object.parents.length !== parsed.parents.length || object.parents.some((parent, index) => parent !== parsed.parents[index])) {
    problems.push(`${label}: commit_object.parents does not match the raw parent headers`)
  }
  if (object.author !== parsed.author) {
    problems.push(`${label}: commit_object.author does not match the raw author header`)
  }
  if (object.committer !== parsed.committer) {
    problems.push(`${label}: commit_object.committer does not match the raw committer header`)
  }
  if (object.message_encoding !== 'utf-8') {
    problems.push(`${label}: commit_object.message_encoding must be utf-8`)
  }
  if (object.message !== parsed.message || !Buffer.from(String(object.message ?? ''), 'utf8').equals(parsed.messageBytes)) {
    problems.push(`${label}: commit_object.message does not match the raw UTF-8 message bytes`)
  }

  const computedCommit = gitObjectSha1('commit', rawContent)
  if (computedCommit !== commit) {
    problems.push(`${label}: raw commit object SHA-1 does not match the external commit pin`)
  }
  if (parsed.treeSha1 !== treeSha1) {
    problems.push(`${label}: raw commit tree header does not match upstream.tree_sha1`)
  }
  return {
    ...parsed,
    rawContent,
    computedCommit
  }
}

function validateArchiveBinding (archive, github, commit, fileCount, label) {
  if (!isPlainObject(archive)) {
    problems.push(`${label}: archive must be an object`)
    return null
  }
  const expectedUrl = `https://codeload.github.com/${github.owner}/${github.repository}/tar.gz/${commit}`
  if (archive.commit !== commit) {
    problems.push(`${label}: archive.commit does not match the external commit pin`)
  }
  if (archive.url !== expectedUrl) {
    problems.push(`${label}: archive.url does not bind the official codeload archive to the external commit pin`)
  }
  if (typeof archive.sha256 !== 'string' || !SHA256_RE.test(archive.sha256)) {
    problems.push(`${label}: archive.sha256 must be a SHA-256`)
  }
  if (!Number.isInteger(archive.byte_length) || archive.byte_length < 1) {
    problems.push(`${label}: archive.byte_length must be a positive integer`)
  }
  if (!Number.isInteger(archive.regular_file_count) || archive.regular_file_count !== fileCount) {
    problems.push(`${label}: archive.regular_file_count must equal the locked file count`)
  }
  return {
    expectedUrl,
    sha256: archive.sha256,
    byteLength: archive.byte_length
  }
}

function validateLicenseIdentity (identity, external, files, label) {
  if (!isPlainObject(identity)) {
    problems.push(`${label}: license_identity must be an object`)
    return
  }
  if (identity.spdx_id !== external.license) {
    problems.push(`${label}: license_identity.spdx_id must match externals.json`)
  }
  const path = normalizeRelativePath(identity.file)
  const locked = path && files.get(path)
  if (!path || !locked) {
    problems.push(`${label}: license_identity.file must name a locked source file`)
    return
  }
  if (identity.sha256 !== locked.sha256 || identity.git_blob_sha1 !== locked.git_blob_sha1) {
    problems.push(`${label}: license identity hashes must match ${path}`)
  }
}

function validateProvenanceLock (lockPath, lock, externals) {
  if (!lock || !isPlainObject(lock)) return null
  const startProblems = problems.length
  const label = lockPath
  if (lock.version !== 2) problems.push(`${label}: expected "version": 2`)
  const sourceRoot = importRootFromPath(lock.source_root, `${label}`)
  const externalId = typeof lock.external_id === 'string' && lock.external_id
  if (!externalId) problems.push(`${label}: external_id must be a non-empty string`)
  const external = externalId ? externals.get(externalId) : null
  if (externalId && !external) problems.push(`${label}: external_id "${externalId}" is not in security/externals.json`)
  const commit = external ? commitPinForExternal(external, label) : null
  const github = external ? parseGitHubRepository(external.official_source, `${label}: external official_source`) : null

  const upstream = lock.upstream
  if (!isPlainObject(upstream)) {
    problems.push(`${label}: upstream must be an object`)
    return {
      lockPath,
      sourceRoot,
      externalId,
      valid: false
    }
  }
  if (external && upstream.repository !== external.official_source) {
    problems.push(`${label}: upstream.repository must match the external official_source`)
  }
  if (upstream.commit !== commit) {
    problems.push(`${label}: upstream.commit must match the external full commit pin`)
  }
  if (typeof upstream.tree_sha1 !== 'string' || !SHA1_RE.test(upstream.tree_sha1)) {
    problems.push(`${label}: upstream.tree_sha1 must be a full SHA-1`)
  }

  const files = validateLockedFileEntries(lock.files, label)
  let derivedTreeSha1 = null
  if (files.size) {
    try {
      derivedTreeSha1 = buildLockedTreeSha1(files)
      if (derivedTreeSha1 !== upstream.tree_sha1) {
        problems.push(`${label}: upstream.tree_sha1 does not match locked paths, modes, and blob identities`)
      }
    } catch (error) {
      problems.push(`${label}: cannot reconstruct locked Git tree: ${error.message}`)
    }
  }

  const commitObject = commit && SHA1_RE.test(upstream.tree_sha1)
    ? validateCommitObject(upstream.commit_object, commit, upstream.tree_sha1, label)
    : null
  const archive = github && commit
    ? validateArchiveBinding(upstream.archive, github, commit, files.size, label)
    : null
  if (github && commit && upstream.commit_api !== `https://api.github.com/repos/${github.owner}/${github.repository}/git/commits/${commit}`) {
    problems.push(`${label}: commit_api does not bind the official GitHub commit endpoint to the external pin`)
  }
  if (github && SHA1_RE.test(upstream.tree_sha1) && upstream.tree_api !== `https://api.github.com/repos/${github.owner}/${github.repository}/git/trees/${upstream.tree_sha1}?recursive=1`) {
    problems.push(`${label}: tree_api does not bind the official GitHub tree endpoint to the locked tree`)
  }
  validateLicenseIdentity(lock.license_identity, external ?? {}, files, label)

  if (typeof lock.retrieved_at_utc !== 'string' || Number.isNaN(Date.parse(lock.retrieved_at_utc))) {
    problems.push(`${label}: retrieved_at_utc must be an ISO timestamp`)
  }
  if (!isPlainObject(lock.verification_method)) {
    problems.push(`${label}: verification_method must be an object`)
  }
  if (!isPlainObject(upstream.commit_signature) || typeof upstream.commit_signature.verified !== 'boolean' || !checkText(upstream.commit_signature.reason, `${label}: upstream.commit_signature.reason`)) {
    problems.push(`${label}: upstream.commit_signature must record verified and reason`)
  }

  return {
    lockPath,
    sourceRoot,
    externalId,
    external,
    github,
    commit,
    treeSha1: upstream.tree_sha1,
    files,
    archive,
    commitObject,
    commitSignature: upstream.commit_signature,
    valid: problems.length === startProblems
  }
}

function discoverImmediateImportRoots () {
  const roots = new Map()
  for (const base of IMPORT_ROOT_BASES) {
    const directory = fullPath(base)
    const stats = lstatMaybe(directory, 'import roots')
    if (!stats) continue
    if (isUnsafeLink(stats) || !stats.isDirectory()) {
      problems.push(`import roots: ${base} must be a non-link directory`)
      continue
    }
    let names
    try {
      names = readdirSync(directory).sort()
    } catch (error) {
      problems.push(`import roots: cannot read ${base}: ${error.message}`)
      continue
    }
    for (const name of names) {
      const child = join(directory, name)
      const childStats = lstatMaybe(child, 'import roots')
      if (!childStats) continue
      const importRoot = `${base}/${name}`
      if (isUnsafeLink(childStats)) {
        problems.push(`import roots: symlink or reparse path is forbidden: ${importRoot}`)
      } else if (childStats.isDirectory()) {
        roots.set(importRoot, child)
      }
    }
  }
  return roots
}

function validateLockClaims (externals) {
  const claims = []
  for (const lockPath of discoverLockFiles()) {
    const lock = readJson(lockPath, lockPath)
    const claim = validateProvenanceLock(lockPath, lock, externals)
    if (claim) claims.push(claim)
  }

  const claimsByRoot = new Map()
  const claimsByExternalId = new Map()
  for (const claim of claims) {
    if (claim.sourceRoot) {
      if (!claimsByRoot.has(claim.sourceRoot)) claimsByRoot.set(claim.sourceRoot, [])
      claimsByRoot.get(claim.sourceRoot).push(claim)
    }
    if (claim.externalId) {
      if (!claimsByExternalId.has(claim.externalId)) claimsByExternalId.set(claim.externalId, [])
      claimsByExternalId.get(claim.externalId).push(claim)
    }
  }

  for (const [sourceRoot, rootClaims] of claimsByRoot) {
    if (rootClaims.length > 1) {
      problems.push(`provenance locks: multiple locks claim source_root ${sourceRoot}: ${rootClaims.map(claim => claim.lockPath).join(', ')}`)
    }
  }
  for (const [externalId, externalClaims] of claimsByExternalId) {
    if (externalClaims.length > 1) {
      problems.push(`provenance locks: multiple locks claim external_id ${externalId}: ${externalClaims.map(claim => claim.lockPath).join(', ')}`)
    }
  }
  for (let index = 0; index < claims.length; index++) {
    for (let other = index + 1; other < claims.length; other++) {
      const left = claims[index]
      const right = claims[other]
      if (left.sourceRoot && right.sourceRoot && left.sourceRoot !== right.sourceRoot && areOverlappingPaths(left.sourceRoot, right.sourceRoot)) {
        problems.push(`provenance locks: overlapping source_root claims ${left.sourceRoot} (${left.lockPath}) and ${right.sourceRoot} (${right.lockPath})`)
      }
    }
  }

  const importedRoots = discoverImmediateImportRoots()
  for (const sourceRoot of importedRoots.keys()) {
    if (!claimsByRoot.has(sourceRoot)) {
      problems.push(`import roots: unclaimed imported tree ${sourceRoot}; add exactly one security/*.lock.json`)
    }
  }
  for (const claim of claims) {
    if (claim.sourceRoot && !importedRoots.has(claim.sourceRoot)) {
      problems.push(`${claim.lockPath}: claimed source_root is missing or not an immediate non-link import directory: ${claim.sourceRoot}`)
    }
  }

  const activeClaims = claims.filter(claim =>
    claim.valid &&
    claim.sourceRoot &&
    importedRoots.has(claim.sourceRoot) &&
    claimsByRoot.get(claim.sourceRoot)?.length === 1 &&
    claimsByExternalId.get(claim.externalId)?.length === 1
  )
  const lockedFilesByRepositoryPath = new Map()
  for (const claim of activeClaims) {
    for (const [path, entry] of claim.files) {
      const repositoryPath = `${claim.sourceRoot}/${path}`
      if (lockedFilesByRepositoryPath.has(repositoryPath)) {
        problems.push(`provenance locks: multiple locked file claims for ${repositoryPath}`)
      } else {
        lockedFilesByRepositoryPath.set(repositoryPath, { claim, entry })
      }
    }
  }
  return { activeClaims, lockedFilesByRepositoryPath }
}

function validateSourceIndex (claim) {
  let output
  try {
    output = execFileSync(
      'git',
      ['-c', 'core.quotepath=false', 'ls-files', '-s', '-z', '--', claim.sourceRoot],
      { cwd: root, encoding: 'buffer', stdio: ['ignore', 'pipe', 'pipe'] }
    )
  } catch (error) {
    problems.push(`${claim.lockPath}: cannot query staged Git entries for ${claim.sourceRoot}: ${error.message}`)
    return
  }

  const actual = new Map()
  for (const record of output.toString('utf8').split('\0').filter(Boolean)) {
    const tab = record.indexOf('\t')
    if (tab < 0) {
      problems.push(`${claim.lockPath}: malformed Git index entry ${record}`)
      continue
    }
    const [mode, blob, stage] = record.slice(0, tab).split(' ')
    const path = record.slice(tab + 1)
    if (!REGULAR_GIT_FILE_MODES.has(mode) || !SHA1_RE.test(blob) || stage !== '0') {
      problems.push(`${claim.lockPath}: malformed Git index metadata for ${path}`)
      continue
    }
    if (actual.has(path)) {
      problems.push(`${claim.lockPath}: duplicate Git index entry for ${path}`)
      continue
    }
    actual.set(path, { mode, gitBlobSha1: blob })
  }

  for (const [path, entry] of claim.files) {
    const repositoryPath = `${claim.sourceRoot}/${path}`
    const actualEntry = actual.get(repositoryPath)
    if (!actualEntry) {
      problems.push(`${claim.lockPath}: locked file is not tracked by Git: ${repositoryPath}`)
      continue
    }
    if (actualEntry.mode !== entry.mode || actualEntry.gitBlobSha1 !== entry.git_blob_sha1) {
      problems.push(`${claim.lockPath}: Git index mode or blob SHA-1 mismatch for ${repositoryPath}`)
    }
  }
  for (const path of actual.keys()) {
    if (!path.startsWith(`${claim.sourceRoot}/`) || !claim.files.has(path.slice(claim.sourceRoot.length + 1))) {
      problems.push(`${claim.lockPath}: Git index contains an unexpected file: ${path}`)
    }
  }
}

function isIgnoredTreePath (repositoryPath) {
  for (const ignoredPath of ignoredTreePaths) {
    if (repositoryPath === ignoredPath || repositoryPath.startsWith(`${ignoredPath}/`)) return true
  }
  return false
}

function validateSourceTree (claim) {
  const sourceDirectory = fullPath(claim.sourceRoot)
  const seen = new Set()

  function visit (directory) {
    let names
    try {
      names = readdirSync(directory).sort()
    } catch (error) {
      problems.push(`${claim.lockPath}: cannot read ${toPosixRelative(directory)}: ${error.message}`)
      return
    }
    for (const name of names) {
      const file = join(directory, name)
      const repositoryPath = toPosixRelative(file)
      const stats = lstatMaybe(file, claim.lockPath)
      if (!stats) continue
      if (isUnsafeLink(stats)) {
        problems.push(`${claim.lockPath}: symlink or reparse path is forbidden: ${repositoryPath}`)
        continue
      }
      if (isIgnoredTreePath(repositoryPath)) continue
      if (stats.isDirectory()) {
        visit(file)
        continue
      }
      if (!stats.isFile()) {
        problems.push(`${claim.lockPath}: unsupported filesystem entry: ${repositoryPath}`)
        continue
      }
      const sourcePath = repositoryPath.slice(claim.sourceRoot.length + 1)
      seen.add(sourcePath)
      const expected = claim.files.get(sourcePath)
      if (!expected) {
        problems.push(`${claim.lockPath}: unexpected file outside explicit generated/vendor exceptions: ${repositoryPath}`)
        continue
      }
      try {
        const digest = fileDigest(file)
        if (digest.bytes.length !== expected.size) {
          problems.push(`${claim.lockPath}: size mismatch for ${repositoryPath}`)
        }
        if (digest.sha256 !== expected.sha256) {
          problems.push(`${claim.lockPath}: SHA-256 mismatch for ${repositoryPath}`)
        }
        if (digest.gitBlobSha1 !== expected.git_blob_sha1) {
          problems.push(`${claim.lockPath}: Git blob SHA-1 mismatch for ${repositoryPath}`)
        }
      } catch (error) {
        problems.push(`${claim.lockPath}: cannot hash ${repositoryPath}: ${error.message}`)
      }
    }
  }

  visit(sourceDirectory)
  for (const sourcePath of [...claim.files.keys()].sort()) {
    if (!seen.has(sourcePath)) {
      problems.push(`${claim.lockPath}: locked file is missing: ${claim.sourceRoot}/${sourcePath}`)
    }
  }
}

// --- 3. Explicit policy exceptions -----------------------------------------

function claimForDescendantPath (repositoryPath, claims) {
  return claims.find(claim => repositoryPath.startsWith(`${claim.sourceRoot}/`)) ?? null
}

function requireClaimedDescendantPath (value, description, claims) {
  const normalized = normalizeRelativePath(value)
  if (!normalized) {
    problems.push(`${description}: path must be a safe repository-relative path`)
    return null
  }
  const claim = claimForDescendantPath(normalized, claims)
  if (!claim) {
    problems.push(`${description}: path must be below a claimed import root`)
    return null
  }
  return { path: normalized, claim }
}

function requireLockedApprovalTarget (source, sourceSha256, description, lockedFilesByRepositoryPath) {
  if (!source) return false
  if (typeof sourceSha256 !== 'string' || !SHA256_RE.test(sourceSha256)) {
    problems.push(`${description}: source_sha256 must be a SHA-256`)
    return false
  }
  const locked = lockedFilesByRepositoryPath.get(source.path)
  if (!locked || locked.entry.sha256 !== sourceSha256) {
    problems.push(`${description}: source_sha256 must match the exact locked source file`)
    return false
  }
  return true
}

function validateExceptionManifest (claims, lockedFilesByRepositoryPath) {
  const manifest = readJson('security/policy-exceptions.json', 'policy-exceptions.json')
  if (!manifest || !isPlainObject(manifest)) return
  if (manifest.version !== 1) problems.push('policy-exceptions.json: expected "version": 1')

  for (const entry of requireArray(manifest, 'ignored_tree_paths', 'policy-exceptions.json')) {
    if (!isPlainObject(entry)) {
      problems.push('policy-exceptions.json: ignored_tree_paths entries must be objects')
      continue
    }
    const source = requireClaimedDescendantPath(entry.path, 'policy-exceptions.json ignored_tree_paths', claims)
    const kindValid = checkText(entry.kind, `policy-exceptions.json ignored_tree_paths [${entry.path ?? '<missing>'}] kind`)
    const reasonValid = checkText(entry.reason, `policy-exceptions.json ignored_tree_paths [${entry.path ?? '<missing>'}] reason`)
    if (!source || !kindValid || !reasonValid) continue
    if (ignoredTreePaths.has(source.path)) {
      problems.push(`policy-exceptions.json: duplicate ignored tree path ${source.path}`)
      continue
    }
    ignoredTreePaths.add(source.path)
  }

  for (const entry of requireArray(manifest, 'approved_lifecycle_scripts', 'policy-exceptions.json')) {
    if (!isPlainObject(entry)) {
      problems.push('policy-exceptions.json: approved_lifecycle_scripts entries must be objects')
      continue
    }
    const source = requireClaimedDescendantPath(entry.path, 'policy-exceptions.json lifecycle approval', claims)
    const scriptValid = checkText(entry.script, `policy-exceptions.json lifecycle approval [${entry.path ?? '<missing>'}] script`)
    const commandValid = typeof entry.command_sha256 === 'string' && SHA256_RE.test(entry.command_sha256)
    if (!commandValid) problems.push(`policy-exceptions.json lifecycle approval [${entry.path ?? '<missing>'}]: command_sha256 must be a SHA-256`)
    const sourceValid = requireLockedApprovalTarget(source, entry.source_sha256, `policy-exceptions.json lifecycle approval [${entry.path ?? '<missing>'}]`, lockedFilesByRepositoryPath)
    const reasonValid = checkText(entry.reason, `policy-exceptions.json lifecycle approval [${entry.path ?? '<missing>'}] reason`)
    if (!source || !scriptValid || !commandValid || !sourceValid || !reasonValid) continue
    const key = `${source.path}\0${entry.script}`
    if (lifecycleApprovals.has(key)) {
      problems.push(`policy-exceptions.json: duplicate lifecycle approval for ${source.path} ${entry.script}`)
      continue
    }
    lifecycleApprovals.set(key, entry)
  }

  for (const entry of requireArray(manifest, 'approved_floating_dependency_manifests', 'policy-exceptions.json')) {
    if (!isPlainObject(entry)) {
      problems.push('policy-exceptions.json: approved_floating_dependency_manifests entries must be objects')
      continue
    }
    const source = requireClaimedDescendantPath(entry.path, 'policy-exceptions.json floating dependency approval', claims)
    const sourceValid = requireLockedApprovalTarget(source, entry.source_sha256, `policy-exceptions.json floating dependency approval [${entry.path ?? '<missing>'}]`, lockedFilesByRepositoryPath)
    const reasonValid = checkText(entry.reason, `policy-exceptions.json floating dependency approval [${entry.path ?? '<missing>'}] reason`)
    if (!source || !sourceValid || !reasonValid) continue
    if (floatingManifestApprovals.has(source.path)) {
      problems.push(`policy-exceptions.json: duplicate floating dependency approval for ${source.path}`)
      continue
    }
    floatingManifestApprovals.set(source.path, entry)
  }

  for (const entry of requireArray(manifest, 'approved_registry_hosts', 'policy-exceptions.json')) {
    if (!isPlainObject(entry)) {
      problems.push('policy-exceptions.json: approved_registry_hosts entries must be objects')
      continue
    }
    const source = requireClaimedDescendantPath(entry.path, 'policy-exceptions.json registry approval', claims)
    const sourceValid = requireLockedApprovalTarget(source, entry.source_sha256, `policy-exceptions.json registry approval [${entry.path ?? '<missing>'}]`, lockedFilesByRepositoryPath)
    const reasonValid = checkText(entry.reason, `policy-exceptions.json registry approval [${entry.path ?? '<missing>'}] reason`)
    const hosts = Array.isArray(entry.hosts) ? entry.hosts : []
    if (!Array.isArray(entry.hosts) || !hosts.length || hosts.some(host => typeof host !== 'string' || !host)) {
      problems.push(`policy-exceptions.json registry approval [${entry.path ?? '<missing>'}]: hosts must be a non-empty string array`)
    }
    if (!source || !sourceValid || !reasonValid || !hosts.length) continue
    for (const host of hosts) {
      if (typeof host !== 'string' || !host) continue
      const key = `${source.path}\0${host.toLowerCase()}`
      if (registryApprovals.has(key)) {
        problems.push(`policy-exceptions.json: duplicate registry approval for ${source.path} ${host}`)
        continue
      }
      registryApprovals.set(key, entry)
    }
  }
}

function validateIgnoredPathsAreUntracked () {
  for (const ignoredPath of [...ignoredTreePaths].sort()) {
    const directory = fullPath(ignoredPath)
    const stats = lstatMaybe(directory, 'policy-exceptions.json')
    if (!stats) continue
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

function lockedSourceMatch (repositoryPath, sourceSha256, lockedFilesByRepositoryPath) {
  const locked = lockedFilesByRepositoryPath.get(repositoryPath)
  return Boolean(locked && locked.entry.sha256 === sourceSha256)
}

// --- 4. Repository dependency and download policy --------------------------

function walkRepository () {
  const files = []

  function visit (directory) {
    let names
    try {
      names = readdirSync(directory).sort()
    } catch (error) {
      problems.push(`repository scan: cannot read ${toPosixRelative(directory)}: ${error.message}`)
      return
    }
    for (const name of names) {
      const file = join(directory, name)
      const repositoryPath = toPosixRelative(file)
      if (repositoryPath === '.git') continue
      const stats = lstatMaybe(file, 'repository scan')
      if (!stats) continue
      if (isUnsafeLink(stats)) {
        problems.push(`repository scan: symlink or reparse path is forbidden: ${repositoryPath}`)
        continue
      }
      if (isIgnoredTreePath(repositoryPath)) continue
      if (stats.isDirectory()) {
        visit(file)
      } else if (stats.isFile()) {
        files.push({ file, repositoryPath })
      } else {
        problems.push(`repository scan: unsupported filesystem entry: ${repositoryPath}`)
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

function validatePackageManifests (files, lockedFilesByRepositoryPath) {
  for (const { file, repositoryPath } of files.filter(item => item.repositoryPath.endsWith('/package.json') || item.repositoryPath === 'package.json')) {
    let digest
    let manifest
    try {
      digest = fileDigest(file)
      manifest = parseJsonBytes(digest.bytes, repositoryPath)
    } catch (error) {
      problems.push(`${repositoryPath}: cannot read package manifest: ${error.message}`)
      continue
    }
    if (!manifest || !isPlainObject(manifest)) {
      problems.push(`${repositoryPath}: package manifest must be an object`)
      continue
    }

    const scripts = manifest.scripts
    if (scripts !== undefined && !isPlainObject(scripts)) {
      problems.push(`${repositoryPath}: scripts must be an object`)
    } else if (scripts) {
      for (const [script, command] of Object.entries(scripts)) {
        if (!LIFECYCLE_SCRIPTS.has(script)) continue
        const key = `${repositoryPath}\0${script}`
        const approval = lifecycleApprovals.get(key)
        if (typeof command !== 'string') {
          problems.push(`${repositoryPath}: lifecycle script "${script}" must be a string`)
          continue
        }
        if (!approval) {
          problems.push(`${repositoryPath}: lifecycle script "${script}" is not approved`)
          continue
        }
        if (approval.command_sha256 !== sha256(Buffer.from(command, 'utf8'))) {
          problems.push(`${repositoryPath}: lifecycle script "${script}" does not match its approved command hash`)
          continue
        }
        if (approval.source_sha256 !== digest.sha256 || !lockedSourceMatch(repositoryPath, approval.source_sha256, lockedFilesByRepositoryPath)) {
          problems.push(`${repositoryPath}: lifecycle script "${script}" is not bound to the immutable upstream source hash`)
          continue
        }
        usedLifecycleApprovals.add(key)
      }
    }

    const floating = []
    for (const section of DEPENDENCY_SECTIONS) {
      if (manifest[section] === undefined) continue
      if (!isPlainObject(manifest[section])) {
        problems.push(`${repositoryPath}: ${section} must be an object`)
        continue
      }
      floating.push(...collectDependencySpecs(manifest[section], section)
        .filter(item => !isExactDependencySpec(item.spec)))
    }
    for (const section of ['overrides', 'resolutions']) {
      if (manifest[section] === undefined) continue
      if (!isPlainObject(manifest[section])) {
        problems.push(`${repositoryPath}: ${section} must be an object`)
        continue
      }
      floating.push(...collectDependencySpecs(manifest[section], section)
        .filter(item => !isExactDependencySpec(item.spec)))
    }
    if (floating.length) {
      const approval = floatingManifestApprovals.get(repositoryPath)
      if (!approval) {
        for (const item of floating) {
          problems.push(`${repositoryPath}: floating or URL dependency ${item.section}.${item.name}=${item.spec}`)
        }
      } else if (approval.source_sha256 !== digest.sha256 || !lockedSourceMatch(repositoryPath, approval.source_sha256, lockedFilesByRepositoryPath)) {
        problems.push(`${repositoryPath}: floating dependency approval is not bound to the immutable upstream source hash`)
      } else {
        usedFloatingApprovals.add(repositoryPath)
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

function validatePackageLocks (files, lockedFilesByRepositoryPath) {
  for (const { file, repositoryPath } of files.filter(item => item.repositoryPath.endsWith('/package-lock.json') || item.repositoryPath.endsWith('/npm-shrinkwrap.json') || item.repositoryPath === 'package-lock.json' || item.repositoryPath === 'npm-shrinkwrap.json')) {
    let digest
    let lock
    try {
      digest = fileDigest(file)
      lock = parseJsonBytes(digest.bytes, repositoryPath)
    } catch (error) {
      problems.push(`${repositoryPath}: cannot read package lock: ${error.message}`)
      continue
    }
    if (!lock || !isPlainObject(lock)) {
      problems.push(`${repositoryPath}: package lock must be an object`)
      continue
    }
    const hosts = new Map()
    for (const resolved of collectResolvedUrls(lock)) {
      let url
      try {
        url = new URL(resolved)
      } catch {
        problems.push(`${repositoryPath}: invalid resolved URL ${resolved}`)
        continue
      }
      const host = url.hostname.toLowerCase()
      if (url.protocol !== 'https:' || url.port || !host) {
        problems.push(`${repositoryPath}: resolved URL must use HTTPS without a custom port: ${resolved}`)
        continue
      }
      hosts.set(host, (hosts.get(host) ?? 0) + 1)
    }
    for (const [host, count] of hosts) {
      if (ALLOWED_REGISTRIES.has(host)) continue
      const key = `${repositoryPath}\0${host}`
      const approval = registryApprovals.get(key)
      if (approval && approval.source_sha256 === digest.sha256 && lockedSourceMatch(repositoryPath, approval.source_sha256, lockedFilesByRepositoryPath)) {
        usedRegistryApprovals.add(key)
        continue
      }
      problems.push(`${repositoryPath}: ${count} resolved package entries use disallowed registry host ${host}`)
    }
  }
}

function validateUnsupportedLockfiles (files) {
  for (const { repositoryPath } of files) {
    if (UNSUPPORTED_LOCKFILES.has(basename(repositoryPath))) {
      problems.push(`${repositoryPath}: unsupported package-manager lockfile; add a parser before allowing it`)
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
  for (const { file, repositoryPath } of files) {
    if (!SCANNED_EXTENSIONS.has(extname(file))) continue
    if (repositoryPath === 'scripts/check-pins.mjs') continue
    let lines
    try {
      lines = readFileSync(file, 'utf8').split(/\r?\n/)
    } catch (error) {
      problems.push(`${repositoryPath}: cannot scan text: ${error.message}`)
      continue
    }
    lines.forEach((line, index) => {
      const trimmed = line.trim()
      if (trimmed.startsWith('#') || trimmed.startsWith('//')) return
      for (const pattern of PIPE_TO_SHELL) {
        if (pattern.test(line)) {
          problems.push(`${repositoryPath}:${index + 1}: downloaded code is piped to an interpreter`)
        }
      }
      for (const pattern of DOWNLOAD_TO_EXECUTABLE) {
        if (pattern.test(line)) {
          problems.push(`${repositoryPath}:${index + 1}: downloaded file is executed on the same command line`)
        }
      }
      const image = IMAGE_RE.exec(line)
      if (image) {
        const pinned = image[1].includes('@sha256:') || image[1].startsWith('${')
        if (!pinned) problems.push(`${repositoryPath}:${index + 1}: container image is not pinned by digest: ${image[1]}`)
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

// --- 5. Bounded official GitHub verification --------------------------------

function githubHeaders (accept) {
  const headers = {
    Accept: accept,
    'User-Agent': 'ai-friends-provenance-check'
  }
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`
  return headers
}

async function fetchBounded (url, description, maximumBytes, headers) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), ONLINE_TIMEOUT_MS)
  try {
    const response = await fetch(url, {
      headers,
      redirect: 'error',
      signal: controller.signal
    })
    if (!response.ok) throw new Error(`received HTTP ${response.status}`)
    const contentLength = response.headers.get('content-length')
    if (contentLength) {
      if (!/^\d+$/.test(contentLength) || Number(contentLength) > maximumBytes) {
        throw new Error(`response content-length exceeds ${maximumBytes} bytes`)
      }
    }
    if (!response.body) throw new Error('response has no body')
    const reader = response.body.getReader()
    const chunks = []
    let length = 0
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.length
      if (length > maximumBytes) {
        await reader.cancel()
        throw new Error(`response exceeds ${maximumBytes} bytes`)
      }
      chunks.push(Buffer.from(value))
    }
    return Buffer.concat(chunks, length)
  } catch (error) {
    problems.push(`${description}: ${error.message}`)
    return null
  } finally {
    clearTimeout(timeout)
  }
}

async function fetchGitHubJson (url, description) {
  const bytes = await fetchBounded(
    url,
    description,
    MAX_GITHUB_JSON_BYTES,
    githubHeaders('application/vnd.github+json')
  )
  return bytes ? parseJsonBytes(bytes, description) : null
}

function parseGitIdentity (value, description) {
  const match = /^(.+) <([^<>]+)> (\d+) ([+-]\d{4})$/.exec(value)
  if (!match) {
    problems.push(`${description}: unsupported author/committer identity format`)
    return null
  }
  return {
    name: match[1],
    email: match[2],
    timestamp: Number(match[3])
  }
}

function verifyOnlineIdentity (actual, rawIdentity, description) {
  const expected = parseGitIdentity(rawIdentity, description)
  if (!expected || !isPlainObject(actual)) return
  const timestamp = typeof actual.date === 'string' ? Date.parse(actual.date) : Number.NaN
  if (
    actual.name !== expected.name ||
    actual.email !== expected.email ||
    !Number.isFinite(timestamp) ||
    Math.trunc(timestamp / 1000) !== expected.timestamp
  ) {
    problems.push(`${description}: GitHub commit identity does not match the locked raw commit header`)
  }
}

async function validateOnlineClaim (claim) {
  const { github, commit, treeSha1, files, archive, commitObject } = claim
  const apiBase = `https://api.github.com/repos/${github.owner}/${github.repository}`
  const commitDocument = await fetchGitHubJson(
    `${apiBase}/git/commits/${commit}`,
    `${claim.lockPath}: official GitHub commit`
  )
  if (commitDocument && isPlainObject(commitDocument)) {
    if (commitDocument.sha !== commit) {
      problems.push(`${claim.lockPath}: official GitHub commit SHA does not match the external pin`)
    }
    if (commitDocument.tree?.sha !== treeSha1) {
      problems.push(`${claim.lockPath}: official GitHub commit tree does not match the locked tree`)
    }
    const parents = Array.isArray(commitDocument.parents) ? commitDocument.parents.map(parent => parent?.sha) : []
    if (parents.length !== commitObject.parents.length || parents.some((parent, index) => parent !== commitObject.parents[index])) {
      problems.push(`${claim.lockPath}: official GitHub parent list does not match the locked raw commit`)
    }
    // GitHub's Git database JSON omits trailing LF bytes from the raw message.
    if (commitDocument.message !== commitObject.message.replace(/\n+$/, '')) {
      problems.push(`${claim.lockPath}: official GitHub commit message does not match the locked raw commit`)
    }
    verifyOnlineIdentity(commitDocument.author, commitObject.author, `${claim.lockPath}: official GitHub author`)
    verifyOnlineIdentity(commitDocument.committer, commitObject.committer, `${claim.lockPath}: official GitHub committer`)
    const signature = commitDocument.verification
    if (
      !isPlainObject(signature) ||
      signature.verified !== claim.commitSignature.verified ||
      signature.reason !== claim.commitSignature.reason
    ) {
      problems.push(`${claim.lockPath}: official GitHub commit signature status does not match the lock`)
    }
  }

  const treeDocument = await fetchGitHubJson(
    `${apiBase}/git/trees/${treeSha1}?recursive=1`,
    `${claim.lockPath}: official GitHub tree`
  )
  if (treeDocument && isPlainObject(treeDocument)) {
    if (treeDocument.sha !== treeSha1 || treeDocument.truncated !== false || !Array.isArray(treeDocument.tree)) {
      problems.push(`${claim.lockPath}: official GitHub recursive tree is incomplete or does not match the locked tree SHA`)
    } else {
      const blobs = new Map()
      for (const entry of treeDocument.tree) {
        if (!isPlainObject(entry)) {
          problems.push(`${claim.lockPath}: official GitHub tree contains an invalid entry`)
          continue
        }
        if (entry.type !== 'blob') {
          if (entry.type !== 'tree') {
            problems.push(`${claim.lockPath}: official GitHub tree contains a non-blob non-tree entry at ${entry.path}`)
          }
          continue
        }
        if (typeof entry.path !== 'string' || blobs.has(entry.path)) {
          problems.push(`${claim.lockPath}: official GitHub tree contains an invalid or duplicate blob path`)
          continue
        }
        blobs.set(entry.path, entry)
      }
      for (const [path, expected] of files) {
        const actual = blobs.get(path)
        if (!actual || actual.mode !== expected.mode || actual.sha !== expected.git_blob_sha1 || actual.size !== expected.size) {
          problems.push(`${claim.lockPath}: official GitHub blob metadata does not match lock for ${path}`)
        }
      }
      for (const path of blobs.keys()) {
        if (!files.has(path)) problems.push(`${claim.lockPath}: official GitHub tree has an unlocked blob ${path}`)
      }
    }
  }

  const archiveBytes = await fetchBounded(
    archive.expectedUrl,
    `${claim.lockPath}: official codeload archive`,
    MAX_ARCHIVE_BYTES,
    { 'User-Agent': 'ai-friends-provenance-check' }
  )
  if (archiveBytes) {
    if (archiveBytes.length !== archive.byteLength) {
      problems.push(`${claim.lockPath}: official codeload archive byte length does not match the lock`)
    }
    if (sha256(archiveBytes) !== archive.sha256) {
      problems.push(`${claim.lockPath}: official codeload archive SHA-256 does not match the lock`)
    }
  }
}

async function validateOnlineClaims (claims) {
  for (const claim of claims) {
    await validateOnlineClaim(claim)
  }
}

async function main () {
  const externals = validateExternals()
  const { activeClaims, lockedFilesByRepositoryPath } = validateLockClaims(externals)
  validateExceptionManifest(activeClaims, lockedFilesByRepositoryPath)
  validateIgnoredPathsAreUntracked()
  for (const claim of activeClaims) {
    validateSourceIndex(claim)
    validateSourceTree(claim)
  }
  const repositoryFiles = walkRepository()
  validatePackageManifests(repositoryFiles, lockedFilesByRepositoryPath)
  validatePackageLocks(repositoryFiles, lockedFilesByRepositoryPath)
  validateUnsupportedLockfiles(repositoryFiles)
  validateTextPolicies(repositoryFiles)
  validateUsedApprovals()
  if (online && !problems.length) await validateOnlineClaims(activeClaims)

  if (problems.length) {
    console.error(`Policy violations: ${problems.length}\n`)
    for (const problem of problems) console.error(`  - ${problem}`)
    process.exit(1)
  }
  console.log(`Dependency and imported-source policy passes${online ? ' (including official GitHub verification)' : ''}.`)
}

await main()
