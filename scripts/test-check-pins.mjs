import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { cpSync, mkdtempSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const checker = join(scriptDirectory, 'check-pins.mjs')
const fixtureRoot = join(scriptDirectory, 'test-fixtures', 'check-pins')

const emptyExceptions = {
  version: 1,
  ignored_tree_paths: [],
  approved_lifecycle_scripts: [],
  approved_floating_dependency_manifests: [],
  approved_registry_hosts: []
}

function objectSha1 (type, content) {
  return createHash('sha1')
    .update(`${type} ${content.length}\0`)
    .update(content)
    .digest('hex')
}

function sha256 (content) {
  return createHash('sha256').update(content).digest('hex')
}

function gitBlobSha1 (content) {
  return objectSha1('blob', content)
}

function gitTreeSha1 (entries) {
  const content = Buffer.concat([...entries]
    .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
    .map(([name, entry]) => Buffer.concat([
      Buffer.from(`${entry.mode} ${name}\0`),
      Buffer.from(entry.git_blob_sha1, 'hex')
    ])))
  return objectSha1('tree', content)
}

function runGit (temporaryRoot, argumentsList) {
  const hooksPath = join(temporaryRoot, '.empty-hooks')
  mkdirSync(hooksPath, { recursive: true })
  const result = spawnSync('git', ['-c', `core.hooksPath=${hooksPath}`, ...argumentsList], {
    cwd: temporaryRoot,
    encoding: 'utf8'
  })
  assert.equal(result.status, 0, result.stdout + result.stderr)
}

function runChecker (temporaryRoot) {
  return spawnSync(process.execPath, [checker], {
    cwd: temporaryRoot,
    encoding: 'utf8'
  })
}

function writeJson (file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`)
}

function externalRegister (items = []) {
  return {
    version: 1,
    generated: '2026-08-30',
    items
  }
}

function prepareFixture (fixture) {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-'))
  mkdirSync(join(temporaryRoot, 'security'), { recursive: true })
  writeJson(join(temporaryRoot, 'security', 'externals.json'), externalRegister())
  writeJson(join(temporaryRoot, 'security', 'policy-exceptions.json'), emptyExceptions)

  cpSync(join(fixtureRoot, fixture), temporaryRoot, { recursive: true })
  for (const file of [
    join(temporaryRoot, 'apps', 'fixture', 'package.json.fixture'),
    join(temporaryRoot, 'apps', 'fixture', 'package-lock.json.fixture'),
    join(temporaryRoot, 'apps', 'fixture', 'yarn.lock.fixture')
  ]) {
    try {
      renameSync(file, file.slice(0, -'.fixture'.length))
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
  }
  return temporaryRoot
}

function expectFixtureRejected (fixture, message) {
  const temporaryRoot = prepareFixture(fixture)
  try {
    const result = runChecker(temporaryRoot)
    assert.equal(result.status, 1, result.stdout + result.stderr)
    assert.match(result.stderr, message)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
}

function writeSourceFiles (temporaryRoot, sourceRoot, contents) {
  const entries = []
  for (const [path, content] of contents) {
    const file = join(temporaryRoot, sourceRoot, ...path.split('/'))
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, content)
    entries.push([path, {
      mode: '100644',
      size: content.length,
      sha256: sha256(content),
      git_blob_sha1: gitBlobSha1(content)
    }])
  }
  return entries
}

function rawCommitContent (treeSha1) {
  return Buffer.from(
    `tree ${treeSha1}\n` +
    'author Fixture Author <fixture@example.test> 0 +0000\n' +
    'committer Fixture Committer <fixture@example.test> 0 +0000\n' +
    '\n' +
    'fixture import\n'
  )
}

function makeLock ({
  externalId,
  sourceRoot,
  repository,
  commit,
  treeSha1,
  rawCommit,
  entries,
  archiveCommit = commit,
  archiveUrl
}) {
  const files = Object.fromEntries(entries)
  const license = files.LICENSE
  const [owner, name] = new URL(repository).pathname.split('/').filter(Boolean)
  const expectedArchiveUrl = `https://codeload.github.com/${owner}/${name}/tar.gz/${commit}`
  return {
    version: 2,
    external_id: externalId,
    source_root: sourceRoot,
    upstream: {
      repository,
      commit,
      tree_sha1: treeSha1,
      commit_object: {
        object_format: 'git-sha1',
        raw_content_encoding: 'base64',
        raw_content_base64: rawCommit.toString('base64'),
        raw_content_sha256: sha256(rawCommit),
        tree_sha1: treeSha1,
        parents: [],
        author: 'Fixture Author <fixture@example.test> 0 +0000',
        committer: 'Fixture Committer <fixture@example.test> 0 +0000',
        message_encoding: 'utf-8',
        message: 'fixture import\n'
      },
      commit_api: `https://api.github.com/repos/${owner}/${name}/git/commits/${commit}`,
      tree_api: `https://api.github.com/repos/${owner}/${name}/git/trees/${treeSha1}?recursive=1`,
      archive: {
        commit: archiveCommit,
        url: archiveUrl ?? expectedArchiveUrl,
        sha256: 'a'.repeat(64),
        byte_length: 1,
        regular_file_count: entries.length
      },
      commit_signature: {
        verified: false,
        reason: 'unsigned'
      }
    },
    retrieved_at_utc: '2026-08-30T00:00:00Z',
    license_identity: {
      spdx_id: 'MIT',
      repository_api_name: 'MIT License',
      file: 'LICENSE',
      sha256: license.sha256,
      git_blob_sha1: license.git_blob_sha1
    },
    verification_method: {
      fixture: 'Synthetic data for parser-only policy tests.'
    },
    files: entries.map(([path, entry]) => ({ path, ...entry }))
  }
}

function createAnchoredImport (temporaryRoot, options = {}) {
  const sourceRoot = options.sourceRoot ?? 'apps/electerm-web'
  const externalId = options.externalId ?? 'fixture-upstream'
  const repository = options.repository ?? 'https://github.com/example/fixture-upstream'
  const contents = options.contents ?? new Map([
    ['LICENSE', Buffer.from('MIT fixture license\n')],
    ['README.md', Buffer.from('fixture source\n')]
  ])
  const entries = writeSourceFiles(temporaryRoot, sourceRoot, contents)
  const treeSha1 = gitTreeSha1(entries)
  const rawCommit = rawCommitContent(treeSha1)
  const commit = objectSha1('commit', rawCommit)
  const lock = makeLock({
    externalId,
    sourceRoot,
    repository,
    commit,
    treeSha1,
    rawCommit,
    entries
  })

  mkdirSync(join(temporaryRoot, 'security'), { recursive: true })
  writeJson(join(temporaryRoot, 'security', 'externals.json'), externalRegister([{
    id: externalId,
    kind: 'git',
    official_source: repository,
    pin: `commit:${commit}`,
    license: 'MIT',
    verdict: 'pin'
  }]))
  writeJson(join(temporaryRoot, 'security', 'policy-exceptions.json'), emptyExceptions)
  writeJson(join(temporaryRoot, 'security', 'fixture.lock.json'), lock)
  runGit(temporaryRoot, ['init', '--quiet'])
  runGit(temporaryRoot, ['add', sourceRoot])
  return {
    sourceRoot,
    repository,
    contents,
    entries,
    treeSha1,
    rawCommit,
    commit,
    lock,
    lockPath: join(temporaryRoot, 'security', 'fixture.lock.json')
  }
}

function expectRejected (temporaryRoot, message) {
  const result = runChecker(temporaryRoot)
  assert.equal(result.status, 1, result.stdout + result.stderr)
  assert.match(result.stderr, message)
}

test('rejects an unapproved lifecycle script under apps', () => {
  expectFixtureRejected('forbidden-lifecycle', /lifecycle script "postinstall" is not approved/)
})

test('rejects a registry mirror under apps', () => {
  expectFixtureRejected('mirror-url', /disallowed registry host registry\.npmmirror\.com/)
})

test('rejects a floating dependency version under apps', () => {
  expectFixtureRejected('floating-version', /floating or URL dependency dependencies\.example=\^1\.2\.3/)
})

test('rejects an unsupported package-manager lockfile under apps', () => {
  expectFixtureRejected('unsupported-lockfile', /unsupported package-manager lockfile/)
})

test('accepts a synthetic import anchored to its raw Git commit object', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-anchored-'))
  try {
    createAnchoredImport(temporaryRoot)
    const result = runChecker(temporaryRoot)
    assert.equal(result.status, 0, result.stdout + result.stderr)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})

test('rejects force-added files under an explicit generated/vendor exception', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-index-'))
  try {
    const fixture = createAnchoredImport(temporaryRoot)
    const injectedPath = join(temporaryRoot, fixture.sourceRoot, 'node_modules', 'injected.js')
    mkdirSync(dirname(injectedPath), { recursive: true })
    writeFileSync(injectedPath, 'export default 1\n')
    writeJson(join(temporaryRoot, 'security', 'policy-exceptions.json'), {
      ...emptyExceptions,
      ignored_tree_paths: [{
        path: `${fixture.sourceRoot}/node_modules`,
        kind: 'vendor',
        reason: 'Fixture-only generated dependency output.'
      }]
    })
    runGit(temporaryRoot, ['add', '-f', `${fixture.sourceRoot}/node_modules/injected.js`])
    expectRejected(temporaryRoot, /tracked files are forbidden below ignored generated\/vendor path/)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})

test('rejects a regenerated source tree and file list that do not match the pinned commit', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-reanchored-'))
  try {
    const fixture = createAnchoredImport(temporaryRoot)
    const changed = new Map(fixture.contents)
    changed.set('README.md', Buffer.from('modified source after the pinned commit\n'))
    const entries = writeSourceFiles(temporaryRoot, fixture.sourceRoot, changed)
    const rewrittenLock = structuredClone(fixture.lock)
    rewrittenLock.files = entries.map(([path, entry]) => ({ path, ...entry }))
    rewrittenLock.upstream.tree_sha1 = gitTreeSha1(entries)
    rewrittenLock.license_identity.sha256 = Object.fromEntries(entries).LICENSE.sha256
    rewrittenLock.license_identity.git_blob_sha1 = Object.fromEntries(entries).LICENSE.git_blob_sha1
    writeJson(fixture.lockPath, rewrittenLock)
    runGit(temporaryRoot, ['add', fixture.sourceRoot])
    expectRejected(temporaryRoot, /raw commit tree header does not match upstream\.tree_sha1/)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})

test('rejects an archive record bound to a different commit', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-archive-'))
  try {
    const fixture = createAnchoredImport(temporaryRoot)
    fixture.lock.upstream.archive.commit = '0'.repeat(40)
    writeJson(fixture.lockPath, fixture.lock)
    expectRejected(temporaryRoot, /archive\.commit does not match the external commit pin/)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})

test('rejects an unclaimed immediate apps tree', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-unclaimed-'))
  try {
    createAnchoredImport(temporaryRoot)
    const nextRoot = join(temporaryRoot, 'apps', 'electerm-web-next')
    mkdirSync(nextRoot, { recursive: true })
    writeFileSync(join(nextRoot, 'README.md'), 'unclaimed tree\n')
    expectRejected(temporaryRoot, /unclaimed imported tree apps\/electerm-web-next/)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})

test('rejects an apps tree with no provenance lock', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-missing-lock-'))
  try {
    mkdirSync(join(temporaryRoot, 'apps', 'electerm-web'), { recursive: true })
    mkdirSync(join(temporaryRoot, 'security'), { recursive: true })
    writeFileSync(join(temporaryRoot, 'apps', 'electerm-web', 'README.md'), 'unclaimed tree\n')
    writeJson(join(temporaryRoot, 'security', 'externals.json'), externalRegister())
    writeJson(join(temporaryRoot, 'security', 'policy-exceptions.json'), emptyExceptions)
    expectRejected(temporaryRoot, /unclaimed imported tree apps\/electerm-web/)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})

test('rejects an unclaimed immediate vendor tree', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-unclaimed-vendor-'))
  try {
    createAnchoredImport(temporaryRoot)
    const vendorRoot = join(temporaryRoot, 'vendor', 'utility')
    mkdirSync(vendorRoot, { recursive: true })
    writeFileSync(join(vendorRoot, 'README.md'), 'unclaimed vendor tree\n')
    expectRejected(temporaryRoot, /unclaimed imported tree vendor\/utility/)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})

test('rejects a lock that claims a missing import root', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-missing-root-'))
  try {
    const fixture = createAnchoredImport(temporaryRoot)
    rmSync(join(temporaryRoot, fixture.sourceRoot), { recursive: true, force: true })
    expectRejected(temporaryRoot, /claimed source_root is missing/)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})

test('rejects multiple locks claiming one imported root', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-duplicate-lock-'))
  try {
    const fixture = createAnchoredImport(temporaryRoot)
    writeJson(join(temporaryRoot, 'security', 'duplicate.lock.json'), fixture.lock)
    expectRejected(temporaryRoot, /multiple locks claim source_root apps\/electerm-web/)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})

test('fixtures remain inert data until copied into a temporary repository', () => {
  for (const fixture of ['forbidden-lifecycle', 'mirror-url', 'floating-version', 'unsupported-lockfile']) {
    const content = readFileSync(join(fixtureRoot, fixture, 'README.fixture'), 'utf8')
    assert.match(content, /fixture/i)
  }
})
