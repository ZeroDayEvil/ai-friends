import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { cpSync, mkdtempSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
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

function externalRegister () {
  return {
    version: 1,
    generated: '2026-08-30',
    items: [
      {
        id: 'electerm-web',
        kind: 'git',
        official_source: 'https://github.com/electerm/electerm-web',
        pin: 'commit:f1deaf02fead7faa1bfb4381f69fbb734ea7f95f',
        license: 'MIT',
        verdict: 'pin'
      }
    ]
  }
}

function prepareFixture (fixture) {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-'))
  mkdirSync(join(temporaryRoot, 'security'), { recursive: true })
  writeFileSync(join(temporaryRoot, 'security', 'externals.json'), JSON.stringify(externalRegister()))
  writeFileSync(
    join(temporaryRoot, 'security', 'policy-exceptions.json'),
    JSON.stringify(emptyExceptions)
  )

  const source = join(fixtureRoot, fixture)
  cpSync(source, temporaryRoot, { recursive: true })
  for (const file of [
    join(temporaryRoot, 'apps', 'fixture', 'package.json.fixture'),
    join(temporaryRoot, 'apps', 'fixture', 'package-lock.json.fixture'),
    join(temporaryRoot, 'apps', 'fixture', 'yarn.lock.fixture')
  ]) {
    try {
      const target = file.slice(0, -'.fixture'.length)
      renameSync(file, target)
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
  }
  return temporaryRoot
}

function expectRejected (fixture, message) {
  const temporaryRoot = prepareFixture(fixture)
  try {
    const result = spawnSync(process.execPath, [checker], {
      cwd: temporaryRoot,
      encoding: 'utf8'
    })
    assert.equal(result.status, 1, result.stdout + result.stderr)
    assert.match(result.stderr, message)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
}

test('rejects an unapproved lifecycle script under apps', () => {
  expectRejected('forbidden-lifecycle', /lifecycle script "postinstall" is not approved/)
})

test('rejects a registry mirror under apps', () => {
  expectRejected('mirror-url', /disallowed registry host registry\.npmmirror\.com/)
})

test('rejects a floating dependency version under apps', () => {
  expectRejected('floating-version', /floating or URL dependency dependencies\.example=\^1\.2\.3/)
})

test('rejects an unsupported package-manager lockfile under apps', () => {
  expectRejected('unsupported-lockfile', /unsupported package-manager lockfile/)
})

function gitBlobSha1 (bytes) {
  return createHash('sha1')
    .update(`blob ${bytes.length}\0`)
    .update(bytes)
    .digest('hex')
}

function gitTreeSha1 (entries) {
  const content = Buffer.concat(entries.map(entry => Buffer.concat([
    Buffer.from(`${entry.mode} ${entry.name}\0`),
    Buffer.from(entry.sha, 'hex')
  ])))
  return createHash('sha1')
    .update(`tree ${content.length}\0`)
    .update(content)
    .digest('hex')
}

function runGit (temporaryRoot, args) {
  const result = spawnSync('git', args, {
    cwd: temporaryRoot,
    encoding: 'utf8'
  })
  assert.equal(result.status, 0, result.stdout + result.stderr)
}

test('rejects force-added files under an explicit generated/vendor exception', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'check-pins-index-'))
  try {
    const sourceRoot = join(temporaryRoot, 'apps', 'electerm-web')
    mkdirSync(join(sourceRoot, 'node_modules'), { recursive: true })
    const readme = Buffer.from('fixture upstream source\n')
    const readmeSha256 = createHash('sha256').update(readme).digest('hex')
    const readmeBlob = gitBlobSha1(readme)
    writeFileSync(join(sourceRoot, 'README'), readme)
    writeFileSync(join(sourceRoot, 'node_modules', 'injected.js'), 'export default 1\n')
    mkdirSync(join(temporaryRoot, 'security'))
    writeFileSync(join(temporaryRoot, 'security', 'externals.json'), JSON.stringify(externalRegister()))
    writeFileSync(join(temporaryRoot, 'security', 'policy-exceptions.json'), JSON.stringify({
      ...emptyExceptions,
      ignored_tree_paths: [
        {
          path: 'apps/electerm-web/node_modules',
          kind: 'vendor',
          reason: 'Fixture-only generated dependency output.'
        }
      ]
    }))
    writeFileSync(join(temporaryRoot, 'security', 'upstream.lock.json'), JSON.stringify({
      version: 1,
      source_root: 'apps/electerm-web',
      upstream: {
        repository: 'https://github.com/electerm/electerm-web',
        commit: 'f1deaf02fead7faa1bfb4381f69fbb734ea7f95f',
        tree_sha1: gitTreeSha1([{ mode: '100644', name: 'README', sha: readmeBlob }]),
        archive_sha256: 'a'.repeat(64),
        archive_regular_file_count: 1
      },
      license_identity: { spdx_id: 'MIT' },
      files: [
        {
          path: 'README',
          mode: '100644',
          size: readme.length,
          sha256: readmeSha256,
          git_blob_sha1: readmeBlob
        }
      ]
    }))
    runGit(temporaryRoot, ['init', '-q'])
    runGit(temporaryRoot, ['add', 'apps/electerm-web/README'])
    runGit(temporaryRoot, ['add', '-f', 'apps/electerm-web/node_modules/injected.js'])
    const result = spawnSync(process.execPath, [checker], {
      cwd: temporaryRoot,
      encoding: 'utf8'
    })
    assert.equal(result.status, 1, result.stdout + result.stderr)
    assert.match(result.stderr, /tracked files are forbidden below ignored generated\/vendor path/)
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
})
