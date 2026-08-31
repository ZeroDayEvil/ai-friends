import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import test from 'node:test'

import {
  analyzeDocuments,
  parseTarGz,
  scanPackageArchive,
  stableStringify,
  verifyIntegrity
} from './npm-audit-electerm-web.mjs'

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')

function fixtureJson (name) {
  return JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'))
}

function tarOctal (value, width) {
  return Buffer.from(`${value.toString(8).padStart(width - 1, '0')}\0`, 'ascii')
}

function tarEntry (filePath, content, type = '0', headerSize = null) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content)
  const header = Buffer.alloc(512)
  header.write(filePath, 0, 100, 'utf8')
  tarOctal(0o644, 8).copy(header, 100)
  tarOctal(0, 8).copy(header, 108)
  tarOctal(0, 8).copy(header, 116)
  tarOctal(headerSize ?? body.byteLength, 12).copy(header, 124)
  tarOctal(0, 12).copy(header, 136)
  header.fill(0x20, 148, 156)
  header.write(type, 156, 1, 'ascii')
  header.write('ustar\0', 257, 6, 'ascii')
  header.write('00', 263, 2, 'ascii')
  const checksum = [...header].reduce((sum, byte) => sum + byte, 0)
  Buffer.from(`${checksum.toString(8).padStart(6, '0')}\0 `, 'ascii').copy(header, 148)
  const padding = Buffer.alloc((512 - (body.byteLength % 512)) % 512)
  return Buffer.concat([header, body, padding])
}

function tarGz (entries) {
  const tar = Buffer.concat([
    ...entries.map(entry => tarEntry(entry.path, entry.content, entry.type, entry.headerSize)),
    Buffer.alloc(1024)
  ])
  return gzipSync(tar, { level: 9, mtime: 0 })
}

function nativeArchive () {
  const fixture = fixtureJson('npm-audit-archive-native.json')
  return tarGz(fixture.files.map(file => ({
    path: file.path,
    content: file.contentBase64
      ? Buffer.from(file.contentBase64, 'base64')
      : Buffer.from(file.text)
  })))
}

function sri512 (buffer) {
  return `sha512-${createHash('sha512').update(buffer).digest('base64')}`
}

function paxRecord (key, value) {
  const payload = `${key}=${value}\n`
  let length = Buffer.byteLength(payload) + 2
  while (Buffer.byteLength(`${length} ${payload}`) !== length) {
    length = Buffer.byteLength(`${length} ${payload}`)
  }
  return Buffer.from(`${length} ${payload}`)
}

function preparedFixtures () {
  const packageJson = fixtureJson('npm-audit-package-v3.json')
  const lockfile = fixtureJson('npm-audit-lock-v3.json')
  const metadata = fixtureJson('npm-audit-registry-v3.json')
  const archive = nativeArchive()
  const integrity = sri512(archive)
  lockfile.packages['node_modules/native-pkg'].integrity = integrity
  metadata['native-pkg@1.0.0'].dist.integrity = integrity
  return { packageJson, lockfile, metadata, archive }
}

test('audits lockfile v3 risks and a hostile native package without network', async () => {
  const fixtures = preparedFixtures()
  const manifest = await analyzeDocuments(fixtures.packageJson, fixtures.lockfile, {
    fixtureMetadata: fixtures.metadata,
    fixtureArchives: {
      'native-pkg@1.0.0': fixtures.archive
    },
    scanTarballs: 'all'
  })
  const entries = new Map(manifest.entries.map(entry => [entry.name, entry]))

  assert.equal(manifest.target.observedLockfileVersion, 3)
  assert.equal(manifest.target.sourceLockfileVersionMismatch, false)
  assert.equal(manifest.counts.manifestEntries, 6)
  assert.equal(manifest.counts.packagePathEntries, 6)
  assert.equal(manifest.counts.legacyRootDependencyEntries, 0)
  assert(entries.get('mirror-pkg').riskFlags.includes('non-official-resolved-host'))
  assert(entries.get('mirror-pkg').riskFlags.includes('floating-declared-spec'))
  assert(entries.get('missing-integrity').riskFlags.includes('missing-lock-integrity'))
  assert.equal(entries.get('missing-integrity').license, 'MIT')
  assert.equal(entries.get('missing-integrity').licenseSource, 'registry.npmjs.org')
  assert(entries.get('lifecycle-pkg').riskFlags.includes('git-or-url-declared-source'))
  assert(entries.get('lifecycle-pkg').riskFlags.includes('has-lifecycle-script'))
  assert.equal(entries.get('lifecycle-pkg').lifecycleScripts.postinstall, 'node scripts/download.js')
  assert(entries.get('forbidden-license').riskFlags.includes('forbidden-license'))
  assert.equal(entries.get('forbidden-license').licenseSource, 'registry.npmjs.org')

  const native = entries.get('native-pkg')
  assert.equal(native.sourceRepository, 'https://github.com/example/native-pkg')
  assert.deepEqual(native.cpu, ['x64'])
  assert.deepEqual(native.os, ['win32'])
  assert(native.riskFlags.includes('native-code'))
  assert(native.riskFlags.includes('bundled-node-addon'))
  assert(native.riskFlags.includes('install-time-network-indicator'))
  assert(native.riskFlags.includes('child-process-indicator'))

  const review = manifest.sourceReviews.find(item => item.packageId === 'native-pkg@1.0.0')
  assert.equal(review.archive.integrityVerified, true)
  assert.equal(review.archive.binaries[0].kind, 'node-addon')
  assert.equal(review.archive.licenseFiles[0].path, 'package/LICENSE')
  assert.equal(review.archive.installTimeNetwork[0].file, 'package/install.js')
})

test('produces deterministic JSON for identical fixtures', async () => {
  const fixtures = preparedFixtures()
  const options = {
    fixtureMetadata: fixtures.metadata,
    fixtureArchives: {
      'native-pkg@1.0.0': fixtures.archive
    },
    scanTarballs: 'all'
  }
  const first = await analyzeDocuments(fixtures.packageJson, fixtures.lockfile, options)
  const second = await analyzeDocuments(fixtures.packageJson, fixtures.lockfile, options)
  assert.equal(stableStringify(first), stableStringify(second))
  assert.deepEqual(JSON.parse(stableStringify(first)), JSON.parse(stableStringify(second)))
})

test('rejects malformed lockfiles', async () => {
  const packageJson = fixtureJson('npm-audit-package-v3.json')
  const lockfile = fixtureJson('npm-audit-lock-malformed.json')
  await assert.rejects(
    analyzeDocuments(packageJson, lockfile, { fixtureMetadata: {} }),
    /Lockfile has no packages object/
  )
})

test('rejects traversal, symlink, and device archive entries', () => {
  assert.throws(
    () => parseTarGz(tarGz([{ path: 'package/../escape.js', content: 'x' }])),
    /Unsafe archive path/
  )
  assert.throws(
    () => parseTarGz(tarGz([{ path: 'package/link', content: '', type: '2' }])),
    /Rejected link or device/
  )
  assert.throws(
    () => parseTarGz(tarGz([{ path: 'package/device', content: '', type: '3' }])),
    /Rejected link or device/
  )
})

test('applies validated PAX size overrides', () => {
  const content = Buffer.alloc(2048, 0x61)
  const result = parseTarGz(tarGz([
    { path: 'PaxHeader', content: paxRecord('size', '2048'), type: 'x' },
    { path: 'package/file.js', content, headerSize: 0 }
  ]))
  assert.equal(result.entries[0].size, 2048)
  assert(result.entries[0].content.equals(content))
})

test('selects and validates the shallow archive-root package manifest', () => {
  const archive = tarGz([
    {
      path: 'package/dist/commonjs/package.json',
      content: '{"name":"nested","version":"9.9.9"}'
    },
    {
      path: 'package/package.json',
      content: '{"name":"root-pkg","version":"1.2.3","scripts":{"install":"node install.js"}}'
    },
    {
      path: 'package/install.js',
      content: 'console.log("fixture")'
    }
  ])
  const result = scanPackageArchive(archive, {
    expectedName: 'root-pkg',
    expectedVersion: '1.2.3'
  })
  assert.equal(result.packageManifestPath, 'package/package.json')
  assert.equal(result.lifecycleScripts.install, 'node install.js')
  assert.throws(
    () => scanPackageArchive(archive, { expectedName: 'wrong-name' }),
    /Expected wrong-name, found root-pkg/
  )
})

test('rejects competing archive roots and decoy manifests', () => {
  const archive = tarGz([
    {
      path: 'package.json',
      content: '{"name":"root-pkg","version":"1.2.3"}'
    },
    {
      path: 'package/package.json',
      content: '{"name":"root-pkg","version":"1.2.3","scripts":{"install":"node install.js"}}'
    },
    {
      path: 'package/install.js',
      content: "fetch('https://registry.npmjs.org/root-pkg')"
    }
  ])
  assert.throws(
    () => scanPackageArchive(archive, {
      expectedName: 'root-pkg',
      expectedVersion: '1.2.3'
    }),
    /Archive path is outside package\//
  )
})

test('detects installer networking after generic evidence truncation', () => {
  const noise = Array.from(
    { length: 100 },
    (_, index) => `fetch('https://registry.npmjs.org/noise-${index}')`
  ).join('\n')
  const archive = tarGz([
    {
      path: 'package/package.json',
      content: '{"name":"network-pkg","version":"1.0.0","scripts":{"install":"node install.js"}}'
    },
    {
      path: 'package/noise.js',
      content: noise
    },
    {
      path: 'package/install.js',
      content: "https.get('https://registry.npmjs.org/network-pkg')"
    }
  ])
  const result = scanPackageArchive(archive, {
    expectedName: 'network-pkg',
    expectedVersion: '1.0.0'
  })
  assert.equal(result.sourceSignals.networkApi.count, 101)
  assert.equal(result.sourceSignals.networkApi.truncated, true)
  assert.equal(result.installTimeNetworkCount, 1)
  assert.equal(result.installTimeNetwork[0].file, 'package/install.js')
})

test('requires and verifies dist.integrity', () => {
  const archive = nativeArchive()
  assert.equal(verifyIntegrity(archive, sri512(archive)).verified, true)
  assert.throws(() => verifyIntegrity(archive, null), /No dist.integrity/)
  assert.throws(
    () => verifyIntegrity(archive, `sha512-${Buffer.alloc(64).toString('base64')}`),
    /do not match dist.integrity/
  )
  const downgraded = [
    `sha512-${Buffer.alloc(64).toString('base64')}`,
    `sha1-${createHash('sha1').update(archive).digest('base64')}`
  ].join(' ')
  assert.throws(() => verifyIntegrity(archive, downgraded), /do not match dist.integrity/)
})

test('does not permit CLI input overrides', () => {
  const result = spawnSync(process.execPath, [
    join(dirname(fileURLToPath(import.meta.url)), 'npm-audit-electerm-web.mjs'),
    '--package-json',
    join(FIXTURES, 'npm-audit-package-v3.json')
  ], { encoding: 'utf8' })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /Unknown argument: --package-json/)
})
