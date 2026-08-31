# npm dependency audit: electerm-web 5.3.15

Audit date: 2026-08-30

Upstream commit: `f1deaf02fead7faa1bfb4381f69fbb734ea7f95f`

Mode: static data and source review only

## Conclusion

This review found **no confirmed malicious behavior** in the inspected npm
artifacts. It also cannot prove that the dependency tree or bundled binaries
are benign. The confirmed findings below are supply-chain and privilege risks,
not attribution of a prior infection.

The tree is not ready for a trusted first build. The immediate blockers are the
53 lockfile paths resolved through `registry.npmmirror.com`, four install-script
packages that need an explicit build policy, unreviewed native/WASM payloads,
an unresolved LGPL distribution review, and unsafe repository-owned runtime
loading, extension, and MCP defaults.

The machine-readable result is
[`security/manifests/npm-audit-electerm-web-5.3.15-f1deaf02.json`](../../security/manifests/npm-audit-electerm-web-5.3.15-f1deaf02.json).

## Pinned inputs and the 1,582-record count

Only these two upstream documents were used:

| Input | Official pinned URL | Bytes | SHA-256 |
|---|---|---:|---|
| `package.json` | `https://raw.githubusercontent.com/electerm/electerm-web/f1deaf02fead7faa1bfb4381f69fbb734ea7f95f/package.json` | 4,739 | `edb4199c3a30b5fcc8a2856a949161f95aa5c162b4605207ddb8e3ffcbabd61a` |
| `package-lock.json` | `https://raw.githubusercontent.com/electerm/electerm-web/f1deaf02fead7faa1bfb4381f69fbb734ea7f95f/package-lock.json` | 720,137 | `3a2953e0c45f4c942ba826b7ea915e5ad24e56bb31d35828954859ec84d5113c` |

The pinned package version is `5.3.15`. Contrary to the expected v3 input, the
official lockfile at this commit declares `lockfileVersion: 2`. It contains:

- 847 `packages` records, including the root;
- 735 top-level legacy `dependencies` records;
- 1,582 serialized records in total.

The manifest retains both representations and labels each record with
`entryKind`; it does not conceal the duplication or rewrite upstream data.
The analyzer supports lockfile v2 and v3, and its offline fixture exercises v3.

## Safe collection method

The analyzer:

1. accepts the two exact commit-pinned GitHub inputs;
2. requests version metadata and tarballs only from
   `https://registry.npmjs.org`;
3. uses bounded concurrency, request spacing, response-size limits, and an
   external cache;
4. requires and verifies registry `dist.integrity` before caching or parsing a
   tarball, then also verifies every lockfile integrity value for that
   coordinate;
5. decompresses and parses tar records in memory without filesystem extraction;
6. rejects traversal, absolute/drive/backslash paths, symlinks, hardlinks,
   devices, FIFOs, unknown tar entry types, invalid checksums, oversized gzip
   output, and excessive file counts;
7. records missing metadata as unknown instead of inventing defaults.

No `npm install`, `npm ci`, `npm pack`, `npm audit`, package command, lifecycle
script, downloaded JavaScript, native addon, executable, or WASM module was
run.

## Inventory and coverage

| Measure | Count |
|---|---:|
| Manifest records | 1,582 |
| Package-path records | 847 |
| Non-root package paths | 846 |
| Legacy top-level dependency records | 735 |
| Unique registry name/version coordinates | 805 |
| Direct runtime package paths | 42 |
| Direct development package paths | 37 |
| Runtime-reachable package paths | 259 |
| Development-reachable package paths | 638 |
| Coordinates with registry metadata | 805 |
| Integrity-verified, safely parsed tarballs | 805 |
| Blocked tarballs | 0 |
| Mirror-resolved package paths | 53 |
| Package paths with lifecycle scripts | 300 |
| Package paths with install scripts | 4 |
| Bundled `.node` files | 47 |
| Bundled PE/ELF/Mach-O files | 11 |
| Bundled WASM files | 3 |

The 805 tarballs total 217,559,515 compressed bytes and 673,012,224 expanded
bytes. The parser inventoried 38,098 files, statically scanned 30,944 source
files, recorded 775 license files, and retained 6,309 external-URL records.
Another 619 source-like files were skipped because they were large, minified,
generated, test, documentation, or fixture material.

Coverage tiers in the manifest are:

- **371 focused static-signal reviews:** every direct-runtime,
  lifecycle-script, native-indicator, or high-privilege-name coordinate;
- **434 automated archive-signal reviews:** remaining transitive coordinates;
- **0 metadata-only or blocked coordinates.**

This is broad static signal coverage, **not** a claim that every transitive
source line was manually audited.

## Confirmed supply-chain behavior

### Unofficial lockfile mirror

The lockfile has 53 package paths (47 unique coordinates) whose `resolved` URL
uses `registry.npmmirror.com`; the complete list is queryable from
`entries[].resolvedHost`. All 47 corresponding official-registry tarballs
matched both `dist.integrity` and the lockfile integrity during this audit.
That match found no byte divergence at review time, but the mirror remains an
unapproved download authority and the lockfile must not be used as-is.

### Install-time execution

| Package | Reachability | Script body | Static result |
|---|---|---|---|
| `electerm-web@5.3.15` | root | `install: node build/bin/install` | Pinned `build/bin/install.js` uses `shelljs` to remove and copy the `@electerm/electerm-react/client` tree; no network call was found. |
| `@serialport/bindings-cpp@13.0.0` | runtime transitive | `install: node-gyp-build` | Selects one of 13 bundled `.node` prebuilds. No package-authored download path was found; the build fallback can invoke `node-gyp`. |
| `fsevents@2.3.3` | optional development transitive | registry/lock install behavior: `node-gyp rebuild` | Contains one bundled macOS `.node` file. It is not runtime-reachable in this tree. |
| `node-pty@1.2.0-beta.15` | direct runtime | `install: node scripts/prebuild.js \|\| node-gyp rebuild`; `postinstall: node scripts/post-install.js` | The first script selects local prebuilds or falls back to compilation. The second cleans build output and copies bundled ConPTY files. No install-time network call was found. |

The manifest also records non-install lifecycle bodies. Across distinct package
IDs it found 87 `prepare`, 249 `prepublishOnly`, and 130 `prepublish` scripts;
these counts overlap.

### Runtime npm loader and dynamic imports

At the pinned commit:

- `src/app/lib/npm.js:8-23` permits `NPM_REGISTRY` to replace the default
  registry, requests mutable `latest` metadata, streams the returned tarball,
  and extracts it without verifying integrity;
- `src/app/lib/npm.js:35-62` recursively downloads declared dependencies;
- `src/app/lib/custom-require.js:25-61` downloads missing packages and imports
  their entry point dynamically.

Static `git grep` found only the `customRequire` definition in this commit, not
an active call site. The mechanism is therefore a dormant but unsafe runtime
code-loading surface, not evidence that a package was actually downloaded.

### Config extensions

`src/app/lib/conf.js:11-26` dynamically imports local `config.js`.
`src/app/lib/extensions.js:8-16` invokes each configured `appExtend` callback
with the live Express application and authentication middleware. This is
repository-owned arbitrary extension code; it has no dedicated npm dependency
closure to remove.

### MCP server

The MCP implementation is repository-owned and uses the already-required
`express` package:

- the default bind address is loopback (`127.0.0.1`);
- the API key default is empty and authentication is skipped when it is empty;
- the command tool accepts shell command strings, controlled by a denylist and
  an optional user allowlist;
- MCP can expose terminal execution, SFTP, bookmarks, and settings.

These facts make accidental rebinding or weak configuration high impact. They
do not establish malicious behavior. Preserve MCP by requiring authentication,
retaining loopback-only binding, and making a narrow allowlist mandatory; do
not remove shared `express`/HTTP functionality.

### Cloud sync

The verified archives contain these operational endpoints:

- `electerm-sync@2.0.1`: `https://api.github.com` and
  `https://gitee.com/api/v5`;
- `gist-wrapper@1.0.0`: `https://api.github.com`;
- `gitee-client@1.0.0`: `https://gitee.com/api`.

They are expected implementation behavior, but they move synced data outside
the controlled perimeter.

## High-risk review list

“High risk” here means high privilege, install-time execution, native payload,
or mutable/external loading. It does not mean malicious.

| Surface | Packages |
|---|---|
| Install/native runtime | `node-pty@1.2.0-beta.15`, `serialport@13.0.0`, `@serialport/bindings-cpp@13.0.0`, `font-list@1.5.1` |
| Remote access and command execution | `@electerm/ssh2@1.22.0`, `ssh2-scp@3.2.1`, `ssh-config-loader@1.1.2`, `node-bash@5.0.1` |
| FTP/SFTP and proxying | `@electerm/ftp-srv@1.0.5`, `basic-ftp@6.0.1`, `socks@2.8.9`, `socks-proxy-agent@8.0.1`, `socksv5-server@1.0.2`, `https-proxy-agent@7.0.1` |
| HTTP/auth/upload | `express@5.2.1`, `express-jwt@8.5.1`, `express-ws@5.0.2`, `jsonwebtoken@9.0.3`, `multer@2.2.0` |
| Runtime loading and sync | `tar@7.5.22`, `electerm-sync@2.0.1`, `gist-wrapper@1.0.0`, `gitee-client@1.0.0` |
| RDP/VNC/SPICE build inputs | `ironrdp-wasm@1.1.0`, `@novnc/novnc@1.7.0`, `spice-client@1.2.0` |
| Native build toolchain | `fsevents@2.3.3`, the `@rolldown/binding-*` packages, the `lightningcss-*` packages, `source-map@0.7.4` |

Notable static evidence:

- `node-pty` bundles 8 Node addons and 10 PE/Mach-O paths, including duplicate
  ConPTY DLL/EXE payloads; every path and SHA-256 is in `sourceReviews`.
- `@serialport/bindings-cpp` bundles 13 platform prebuilds.
- `font-list` bundles a 168,560-byte Mach-O executable and invokes platform
  subprocesses.
- `ironrdp-wasm` bundles a 4,106,629-byte WASM module.
- `@electerm/ssh2` contains legitimate SSH command/agent process paths, a
  `new Function` feature probe, and generated cryptographic loader code.
- No archive showed a confirmed install-time network request. Local prebuild
  selection is recorded separately from actual prebuilt-download logic.

## Licenses and deprecations

No package matched the analyzer fixture-tested forbidden-license policy, and no
coordinate remains license-unknown after normalizing both modern `license` and
legacy `licenses[].type` registry declarations. This does not settle
distribution compatibility: `spice-client@1.2.0` declares
`LGPL-3.0-or-later` and requires a separate distribution/linking review.
License file paths and hashes are inventoried, but their full legal meaning was
not inferred automatically.

Eight distinct coordinates have registry deprecation notices:
`@humanwhocodes/config-array@0.11.11`,
`@humanwhocodes/object-schema@1.2.1`,
`@ungap/structured-clone@1.2.1`, `eslint@8.50.0`,
`inflight@1.0.6`, `glob@7.2.3`, `glob@10.5.0`, and `rimraf@3.0.2`.
The `@ungap/structured-clone` notice specifically requests 1.3.1 or newer for
potential CWE-502.

## Dependency closures removed by safer replacements

The calculation removes only named direct roots, recomputes reachability from
all retained runtime and build roots, and keeps shared AI/MCP/HTTP/FTP
dependencies.

| Replacement | Packages that disappear |
|---|---|
| Self-hosted cloud sync replaces GitHub/Gitee adapters | `electerm-sync@2.0.1`, `gist-wrapper@1.0.0`, `gitee-client@1.0.0` |
| Reviewed bundled extension catalog replaces runtime npm extraction | `tar@7.5.22`, `@isaacs/fs-minipass@4.0.1`, `chownr@3.0.0`, `minizlib@3.1.0`, `yallist@5.0.0` |
| Arbitrary `config.js` extension hook is replaced in repository code | No npm package disappears |
| MCP is hardened while shared HTTP stays | No npm package disappears; `express` remains |
| `node-bash` filesystem helper is replaced with argument-vector subprocesses | `node-bash@5.0.1`, `child-shell@5.0.0`, `accumulate-stream@5.0.0`, `kind-of@6.0.3`, `nanoid@3.3.12`, `p-finally@1.0.0`, `p-queue@6.6.2`, `eventemitter3@4.0.7`, `p-timeout@3.2.0`, `p-timeout@4.1.0`, `trim-buffer@5.0.0` |

`axios` remains because AI and other HTTP behavior share it. FTP, SSH,
RDP/VNC/SPICE, HTTP, and MCP package roots remain unless their functionality is
reimplemented separately.

## Remaining blockers to a first build

1. Produce and review a real lockfile v3 that uses only
   `registry.npmjs.org`; preserve exact versions and verified integrities.
2. Define an install-script allowlist. Replace the root copy hook with an
   explicit build step, and either reproduce native artifacts in trusted CI or
   approve exact prebuild hashes per platform.
3. Reverse-engineer or reproducibly rebuild the 47 Node addons, 11 native
   executables, and 3 WASM files. Integrity proves identity, not safety.
4. Remove the runtime npm loader and arbitrary config extension hook, then
   harden MCP authentication, binding, and command policy before deployment.
5. Resolve the `spice-client` LGPL distribution/linking obligations and review
   the retained license-file inventory.
6. Review the eight deprecated coordinates and run a separately pinned,
   non-executing vulnerability-database scan. `npm audit` was intentionally not
   run.
7. Perform a clean build only after the preceding controls exist. This audit
   did not execute install hooks or prove that `--ignore-scripts` plus explicit
   native steps produces a working application.

Additional limits: native/WASM behavior was not reverse engineered; generated
and minified code did not receive complete manual line review; registry
metadata is mutable even though its response hashes are recorded; and one
development peer edge (`react-markdown` to absent `@types/react`) remains
unresolved. These limits are evidence gaps, not malicious findings.

## Reproduction

Networked collection, using an external cache:

```text
node scripts/security/npm-audit-electerm-web.mjs --scan-tarballs all --cache-dir <external-cache>
```

Deterministic cached regeneration:

```text
node scripts/security/npm-audit-electerm-web.mjs --offline --scan-tarballs all --cache-dir <external-cache>
```

Offline fixture tests:

```text
node --test scripts/security/npm-audit-electerm-web.test.mjs
```

The fixtures cover an unofficial mirror, missing integrity, install lifecycle
body, floating/git declaration, forbidden license, bundled native binary,
malformed lockfile, integrity mismatch, traversal, symlink, and device entry.
