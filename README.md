# Black Duck SCA AOSP scan utility - bd_aosp_scan v0.17

Creates a Black Duck SCA project version from AOSP (Android Open Source Project) build artifacts. Platform repos and external third-party packages are uploaded separately, each with their own matching strategy; Custom (Black Duck) components can be created where upstream OSS packages cannot be identified, with CPE specified to map CVEs where available.

Black Duck SCA 2026.7 provides new capabilities to provide a CPE for custom components for 3rd party vulnerability reporting. Ensure you are using this version for complete vulnerability identification and reporting.

## AOSP Introduction

AOSP builds download source code from https://android.googlesource.com.

AOSP comprises:
*	About 400 standard AOSP packages
*	About 500 external packages forked into android.googlesource.com repos with METADATA files
    - Repos are forked from github (60%) or elsewhere

Not all repos are built/included in an Android release.

Android Security Bulletins are provided by Google referencing CVEs but all are created with the same CPE with vendor 'google' and package 'android'. CPE version strings do not match the versioning used in the AOSP repos ('16.0' versus 'android_16.0.0_r4' for example).

## BD Scan Utility - Principles

A complete BOM of the built packages is the optimal outcome – optionally creating Custom Components (with CPEs associated and appropriate licences) for unmatched packages. Unbuilt packages will not be included in the BOM.

Standard AOSP packages have no vulnerabilities reported (as none exist). If custom components are created for unmatched AOSP standard packages, they will have Apache-2.0 license.

A Google/Android custom component can optionally be created to show CVEs reported in the Android Security Bulletins (requires BD-SCA 2026.7 or later).

The primary assumption is that determining up-stream origins for licence and vulnerability identification will add value for external packages. Analysis shows that many packages potentially have unpatched vulnerabilities from the origin OSS package. Furthermore, the origin licence may not agree with the licences reported in the AOSP forks, and deep license analysis may identify embedded and other licences of interest.

External packages can optionally be scanned:
-	Using the upstream origin as component ID where identifiable
-	By looking up CPEs in the BD KB to find associated components
-	By creating custom components for unmatched components with CPE where available (and licences from the source repo configuration)
-	By Signature scanning where no other identification is successful.

Custom Components are global, so once created they can change the scan result for subsequent scans. Care should be used when creating custom components (the scan script does not create them by default)

## Why External Repo Scan Modes Exist

AOSP incorporates hundreds of third-party open-source projects under `external/`. These repos are forks — copied into the Android source tree from upstream projects hosted on GitHub, GitLab, or elsewhere. Each fork may pin a specific tagged release, a commit hash, or an arbitrary snapshot, and the connection to the original upstream project is recorded (when it is recorded at all) in a `METADATA` file within the repo.

In practice, many of these `METADATA` files are missing, incomplete, or inaccurate:

- Some repos have no `METADATA` file at all (~20%)
- Some reference a GitHub URL but provide only a commit hash, not a release tag (~20%)
- Some list a CPE (Common Platform Enumeration) identifier but no source URL (~8%)
- Some contain stale or incorrect version information that no longer matches the actual code in the repo (~5%)

This means there is no single reliable method to determine the upstream source and version of every external repo. Different scan modes exist to apply progressively deeper inspection strategies according to requirements.

### Why Identifying Upstream Sources Matters for External Repos

Mapping each forked external repo back to its original upstream project is critical for several reasons:

- **Vulnerability detection beyond the Android Security Bulletin.** The Android Security Bulletin covers vulnerabilities found and patched within AOSP itself, but upstream projects may have disclosed CVEs that are not yet addressed in the AOSP fork. Associating each repo with its upstream component in the Black Duck KnowledgeBase enables continuous monitoring for these vulnerabilities.

- **License validation.** AOSP repos contain `NOTICE` and license classification files, but these may not reflect the full licensing terms of the upstream project. Identifying the upstream source allows Black Duck to perform deep license and copyright detection against the original project, validating that the license declarations in the AOSP repo are complete and accurate.

- **License compliance.** Some upstream projects use licenses with specific obligations (attribution, source disclosure, copyleft). Accurate upstream identification ensures these obligations are tracked and met.

## Prerequisites

- **Python 3.6+**
- **AOSP build artifacts:**
  - `module-info.json` — generated by the AOSP build system (typically at `out/target/product/<device>/module-info.json`)
  - `repo-list.txt` — output of `repo list` from the AOSP source root
- **Black Duck SCA server** (recommended version 2026.7 or later) — required for SBOM upload
- **Black Duck API token** — generated from the Black Duck UI under User > API Tokens - requires global Component Manager role to create custom components
- **curl** — required on the system PATH for signature scanning (downloads the Detect script)

## Configuration

Black Duck connection settings can be provided as command-line arguments or environment variables:

| Setting | Argument | Environment Variable |
|---|---|---|
| API token | `--bd-api-token` | `BLACKDUCK_API_TOKEN` |
| Server URL | `--bd-url` | `BLACKDUCK_URL` |
| Trust server certificate | `--bd-trust-cert` | `BLACKDUCK_TRUST_CERT` (`1`, `true`, or `yes`) |
| GitHub API token | `--github-token` | `GITHUB_TOKEN` |

The Github Token is required to examine GH repos to match commit IDs used in AOSP against versions/tags mapped in Black Duck SCA.
If not specified, then the Github lookup will use the free API tier which only allows a limited number of requests.

## Usage

### Required Arguments

```
--module-info PATH        Path to module-info.json from the AOSP build
--repo-list PATH          Path to repo-list.txt from 'repo list'
--android-version VER     Android version string (e.g. android-16.0.0_r4)
--bd-project NAME         Black Duck project name
--bd-version VER          Black Duck project version
```

### Optional Arguments

```
--version                 Show program version and exit
--aosp-root PATH          Path to AOSP source root (for reading METADATA files
                          and signature scanning)
--metadata-dir PATH       Directory containing METADATA files (one per package).
                          Overrides --aosp-root for metadata lookup.
--bd-api-token TOKEN      Black Duck API token (can also use $BLACKDUCK_API_TOKEN value)
--bd-url URL              Black Duck server URL (can also use $BLACKDUCK_URL value)
--bd-trust-cert           Trust the Black Duck server's SSL certificate (can also use $BLACKDUCK_TRUST_CERT value)
--github-token TOKEN      GitHub API token for higher rate limits (default: 60
                          requests/hour without a token)
--external-scan-modes M   Comma-separated scan modes or preset (see below).
                          Default: NONE (platform repos only)
--create-custom-components  Enable autocreate to create custom components for
                          unmatched packages (requires Component Manager role)
--skip-upload             Generate SBOM files but do not upload to Black Duck
--list-packages           List package classification and exit
--debug                   Enable debug logging
```

### External Scan Modes

The `--external-scan-modes` argument controls which resolution strategies are applied to external packages. Specify a comma-separated list of modes or a preset name.

Although any combination of modes can be used to scan external repos, the GITHUB_REPOS mode is fundamental to matching upstream OSS packages (and is recommended).
Many external repos are forked from Github but only reference a commit ID. The GH API can be used to lookup the closest version/tag for full identification; GH rate-limiting
means that a (readonly) GitHub API token (--github-token) is required to support full analysis.

**Individual modes:**

| Mode | Description |
|---|---|
| `GITHUB_REPOS` | Resolve commit-hash packages to tagged releases via the GitHub API (recommended --github-token is also specified) |
| `KB_LOOKUP` | Look up commit-hash packages in the Black Duck KnowledgeBase by component and release date |
| `CPE_LOOKUP` | Resolve packages with CPE identifiers against the Black Duck KnowledgeBase |
| `SIG_SCAN` | Run Black Duck Detect signature scanning on unmatched external repos |
| `CUSTOM_COMPS` | Allow custom component creation for unmatched packages (also requires `--create-custom-components`) |

**Presets:**

| Preset | Modes |
|---|---|
| `DEFAULT` | `GITHUB_REPOS`, `KB_LOOKUP`, `CPE_LOOKUP`, `CUSTOM_COMPS` |
| `ALL` | All modes |
| `NONE` | No external repo processing (platform repos are processed) |

Modes can be combined: `--external-scan-modes 'GITHUB_REPOS,CPE_LOOKUP,CUSTOM_COMPS'`

### Examples

**Run prerequisites:**

```bash

repo list > repo-list.txt

export BLACKDUCK_API_TOKEN="your-api-token"
export BLACKDUCK_URL="https://your-blackduck-server.com"
#export BLACKDUCK_TRUST_CERT=true
```

**Full BOM resolution with GitHub, KB, CPE Lookup & Signature scan for external packages and create custom components for unknown packages:**

```bash
python3 scan_aosp_project.py \
    --module-info out/target/product/generic_arm64/module-info.json \
    --repo-list repo-list.txt \
    --android-version android-16.0.0_r4 \
    --bd-project "My-AOSP-Project" \
    --bd-version "16.0.0_r4" \
    --github-token "$GITHUB_TOKEN" \
    --aosp-root /home/aosp \
    --external-scan-modes ALL \
    --create-custom-components \
    --github-token ghb-XXX
```

**Platform repos only (external repos excluded) and create custom components for missing standard packages:**

```bash
python3 scan_aosp_project.py \
    --module-info out/target/product/generic_arm64/module-info.json \
    --repo-list repo-list.txt \
    --android-version android-16.0.0_r4 \
    --bd-project "My-AOSP-Project" \
    --bd-version "16.0.0_r4" \
    --create-custom-components
```

## How It Works

1. **Parse inputs** — reads `repo-list.txt` and `module-info.json` to determine which repos contribute installed artifacts to the build.

2. **Map paths to repos** — matches each installed path to its owning repo using longest-prefix matching.

3. **Collect platform packages** — all non-external repos are packaged with `pkg:android/platform-{repo-path}@{android_version}` PURLs and uploaded in a single-pass SBOM to Black Duck SCA (--create-custom-components determines if missing packages are added as custom components). A master Google/Android custom component can also be created to map CVEs reported against the associated CPE (requires BD-SCA 2026.7 or later).

4. **Classify external packages** — external repos (under `external/`) are classified into tiers based on their `METADATA` content:
   - **Tier 1 — GitHub PURL**: repo has a GitHub URL and a tagged version (strongest match)
   - **Tier 2 — CPE lookup**: repo has a CPE identifier (matched against the Black Duck KnowledgeBase)
   - **Tier 3 — GitHub commit**: repo has a GitHub URL but only a commit hash (weak, needs resolution)
   - **Tier 4 — Custom**: no usable upstream identifier (fallback)

5. **Resolve external packages** — based on active scan modes, resolution steps promote packages to stronger tiers:
   - `GITHUB_REPOS`: queries the GitHub API to find tagged releases near the repo's last upgrade date, promoting commit-hash packages to tagged versions
   - `KB_LOOKUP`: queries the Black Duck KnowledgeBase to find component versions by release date
   - `CPE_LOOKUP`: resolves CPE identifiers against the Black Duck KnowledgeBase
     
6. **Ensure project version** — creates the Black Duck project and version via the REST API if they do not already exist.

7. **Upload external SBOM** — uploads external packages with autocreate enabled when `CUSTOM_COMPS` mode is active and `--create-custom-components` is passed, creating custom components for any packages that do not match existing KnowledgeBase components.

8. **Signature scan** — if `SIG_SCAN` mode is active, runs Black Duck Detect on unmatched external repos in batches of up to 4 GB, using `.bdignore` files to control which repos are included in each batch.

## Generating Input Files

### repo-list.txt

From the AOSP source root:

```bash
repo list > repo-list.txt
```

### module-info.json

Build the AOSP target, then locate `module-info.json`:

```bash
source build/envsetup.sh
lunch <target>
make -j$(nproc)
```

The file is typically at `out/target/product/<device>/module-info.json`.
