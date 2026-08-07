"""AOSP input parsing: repo list, module-info, METADATA, GitHub path parsing."""

import json
import logging
import re

log = logging.getLogger(__name__)


def parse_repo_list(repo_list_path):
    repos = {}
    with open(repo_list_path) as f:
        for line in f:
            line = line.strip()
            if not line or ' : ' not in line:
                log.debug("Skipping repo-list line: %s", line)
                continue
            local_path, remote = line.split(' : ', 1)
            repos[local_path.strip()] = remote.strip()
    log.debug("Parsed %d repos from %s", len(repos), repo_list_path)
    return repos


def extract_installed_paths(module_info_path):
    with open(module_info_path) as f:
        modules = json.load(f)

    paths = set()
    for entry in modules.values():
        if entry.get("installed"):
            for p in entry.get("path", []):
                paths.add(p)

    include = re.compile(
        r'^(art|bionic|external|frameworks|hardware|packages|prebuilts|system|tools)(/|$)'
    )
    exclude = re.compile(
        r'(/test/|/tests/|/test$|/tests$'
        r'|/hostsidetests/|/testing/|/testing$|/javatests$|/javatest$)'
    )
    filtered = sorted(p for p in paths
                      if p != '.' and include.search(p) and not exclude.search(p))
    log.debug("Extracted %d installed paths from %d total (excluded %d)",
              len(filtered), len(paths), len(paths) - len(filtered))
    return filtered


def map_paths_to_repos(paths, repos):
    sorted_repo_paths = sorted(repos.keys(), key=len, reverse=True)
    repo_matches = {}
    unmatched = []

    for path in paths:
        matched = False
        for repo_path in sorted_repo_paths:
            if path == repo_path or path.startswith(repo_path + '/'):
                repo_matches.setdefault(repo_path, set()).add(path)
                matched = True
                break
        if not matched:
            unmatched.append(path)

    log.debug("Matched %d paths to %d repos, %d unmatched",
              sum(len(v) for v in repo_matches.values()),
              len(repo_matches), len(unmatched))
    for path in unmatched:
        log.debug("Unmatched path: %s", path)
    return repo_matches, unmatched


def _is_commit_hash(s):
    if not s:
        return False
    return bool(re.fullmatch(r'[0-9a-f]{7,40}', s)) and bool(re.search(r'[a-f]', s))


def _has_github(url):
    return bool(url) and bool(re.search(r'github\.com/', url, re.IGNORECASE))


def _extract_version_from_archive_url(url):
    if not url:
        return None
    match = re.search(r'/archive/([^/]+?)\.(?:zip|tar\.gz|tgz)$', url, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'/releases/download/([^/]+)/', url, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def parse_metadata(metadata_path):
    result = {"name": None, "version": None, "cpe": None, "github_url": None,
              "closest_version": None, "top_version": None,
              "license_type": None, "all_versions": [],
              "last_upgrade_date": None}

    try:
        with open(metadata_path) as f:
            content = f.read()
    except (OSError, IOError):
        log.debug("No METADATA file at %s", metadata_path)
        return result

    name_match = re.search(r'^name:\s*"([^"]*)"', content, re.MULTILINE)
    if name_match:
        result["name"] = name_match.group(1)

    license_match = re.search(r'license_type:\s*(\w+)', content)
    if license_match:
        result["license_type"] = license_match.group(1)

    cpe_match = re.search(
        r'identifier\s*:?\s*\{[^}]*type:\s*"?cpe"?[^}]*value:\s*"([^"]*)"',
        content, re.DOTALL,
    )
    if not cpe_match:
        cpe_match = re.search(
            r'identifier\s*:?\s*\{[^}]*value:\s*"(cpe:[^"]*)"[^}]*type:\s*"?cpe"?',
            content, re.DOTALL,
        )
    if not cpe_match:
        cpe_match = re.search(r'tag:\s*"(?:NVD-CPE2\.3:)?(cpe:[^"]*)"', content)
    if cpe_match:
        result["cpe"] = cpe_match.group(1)

    url_blocks = []
    for block_content in re.findall(r'url\s*:?\s*\{(.*?)\}', content, flags=re.DOTALL):
        type_match = re.search(r'type:\s*"?(\w+)"?', block_content)
        value_match = re.search(r'value:\s*"([^"]+)"', block_content)
        if type_match and value_match:
            url_blocks.append({
                "type": type_match.group(1).upper(),
                "value": value_match.group(1),
            })

    identifier_blocks = []
    for block_content in re.findall(
        r'identifier\s*:?\s*\{(.*?)\}', content, flags=re.DOTALL
    ):
        type_match = re.search(r'type:\s*"?(\w+)"?', block_content)
        if not type_match:
            continue
        block = {"type": type_match.group(1).upper(), "value": None,
                 "version": None, "closest_version": None}
        value_match = re.search(r'value:\s*"([^"]+)"', block_content)
        if value_match:
            block["value"] = value_match.group(1)
        ver_match = re.search(r'(?<!closest_)version:\s*"([^"]*)"', block_content)
        if ver_match:
            block["version"] = ver_match.group(1)
        closest_match = re.search(r'closest_version:\s*"([^"]*)"', block_content)
        if closest_match:
            block["closest_version"] = closest_match.group(1)
        identifier_blocks.append(block)

    homepage = None
    homepage_match = re.search(r'homepage:\s*"([^"]+)"', content)
    if homepage_match:
        homepage = homepage_match.group(1)

    github_url = None
    for source in [
        (url_blocks, "GIT"),
        (identifier_blocks, "GIT"),
        (url_blocks, "HOMEPAGE"),
    ]:
        for b in source[0]:
            if b["type"] == source[1] and _has_github(b.get("value")):
                github_url = b["value"]
                break
        if github_url:
            break

    if not github_url and _has_github(homepage):
        github_url = homepage

    if not github_url:
        for source in [
            (identifier_blocks, "HOMEPAGE"),
            (url_blocks, "ARCHIVE"),
            (identifier_blocks, "ARCHIVE"),
        ]:
            for b in source[0]:
                if b["type"] == source[1] and _has_github(b.get("value")):
                    github_url = b["value"]
                    break
            if github_url:
                break

    result["github_url"] = github_url

    content_no_ident = re.sub(
        r'identifier\s*:?\s*\{.*?\}', '', content, flags=re.DOTALL,
    )
    ver_match = re.search(
        r'^\s*version:\s*"([^"]*)"', content_no_ident, re.MULTILINE,
    )
    top_version = ver_match.group(1) if ver_match else None

    closest_versions = []
    for b in identifier_blocks:
        if b["closest_version"]:
            closest_versions.append(b["closest_version"])
    if closest_versions:
        result["closest_version"] = closest_versions[0]

    result["top_version"] = top_version

    versions = list(closest_versions)
    if top_version:
        versions.append(top_version)
    for b in identifier_blocks:
        if b["version"]:
            versions.append(b["version"])
    for b in url_blocks + identifier_blocks:
        if b["type"] == "ARCHIVE":
            v = _extract_version_from_archive_url(b.get("value"))
            if v:
                versions.append(v)

    result["all_versions"] = versions

    best = None
    for v in versions:
        if v and not _is_commit_hash(v):
            best = v
            break
    if not best:
        for v in versions:
            if v:
                best = v
                break
    result["version"] = best

    date_match = re.search(
        r'last_upgrade_date\s*\{[^}]*year:\s*(\d+)[^}]*month:\s*(\d+)'
        r'[^}]*day:\s*(\d+)', content, re.DOTALL)
    if date_match:
        result["last_upgrade_date"] = (
            f"{date_match.group(1)}-{int(date_match.group(2)):02d}"
            f"-{int(date_match.group(3)):02d}")

    log.debug("METADATA %s: name=%s version=%s cpe=%s github_url=%s",
              metadata_path, result["name"], result["version"],
              result["cpe"], result["github_url"])
    return result


def parse_github_path(git_url):
    match = re.match(
        r'https?://github\.com/([^/]+/[^/]+?)(?:\.git)?(?:/.*)?$', git_url,
        re.IGNORECASE,
    )
    return match.group(1) if match else None
