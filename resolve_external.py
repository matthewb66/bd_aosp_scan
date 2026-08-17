"""External package resolution modes: GitHub tag, BD KB version-by-date, CPE."""

import json
import logging
import re
import sys
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from bd_api import (
    _bd_find_component_by_github,
    _bd_find_version_fuzzy,
    _bd_find_version_near_date,
    _bd_get_first_origin,
    bd_cpe_lookup,
)
from spdx_builder import _extract_cpe_version
from version_utils import find_best_tag_match

log = logging.getLogger(__name__)


def _add_bd_refs(pkg, comp_id, ver_id, origin_id=None):
    """Append BlackDuck component/version/origin external refs to a package."""
    pkg["externalRefs"].extend([
        {"referenceCategory": "OTHER",
         "referenceType": "BlackDuck-Component",
         "referenceLocator": comp_id},
        {"referenceCategory": "OTHER",
         "referenceType": "BlackDuck-ComponentVersion",
         "referenceLocator": ver_id},
    ])
    if origin_id:
        pkg["externalRefs"].append(
            {"referenceCategory": "OTHER",
             "referenceType": "BlackDuck-ComponentOrigin",
             "referenceLocator": origin_id})


# ---------------------------------------------------------------------------
# GitHub version resolution
# ---------------------------------------------------------------------------

def _gh_api_request(url, github_token=None):
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    if github_token:
        req.add_header("Authorization", f"Bearer {github_token}")
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read().decode())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
            ConnectionError, OSError) as exc:
        log.debug("GitHub API error for %s: %s", url, exc)
        return None


def gh_find_tag_near_date(owner, repo, target_date, github_token=None):
    base = "https://api.github.com"

    candidate_after = None
    candidate_before = None
    page = 1
    while page <= 5:
        url = f"{base}/repos/{owner}/{repo}/releases?per_page=100&page={page}"
        releases = _gh_api_request(url, github_token)
        if releases is None or len(releases) == 0:
            break
        for rel in releases:
            if rel.get("draft"):
                continue
            pub = rel.get("published_at", "")[:10]
            tag = rel.get("tag_name", "")
            if not pub or not tag:
                continue
            if pub >= target_date:
                candidate_after = (tag, pub)
            else:
                if not candidate_before:
                    candidate_before = (tag, pub)
                if candidate_after:
                    return candidate_after
                break
        else:
            if len(releases) < 100:
                break
            page += 1
            continue
        break
    if candidate_after:
        return candidate_after
    if candidate_before:
        return candidate_before

    candidate_after = None
    candidate_before = None
    page = 1
    while page <= 3:
        url = f"{base}/repos/{owner}/{repo}/tags?per_page=100&page={page}"
        tags = _gh_api_request(url, github_token)
        if tags is None or len(tags) == 0:
            break
        for tag_obj in tags:
            tag_name = tag_obj.get("name", "")
            sha = tag_obj.get("commit", {}).get("sha", "")
            if not sha:
                continue
            commit_url = f"{base}/repos/{owner}/{repo}/commits/{sha}"
            commit_data = _gh_api_request(commit_url, github_token)
            if commit_data is None:
                continue
            commit_date = (commit_data.get("commit", {})
                           .get("committer", {})
                           .get("date", ""))[:10]
            if not commit_date:
                continue
            if commit_date >= target_date:
                candidate_after = (tag_name, commit_date)
            else:
                if not candidate_before:
                    candidate_before = (tag_name, commit_date)
                if candidate_after:
                    return candidate_after
                break
        else:
            if len(tags) < 100:
                break
            page += 1
            continue
        break
    if candidate_after:
        return candidate_after
    if candidate_before:
        return candidate_before

    return None, None


def _resolve_one_github(entry, github_token):
    info = entry["info"]
    github_path = info.get("github_path")
    last_upgrade = info.get("last_upgrade_date")

    if not github_path or not last_upgrade:
        return entry, None, None

    parts = github_path.split("/", 1)
    if len(parts) != 2:
        return entry, None, None

    owner, repo = parts
    try:
        tag, pub_date = gh_find_tag_near_date(owner, repo, last_upgrade,
                                              github_token)
    except Exception as exc:
        log.debug("GitHub resolution error for %s: %s", github_path, exc)
        print(f"  WARNING: GitHub resolution failed for {github_path}: {exc}",
              file=sys.stderr, flush=True)
        return entry, None, None
    return entry, tag, pub_date


def resolve_github_versions(packages_by_tier, github_token=None):
    commit_entries = packages_by_tier.get("github_commit", [])
    if not commit_entries:
        return 0

    total = len(commit_entries)
    print(f"\nResolving GitHub versions for {total} "
          f"external commit-hash packages...", file=sys.stderr)

    done_count = 0
    lock = threading.Lock()

    def on_done(future):
        nonlocal done_count
        with lock:
            done_count += 1
            if done_count % 10 == 0 or done_count == total:
                print(f"  GitHub resolution: {done_count}/{total} done",
                      file=sys.stderr, flush=True)

    futures = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for entry in commit_entries:
            f = executor.submit(_resolve_one_github, entry, github_token)
            f.add_done_callback(on_done)
            futures.append(f)

    promoted = 0
    remaining = []
    for f in futures:
        entry, tag, pub_date = f.result()
        if tag:
            info = entry["info"]
            github_path = info["github_path"]
            name = info["name"]
            print(f"  {name}: {tag} (published {pub_date}, "
                  f"upgrade date {info['last_upgrade_date']})",
                  file=sys.stderr)

            purl = f"pkg:github/{github_path}@{tag}"
            pkg = entry["package"]
            for ref in pkg["externalRefs"]:
                if ref["referenceType"] == "purl":
                    ref["referenceLocator"] = purl
                    break
            pkg["versionInfo"] = tag
            info["resolved_tag"] = tag
            info["resolved_date"] = pub_date
            info["version_source"] = "github_release_api"
            packages_by_tier["github_purl"].append(entry)
            promoted += 1
        else:
            remaining.append(entry)

    packages_by_tier["github_commit"] = remaining
    print(f"  Promoted {promoted} packages to github_purl tier, "
          f"{len(remaining)} remain as github_commit", file=sys.stderr)
    return promoted


# ---------------------------------------------------------------------------
# CPE-derived GitHub version verification
# ---------------------------------------------------------------------------

def _gh_list_tags(owner, repo, github_token=None, max_pages=3):
    """Fetch tag names from GitHub API (up to max_pages * 100 tags)."""
    base = "https://api.github.com"
    tags = []
    for page in range(1, max_pages + 1):
        url = f"{base}/repos/{owner}/{repo}/tags?per_page=100&page={page}"
        data = _gh_api_request(url, github_token)
        if data is None or len(data) == 0:
            break
        for tag_obj in data:
            name = tag_obj.get("name", "")
            if name:
                tags.append(name)
        if len(data) < 100:
            break
    return tags


def gh_find_tag_by_version(owner, repo, target_version,
                           github_token=None):
    """Find the GitHub tag that best matches target_version."""
    tags = _gh_list_tags(owner, repo, github_token)
    if not tags:
        return None
    return find_best_tag_match(tags, target_version)


def _resolve_one_cpe_github(entry, bearer, bd_url, trust_cert,
                            github_token):
    """Resolve a tier 1c package via GitHub tags, then BD KB fuzzy."""
    info = entry["info"]
    github_path = info.get("github_path")
    cpe = info.get("cpe")

    cpe_version = _extract_cpe_version(cpe) if cpe else None
    if not github_path or not cpe_version:
        return entry, None

    parts = github_path.split("/", 1)
    if len(parts) != 2:
        return entry, None
    owner, repo = parts

    tag = gh_find_tag_by_version(owner, repo, cpe_version,
                                github_token=github_token)
    if tag:
        return entry, {"source": "github_tag", "tag": tag}

    comp_url, comp_id = _bd_find_component_by_github(
        bearer, github_path, bd_url, trust_cert)
    if comp_url:
        ver_name, ver_id = _bd_find_version_fuzzy(
            bearer, comp_url, cpe_version, bd_url, trust_cert)
        if ver_name and ver_id:
            origin_id = _bd_get_first_origin(
                bearer, comp_url, ver_id, trust_cert)
            return entry, {
                "source": "bd_kb_fuzzy",
                "tag": ver_name,
                "comp_id": comp_id,
                "ver_id": ver_id,
                "origin_id": origin_id,
            }

    return entry, None


def resolve_cpe_github_versions(packages_by_tier, bearer, bd_url,
                                trust_cert=False, github_token=None):
    """Verify/correct tier 1c packages (github_purl from CPE version).

    Searches GitHub tags and BD KB to find the actual version tag,
    replacing the initial best-guess v-prefixed version.
    """
    work_list = [
        entry for entry in packages_by_tier.get("github_purl", [])
        if entry["info"].get("version_source") == "cpe_version"
    ]

    if not work_list:
        return 0

    total = len(work_list)
    print(f"\nVerifying CPE-derived GitHub versions for {total} "
          f"packages...", file=sys.stderr)

    done_count = 0
    lock = threading.Lock()

    def on_done(future):
        nonlocal done_count
        with lock:
            done_count += 1
            if done_count % 5 == 0 or done_count == total:
                print(f"  CPE-GitHub verification: {done_count}/{total} done",
                      file=sys.stderr, flush=True)

    futures = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for entry in work_list:
            f = executor.submit(_resolve_one_cpe_github, entry, bearer,
                                bd_url, trust_cert, github_token)
            f.add_done_callback(on_done)
            futures.append(f)

    verified = 0
    for f in futures:
        entry, result = f.result()
        if result:
            info = entry["info"]
            pkg = entry["package"]
            github_path = info["github_path"]
            tag = result["tag"]
            old_tag = pkg["versionInfo"]

            purl = f"pkg:github/{github_path}@{tag}"
            for ref in pkg["externalRefs"]:
                if ref["referenceType"] == "purl":
                    ref["referenceLocator"] = purl
                    break
            pkg["versionInfo"] = tag
            info["version_source"] = f"cpe_version_{result['source']}"

            if result.get("comp_id"):
                bd_ref = {
                    "comp_id": result["comp_id"],
                    "ver_id": result["ver_id"],
                    "origin_id": result.get("origin_id"),
                }
                _add_bd_refs(pkg, result["comp_id"], result["ver_id"],
                             result.get("origin_id"))
                entry["bd_ref"] = bd_ref

            verified += 1
            change = f" (was {old_tag})" if old_tag != tag else ""
            print(f"  {info['name']}: {tag} via "
                  f"{result['source']}{change}", file=sys.stderr)

    print(f"  Verified {verified}/{total} CPE-derived versions",
          file=sys.stderr)
    return verified


# ---------------------------------------------------------------------------
# BD KB version-by-date resolution
# ---------------------------------------------------------------------------

def _resolve_one_bd_kb(entry, bearer, bd_url, trust_cert):
    info = entry["info"]
    github_path = info.get("github_path")
    last_upgrade = info.get("last_upgrade_date")

    if not github_path or not last_upgrade:
        return entry, None

    comp_url, comp_id = _bd_find_component_by_github(
        bearer, github_path, bd_url, trust_cert)
    if not comp_url:
        log.debug("BD KB: no component for %s", github_path)
        return entry, None

    ver_name, ver_date, ver_id = _bd_find_version_near_date(
        bearer, comp_url, last_upgrade, bd_url, trust_cert)
    if not ver_name or not ver_id:
        log.debug("BD KB: component found for %s but no version "
                  "near %s", github_path, last_upgrade)
        return entry, None

    origin_id = _bd_get_first_origin(bearer, comp_url, ver_id, trust_cert)

    return entry, {
        "comp_id": comp_id, "ver_id": ver_id, "origin_id": origin_id,
        "ver_name": ver_name, "ver_date": ver_date,
    }


def resolve_bd_kb_versions(packages_by_tier, bearer, bd_url,
                           trust_cert=False):
    commit_entries = packages_by_tier.get("github_commit", [])
    if not commit_entries:
        return 0

    total = len(commit_entries)
    print(f"\nResolving BD KB versions by date for {total} "
          f"remaining external commit-hash packages...", file=sys.stderr)

    done_count = 0
    lock = threading.Lock()

    def on_done(future):
        nonlocal done_count
        with lock:
            done_count += 1
            if done_count % 5 == 0 or done_count == total:
                print(f"  BD KB resolution: {done_count}/{total} done",
                      file=sys.stderr, flush=True)

    futures = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        for entry in commit_entries:
            f = executor.submit(_resolve_one_bd_kb, entry, bearer,
                                bd_url, trust_cert)
            f.add_done_callback(on_done)
            futures.append(f)

    print(f"  BD KB resolution: {total}/{total} done, "
          f"processing results...", file=sys.stderr, flush=True)

    promoted = 0
    remaining = []
    for f in futures:
        entry, result = f.result()
        if result:
            info = entry["info"]
            name = info["name"]
            last_upgrade = info["last_upgrade_date"]
            print(f"  {name}: {result['ver_name']} "
                  f"(released {result['ver_date']}, "
                  f"upgrade date {last_upgrade})", file=sys.stderr)

            pkg = entry["package"]
            pkg["versionInfo"] = result["ver_name"]

            bd_ref = {"comp_id": result["comp_id"],
                      "ver_id": result["ver_id"],
                      "origin_id": result["origin_id"]}
            _add_bd_refs(pkg, result["comp_id"], result["ver_id"],
                         result["origin_id"])
            pkg["externalRefs"] = [
                r for r in pkg["externalRefs"]
                if r["referenceType"] != "purl"
            ]

            entry["bd_ref"] = bd_ref
            info["resolved_kb_version"] = result["ver_name"]
            info["resolved_kb_date"] = result["ver_date"]
            info["version_source"] = "bd_kb_date_lookup"
            packages_by_tier["cpe_lookup"].append(entry)
            promoted += 1
        else:
            remaining.append(entry)

    packages_by_tier["github_commit"] = remaining
    print(f"  Promoted {promoted} packages to cpe_lookup tier, "
          f"{len(remaining)} remain as github_commit", file=sys.stderr)
    return promoted


# ---------------------------------------------------------------------------
# CPE resolution
# ---------------------------------------------------------------------------

def _resolve_one_cpe(entry, bearer, bd_url, trust_cert):
    info = entry["info"]
    pkg_name = info.get("name") or ""
    pkg_version = (info.get("closest_version")
                   or info.get("version") or "")
    cpe = info.get("cpe")

    log.debug("CPE lookup: %s (ver=%s, cpe=%s)",
              pkg_name, pkg_version[:30] if pkg_version else "?",
              cpe or "none")
    bd_ref = bd_cpe_lookup(bearer, pkg_name, pkg_version, cpe,
                           bd_url, trust_cert)
    return entry, bd_ref


def resolve_cpe_packages(packages_by_tier, bearer, bd_url, trust_cert):
    work_list = []
    for tier_name in ["cpe_lookup", "github_commit", "custom"]:
        for entry in packages_by_tier.get(tier_name, []):
            if not entry.get("bd_ref"):
                work_list.append(entry)

    if not work_list:
        return 0

    total = len(work_list)
    print(f"\nCPE resolution for {total} packages...", file=sys.stderr)

    done_count = 0
    lock = threading.Lock()

    def on_done(future):
        nonlocal done_count
        with lock:
            done_count += 1
            if done_count % 10 == 0 or done_count == total:
                print(f"  CPE resolution: {done_count}/{total} done",
                      file=sys.stderr, flush=True)

    futures = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        for entry in work_list:
            f = executor.submit(_resolve_one_cpe, entry, bearer,
                                bd_url, trust_cert)
            f.add_done_callback(on_done)
            futures.append(f)

    print(f"  CPE resolution: {total}/{total} done, "
          f"processing results...", file=sys.stderr, flush=True)

    resolved = 0
    for f in futures:
        entry, bd_ref = f.result()
        if bd_ref:
            pkg = entry["package"]
            info = entry["info"]
            pkg_name = info.get("name") or ""
            existing_bd_types = {
                r["referenceType"] for r in pkg["externalRefs"]
                if r["referenceCategory"] == "OTHER"
            }
            if "BlackDuck-Component" not in existing_bd_types:
                _add_bd_refs(pkg, bd_ref["comp_id"], bd_ref["ver_id"],
                             bd_ref.get("origin_id"))

            pkg["externalRefs"] = [
                r for r in pkg["externalRefs"]
                if r["referenceType"] != "purl"
            ]

            cpe = info.get("cpe")
            if cpe:
                cpe_ver = _extract_cpe_version(cpe)
                if cpe_ver:
                    pkg["versionInfo"] = cpe_ver

            entry["bd_ref"] = bd_ref
            resolved += 1
            print(f"  CPE resolved: {pkg_name} -> "
                  f"{bd_ref['comp_id'][:8]}../{bd_ref['ver_id'][:8]}..",
                  file=sys.stderr)
        else:
            entry["cpe_failed"] = True

    return resolved


