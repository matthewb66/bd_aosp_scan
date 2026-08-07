#!/usr/bin/env python3
"""Generate an SPDX 2.3 SBOM from AOSP external packages and upload to Black Duck SCA.

Implements a 4-tier matching strategy:
  Tier 1: GitHub PURL with tag version (strongest PURL match)
  Tier 2: CPE lookup -> BD internal reference (strongest KB match)
  Tier 3: GitHub PURL with commit hash (weak, likely fails)
  Tier 4: Custom component via autocreate (fallback)
"""

import argparse
import json
import logging
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from generate_bdio import (
    _has_github,
    _is_commit_hash,
    extract_installed_paths,
    map_paths_to_repos,
    parse_github_path,
    parse_metadata,
    parse_repo_list,
)

log = logging.getLogger(__name__)

LICENSE_MAP = {
    "NOTICE": "NOASSERTION",
    "PERMISSIVE": "NOASSERTION",
    "UNENCUMBERED": "NOASSERTION",
    "RESTRICTED": "NOASSERTION",
    "RESTRICTED_IF_STATICALLY_LINKED": "NOASSERTION",
    "BY_EXCEPTION_ONLY": "NOASSERTION",
    "RECIPROCAL": "NOASSERTION",
}


# ---------------------------------------------------------------------------
# BD API helpers
# ---------------------------------------------------------------------------

def _ssl_ctx(trust_cert):
    if not trust_cert:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _api_request(url, bearer, method="GET", data=None, accept=None,
                 content_type=None, trust_cert=False):
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {bearer}")
    if accept:
        req.add_header("Accept", accept)
    if content_type:
        req.add_header("Content-Type", content_type)
    ctx = _ssl_ctx(trust_cert)
    resp = urllib.request.urlopen(req, context=ctx)
    return resp


def bd_authenticate(api_token, bd_url, trust_cert=False):
    url = f"{bd_url.rstrip('/')}/api/tokens/authenticate"
    req = urllib.request.Request(url, data=b"", method="POST")
    req.add_header("Authorization", f"token {api_token}")
    req.add_header("Accept", "application/vnd.blackducksoftware.user-4+json")
    resp = urllib.request.urlopen(req, context=_ssl_ctx(trust_cert))
    return json.loads(resp.read())["bearerToken"]


def _bd_cpe_direct_query(bearer, cpe, bd_url, trust_cert=False):
    """Query CPE API with an exact CPE string and follow links to get IDs.

    Returns a dict with comp_id, ver_id, origin_id, or None if not found.
    """
    base = bd_url.rstrip("/")
    url = f"{base}/api/cpes?q={urllib.request.quote(cpe, safe='')}&limit=5"
    try:
        resp = _api_request(
            url, bearer,
            accept="application/vnd.blackducksoftware.component-detail-5+json",
            trust_cert=trust_cert,
        )
        data = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.debug("CPE lookup failed for %s: %s", cpe, e)
        return None

    for item in data.get("items", []):
        links = {l["rel"]: l["href"] for l in item.get("_meta", {}).get("links", [])}

        # Path A: cpe-origins -> direct origin
        if "cpe-origins" in links:
            origin_result = _follow_origins(bearer, links["cpe-origins"], trust_cert)
            if origin_result:
                return origin_result

        # Path B: cpe-versions -> version -> origins
        if "cpe-versions" in links:
            try:
                vresp = _api_request(
                    links["cpe-versions"], bearer,
                    accept="application/vnd.blackducksoftware.component-detail-5+json",
                    trust_cert=trust_cert,
                )
                vdata = json.loads(vresp.read())
            except (urllib.error.URLError, urllib.error.HTTPError):
                continue
            for ver_item in vdata.get("items", []):
                ver_links = {l["rel"]: l["href"]
                             for l in ver_item.get("_meta", {}).get("links", [])}
                if "origins" in ver_links:
                    origin_result = _follow_origins(
                        bearer, ver_links["origins"], trust_cert)
                    if origin_result:
                        return origin_result
    return None


def _follow_origins(bearer, origins_url, trust_cert):
    try:
        resp = _api_request(
            origins_url, bearer,
            accept="application/vnd.blackducksoftware.component-detail-5+json",
            trust_cert=trust_cert,
        )
        data = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError):
        return None
    for origin in data.get("items", []):
        href = origin.get("_meta", {}).get("href", "")
        m = re.search(
            r"/api/components/([^/?#]+)/versions/([^/?#]+)/origins/([^/?#]+)", href)
        if m:
            return {"comp_id": m.group(1), "ver_id": m.group(2),
                    "origin_id": m.group(3)}
    return None


def _parse_cpe_string(cpe_str):
    """Parse a CPE string into (vendor, product, version).

    Handles both CPE 2.2 (cpe:/) and 2.3 (cpe:2.3:) formats.
    """
    if not cpe_str:
        return None, None, None
    m = re.match(r'cpe:2\.3:a:([^:]+):([^:]+):([^:]*)', cpe_str)
    if m:
        v = m.group(3)
        return m.group(1), m.group(2), v if v and v != '*' else None
    m = re.match(r'cpe:/a:([^:]+):([^:]+)(?::([^:]*))?', cpe_str)
    if m:
        v = m.group(3)
        return m.group(1), m.group(2), v if v else None
    return None, None, None


def _extract_clean_version(version_str):
    """Extract clean numeric version from tag-style version strings.

    elfutils-0.193 -> 0.193, v1.8.3 -> 1.8.3, libdrm-2.4.124 -> 2.4.124,
    pixman-0.44.2 -> 0.44.2, bzip2-1.0.8 -> 1.0.8, 1.22.0 -> 1.22.0,
    commit hashes -> None, unknown -> None
    """
    if not version_str or version_str == "unknown":
        return None
    if _is_commit_hash(version_str):
        return None
    s = version_str.strip()
    if re.match(r'^[vV]\d', s):
        s = s[1:]
    if re.match(r'^\d[\d.]*$', s):
        return s
    m = re.search(r'[-_](\d[\d.]+)$', s)
    if m:
        return m.group(1)
    return None


def _resolve_component_from_cpe_item(bearer, item, bd_url, trust_cert):
    """Follow a CPE result item's links to find the component UUID.

    CPE items link to /api/cpes/{id}/origins or /versions, not directly to
    /api/components/{uuid}. We follow one hop to extract the component UUID
    from the resulting hrefs.
    """
    links = {l["rel"]: l["href"]
             for l in item.get("_meta", {}).get("links", [])}
    for rel in ("cpe-versions", "cpe-origins"):
        if rel not in links:
            continue
        try:
            resp = _api_request(
                links[rel], bearer,
                accept="application/vnd.blackducksoftware.component-detail-5+json",
                trust_cert=trust_cert,
            )
            data = json.loads(resp.read())
        except (urllib.error.URLError, urllib.error.HTTPError):
            continue
        for sub_item in data.get("items", []):
            href = sub_item.get("_meta", {}).get("href", "")
            m = re.search(r'/api/components/([0-9a-f-]{36})', href)
            if m:
                return m.group(1)
    return None


def _get_component_name(bearer, comp_id, bd_url, trust_cert):
    """Get the display name of a BD component."""
    url = f"{bd_url.rstrip('/')}/api/components/{comp_id}"
    try:
        resp = _api_request(
            url, bearer,
            accept="application/vnd.blackducksoftware.component-detail-5+json",
            trust_cert=trust_cert,
        )
        data = json.loads(resp.read())
        return data.get("name", "")
    except (urllib.error.URLError, urllib.error.HTTPError):
        return ""


def _component_name_matches(comp_name, pkg_name):
    """Check if a BD component name is a reasonable match for a package name."""
    cn = comp_name.lower()
    pn = pkg_name.lower()
    if cn == pn:
        return True
    if pn in cn or cn in pn:
        return True
    pn_clean = re.sub(r'[-_]', '', pn)
    cn_clean = re.sub(r'[-_]', '', cn)
    if pn_clean in cn_clean or cn_clean in pn_clean:
        return True
    return False


def _search_component_versions(bearer, comp_id, target_version, bd_url,
                                trust_cert):
    """Search a component's versions for an exact match, return origin info."""
    base = bd_url.rstrip("/")
    encoded_ver = urllib.request.quote(target_version, safe='')
    url = (f"{base}/api/components/{comp_id}/versions"
           f"?q=versionName:{encoded_ver}&limit=20")
    try:
        resp = _api_request(
            url, bearer,
            accept="application/vnd.blackducksoftware.component-detail-5+json",
            trust_cert=trust_cert,
        )
        data = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.debug("    Version search failed for %s: %s", comp_id[:8], e)
        return None

    for ver_item in data.get("items", []):
        ver_name = ver_item.get("versionName", "")
        if ver_name == target_version:
            ver_href = ver_item.get("_meta", {}).get("href", "")
            if ver_href:
                origins_url = f"{ver_href}/origins?limit=1"
                result = _follow_origins(bearer, origins_url, trust_cert)
                if result:
                    return result
    return None


def bd_cpe_lookup(bearer, pkg_name, pkg_version, cpe_from_metadata,
                  bd_url, trust_cert=False):
    """Enhanced CPE lookup with multiple fallback strategies.

    Strategy 1: Try exact CPE from METADATA (if available)
    Strategy 2: Wildcard vendor + exact version
    Strategy 3: Wildcard vendor + wildcard version, then search component versions

    Returns a dict with comp_id, ver_id, origin_id, or None.
    """
    _, cpe_product, cpe_version = _parse_cpe_string(cpe_from_metadata)
    product = cpe_product or pkg_name.lower().replace(' ', '_')
    clean_ver = _extract_clean_version(pkg_version)
    if cpe_version:
        clean_ver = cpe_version

    # Strategy 1: exact CPE from METADATA
    if cpe_from_metadata:
        result = _bd_cpe_direct_query(bearer, cpe_from_metadata, bd_url,
                                      trust_cert)
        if result:
            log.debug("  CPE strategy 1 (exact METADATA CPE): matched")
            return result

    if not product:
        return None

    # Strategy 2: wildcard vendor + exact version
    if clean_ver:
        cpe = f"cpe:2.3:a:*:{product}:{clean_ver}:*:*:*:*:*:*:*"
        result = _bd_cpe_direct_query(bearer, cpe, bd_url, trust_cert)
        if result:
            log.debug("  CPE strategy 2 (wildcard vendor, ver=%s): matched",
                      clean_ver)
            return result

    # Strategy 3: wildcard version, find component, then search its versions
    if clean_ver:
        cpe = f"cpe:2.3:a:*:{product}:*:*:*:*:*:*:*:*"
        log.debug("  CPE strategy 3: querying %s", cpe)
        base = bd_url.rstrip("/")
        url = (f"{base}/api/cpes"
               f"?q={urllib.request.quote(cpe, safe='')}&limit=20")
        try:
            resp = _api_request(
                url, bearer,
                accept="application/vnd.blackducksoftware.component-detail-5+json",
                trust_cert=trust_cert,
            )
            data = json.loads(resp.read())
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            log.debug("    Wildcard CPE query failed: %s", e)
            return None

        items = data.get("items", [])
        if not items:
            log.debug("    No CPE items found for %s", product)
            return None

        seen_comp_ids = set()
        for item in items[:10]:
            comp_id = _resolve_component_from_cpe_item(
                bearer, item, bd_url, trust_cert)
            if not comp_id or comp_id in seen_comp_ids:
                continue
            seen_comp_ids.add(comp_id)

            comp_name = _get_component_name(
                bearer, comp_id, bd_url, trust_cert)
            if not _component_name_matches(comp_name, pkg_name):
                log.debug("    Skipping component %s (name=%s, want=%s)",
                          comp_id[:8], comp_name, pkg_name)
                continue

            log.debug("    Searching versions of %s (%s) for %s",
                      comp_name, comp_id[:8], clean_ver)
            result = _search_component_versions(
                bearer, comp_id, clean_ver, bd_url, trust_cert)
            if result:
                log.debug("  CPE strategy 3 (wildcard ver + search): "
                          "matched via %s", comp_name)
                return result

        if not seen_comp_ids:
            log.debug("    Could not resolve any components from CPE items")

    return None


def bd_upload_spdx(bearer, sbom_content, bd_url, autocreate=False,
                   trust_cert=False):
    """Upload SPDX JSON to BD. Returns (http_status, scan_url) or raises."""
    boundary = uuid.uuid4().hex
    parts = []
    sbom_bytes = sbom_content.encode("utf-8") if isinstance(
        sbom_content, str) else sbom_content

    parts.append(
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; "
        f"filename=\"sbom.spdx.json\"\r\n"
        f"Content-Type: application/spdx\r\n\r\n"
    )
    parts.append(sbom_bytes)
    parts.append(b"\r\n")

    if autocreate:
        parts.append(
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"autocreate\"\r\n\r\n"
            f"true\r\n"
        )

    parts.append(f"--{boundary}--\r\n")

    body = b""
    for part in parts:
        body += part.encode("utf-8") if isinstance(part, str) else part

    url = f"{bd_url.rstrip('/')}/api/scan/data"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {bearer}")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    ctx = _ssl_ctx(trust_cert)
    resp = urllib.request.urlopen(req, context=ctx)
    scan_url = resp.headers.get("Location", "")
    return resp.getcode(), scan_url


def bd_poll_scan(bearer, scan_url, bd_url, trust_cert=False,
                 max_polls=30, interval=5):
    """Poll scan summary until terminal state. Returns scan summary dict."""
    scan_id = scan_url.rstrip("/").split("/")[-1]
    poll_url = f"{bd_url.rstrip('/')}/api/scan-summaries/{scan_id}"

    for i in range(max_polls):
        resp = _api_request(
            poll_url, bearer,
            accept="application/vnd.blackducksoftware.scan-6+json",
            trust_cert=trust_cert,
        )
        summary = json.loads(resp.read())
        state = summary.get("scanState", "")
        log.debug("Poll %d: state=%s", i + 1, state)
        if state in ("SUCCESS", "FAILURE"):
            return summary
        time.sleep(interval)

    raise TimeoutError(f"Scan {scan_id} did not complete within {max_polls * interval}s")


def bd_get_import_events(bearer, scan_url, bd_url, trust_cert=False):
    """Fetch component import events from a completed scan. Returns list of dicts."""
    scan_id = scan_url.rstrip("/").split("/")[-1]
    url = (f"{bd_url.rstrip('/')}/api/bom-import/{scan_id}/"
           f"component-import-events?limit=1000")
    resp = _api_request(url, bearer, trust_cert=trust_cert)
    data = json.loads(resp.read())
    return data.get("items", [])


def bd_find_or_create_project(bearer, project_name, bd_url, trust_cert=False):
    """Find or create a BD project. Returns project href."""
    base = bd_url.rstrip("/")
    url = (f"{base}/api/projects?q=name:{urllib.request.quote(project_name)}"
           f"&limit=10")
    resp = _api_request(url, bearer, trust_cert=trust_cert)
    data = json.loads(resp.read())
    for item in data.get("items", []):
        if item.get("name") == project_name:
            return item["_meta"]["href"]

    payload = json.dumps({"name": project_name}).encode()
    resp = _api_request(
        f"{base}/api/projects", bearer, method="POST", data=payload,
        content_type="application/json", trust_cert=trust_cert,
    )
    location = resp.headers.get("Location", "")
    if not location:
        raise RuntimeError(
            f"Created project '{project_name}' but server returned no Location header")
    return location


def bd_find_or_create_version(bearer, project_href, version_name, bd_url,
                              trust_cert=False):
    """Find or create a version within a project. Returns version href."""
    url = (f"{project_href}/versions"
           f"?q=versionName:{urllib.request.quote(version_name)}&limit=10")
    resp = _api_request(url, bearer, trust_cert=trust_cert)
    data = json.loads(resp.read())
    for item in data.get("items", []):
        if item.get("versionName") == version_name:
            return item["_meta"]["href"]

    payload = json.dumps({
        "versionName": version_name,
        "phase": "DEVELOPMENT",
        "distribution": "INTERNAL",
    }).encode()
    resp = _api_request(
        f"{project_href}/versions", bearer, method="POST", data=payload,
        content_type="application/json", trust_cert=trust_cert,
    )
    location = resp.headers.get("Location", "")
    if not location:
        raise RuntimeError(
            f"Created version '{version_name}' but server returned no Location header")
    return location


def bd_map_codelocation(bearer, codeloc_href, version_href, trust_cert=False):
    """Map a codelocation to a project version."""
    payload = json.dumps({"mappedProjectVersion": version_href}).encode()
    _api_request(
        codeloc_href, bearer, method="PUT", data=payload,
        content_type="application/json", trust_cert=trust_cert,
    )


def bd_delete_codelocation(bearer, codeloc_href, trust_cert=False):
    """Delete a codelocation."""
    try:
        _api_request(codeloc_href, bearer, method="DELETE",
                     trust_cert=trust_cert)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise


def _get_codeloc_href(scan_summary):
    for link in scan_summary.get("_meta", {}).get("links", []):
        if link["rel"] == "codelocation":
            return link["href"]
    return None


# ---------------------------------------------------------------------------
# SPDX SBOM generation
# ---------------------------------------------------------------------------

def build_spdx_package(spdx_id, name, version, download_location,
                       license_spdx, purl=None, cpe=None, bd_ref=None):
    """Build a single SPDX package dict."""
    pkg = {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version or "NOASSERTION",
        "downloadLocation": download_location or "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": license_spdx or "NOASSERTION",
        "licenseDeclared": license_spdx or "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [],
    }

    if purl:
        pkg["externalRefs"].append({
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        })

    if cpe:
        cpe_normalized = cpe
        if cpe_normalized.startswith("cpe:/"):
            cpe_normalized = "cpe:2.3:" + cpe_normalized[5:].replace(
                ":", ":").rstrip(":")
            while cpe_normalized.count(":") < 12:
                cpe_normalized += ":*"
        pkg["externalRefs"].append({
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": cpe_normalized,
        })

    if bd_ref:
        pkg["externalRefs"].extend([
            {"referenceCategory": "OTHER",
             "referenceType": "BlackDuck-Component",
             "referenceLocator": bd_ref["comp_id"]},
            {"referenceCategory": "OTHER",
             "referenceType": "BlackDuck-ComponentVersion",
             "referenceLocator": bd_ref["ver_id"]},
        ])
        if bd_ref.get("origin_id"):
            pkg["externalRefs"].append(
                {"referenceCategory": "OTHER",
                 "referenceType": "BlackDuck-ComponentOrigin",
                 "referenceLocator": bd_ref["origin_id"]})

    return pkg


def build_spdx_document(packages, doc_name, doc_namespace):
    """Build a complete SPDX 2.3 JSON document."""
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT",
         "relationshipType": "DESCRIBES",
         "relatedSpdxElement": pkg["SPDXID"]}
        for pkg in packages
    ]

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: aosp-spdx-sbom-generator"],
        },
        "packages": packages,
        "relationships": relationships,
    }


# ---------------------------------------------------------------------------
# Package classification and PURL generation
# ---------------------------------------------------------------------------

def _sanitize_purl_version(version):
    """Sanitize a version string for use in PURLs (no spaces or slashes)."""
    if not version:
        return "unknown"
    return re.sub(r'[^a-zA-Z0-9._-]', '-', version)


def classify_package(metadata, repo_path):
    """Classify a package into a matching tier and build its SPDX package.

    Returns (tier, spdx_package, info_dict).
    tier is one of: "github_purl", "cpe_lookup", "github_commit", "custom"
    """
    github_url = metadata.get("github_url")
    cpe = metadata.get("cpe")
    closest_version = metadata.get("closest_version")
    top_version = metadata.get("top_version")
    version = metadata.get("version")
    name = metadata.get("name") or repo_path.split("/")[-1]
    license_type = metadata.get("license_type")
    license_spdx = LICENSE_MAP.get(license_type, "NOASSERTION")

    safe_name = re.sub(r'[^a-zA-Z0-9._-]', '-', name)
    spdx_id = f"SPDXRef-{safe_name}"

    github_path = parse_github_path(github_url) if github_url else None

    info = {
        "repo_path": repo_path,
        "name": name,
        "github_url": github_url,
        "github_path": github_path,
        "cpe": cpe,
        "version": version,
        "closest_version": closest_version,
        "last_upgrade_date": metadata.get("last_upgrade_date"),
    }

    # Tier 1: GitHub PURL with tag version
    if github_path and closest_version and not _is_commit_hash(closest_version):
        purl = f"pkg:github/{github_path}@{closest_version}"
        pkg = build_spdx_package(
            spdx_id, name, version or closest_version,
            github_url, license_spdx, purl=purl, cpe=cpe,
        )
        return "github_purl", pkg, info

    if github_path and top_version and not _is_commit_hash(top_version):
        purl = f"pkg:github/{github_path}@{top_version}"
        pkg = build_spdx_package(
            spdx_id, name, top_version,
            github_url, license_spdx, purl=purl, cpe=cpe,
        )
        info["version_source"] = "top_version"
        return "github_purl", pkg, info

    # Tier 2: Has CPE (will be resolved via API later)
    # Include a generic PURL as fallback so autocreate works if CPE lookup fails
    if cpe:
        pkg_version = _sanitize_purl_version(version or "unknown")
        safe_pkg_name = name.replace(" ", "-").replace("/", "-")
        fallback_purl = f"pkg:generic/{safe_pkg_name}@{pkg_version}"
        pkg = build_spdx_package(
            spdx_id, name, version or "NOASSERTION",
            github_url or "NOASSERTION", license_spdx,
            purl=fallback_purl, cpe=cpe,
        )
        return "cpe_lookup", pkg, info

    # Tier 3: GitHub with commit hash
    if github_path and version and _is_commit_hash(version):
        purl = f"pkg:github/{github_path}@{version}"
        pkg = build_spdx_package(
            spdx_id, name, version,
            github_url, license_spdx, purl=purl,
        )
        return "github_commit", pkg, info

    # Tier 4: Custom component
    pkg_version = _sanitize_purl_version(version or "unknown")
    safe_pkg_name = name.replace(" ", "-").replace("/", "-")
    purl = f"pkg:generic/{safe_pkg_name}@{pkg_version}"
    pkg = build_spdx_package(
        spdx_id, name, version or pkg_version,
        github_url or "NOASSERTION", license_spdx, purl=purl,
    )
    return "custom", pkg, info


def _resolve_one_cpe(entry, bearer, bd_url, trust_cert):
    """Resolve a single entry via CPE lookup. Thread-safe."""
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
    """Try CPE lookup for all non-tier-1 packages to find BD KB matches.

    For packages with CPE in METADATA, uses that CPE.
    For packages without CPE, constructs search from package name and version.
    """
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
                      file=sys.stderr)

    futures = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        for entry in work_list:
            f = executor.submit(_resolve_one_cpe, entry, bearer,
                                bd_url, trust_cert)
            f.add_done_callback(on_done)
            futures.append(f)

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
                pkg["externalRefs"].extend([
                    {"referenceCategory": "OTHER",
                     "referenceType": "BlackDuck-Component",
                     "referenceLocator": bd_ref["comp_id"]},
                    {"referenceCategory": "OTHER",
                     "referenceType": "BlackDuck-ComponentVersion",
                     "referenceLocator": bd_ref["ver_id"]},
                ])
                if bd_ref.get("origin_id"):
                    pkg["externalRefs"].append(
                        {"referenceCategory": "OTHER",
                         "referenceType": "BlackDuck-ComponentOrigin",
                         "referenceLocator": bd_ref["origin_id"]})
            entry["bd_ref"] = bd_ref
            resolved += 1
            print(f"  CPE resolved: {pkg_name} -> "
                  f"{bd_ref['comp_id'][:8]}../{bd_ref['ver_id'][:8]}..",
                  file=sys.stderr)
        else:
            entry["cpe_failed"] = True

    return resolved


# ---------------------------------------------------------------------------
# GitHub version resolution
# ---------------------------------------------------------------------------

def _gh_api_request(url, github_token=None):
    """Make a GitHub API request. Returns parsed JSON or None on error."""
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    if github_token:
        req.add_header("Authorization", f"Bearer {github_token}")
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read().decode())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        log.debug("GitHub API error for %s: %s", url, exc)
        return None


def gh_find_tag_near_date(owner, repo, target_date, github_token=None):
    """Find the GitHub release/tag closest to *target_date*.

    The target_date is the AOSP last_upgrade_date — the date the package
    was upgraded. Prefers the earliest release on or after that date (the
    version it was upgraded TO). Falls back to the most recent release
    before the date when no later release exists (e.g. upgraded to a
    post-release commit).

    Tries the releases API first (has published_at dates).  Falls back to
    the tags API + commit date lookup if no releases exist.

    Returns (tag_name, published_date_str) or (None, None).
    """
    base = "https://api.github.com"

    # --- Strategy 1: Releases (paginated, sorted newest-first) ---
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

    # --- Strategy 2: Tags + commit date lookup ---
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
    """Resolve a single github_commit entry. Thread-safe (no shared mutation)."""
    info = entry["info"]
    github_path = info.get("github_path")
    last_upgrade = info.get("last_upgrade_date")

    if not github_path or not last_upgrade:
        return entry, None, None

    parts = github_path.split("/", 1)
    if len(parts) != 2:
        return entry, None, None

    owner, repo = parts
    tag, pub_date = gh_find_tag_near_date(owner, repo, last_upgrade,
                                          github_token)
    return entry, tag, pub_date


def resolve_github_versions(packages_by_tier, github_token=None):
    """Resolve tagged versions for github_commit packages using GitHub API.

    For each package in the github_commit tier that has a last_upgrade_date,
    queries GitHub for the nearest release/tag to that date (preferring
    the first on or after). Successfully resolved packages are promoted
    to github_purl tier.

    Returns the number of packages promoted.
    """
    commit_entries = packages_by_tier.get("github_commit", [])
    if not commit_entries:
        return 0

    total = len(commit_entries)
    print(f"\nResolving GitHub versions for {total} "
          f"commit-hash packages...", file=sys.stderr)

    done_count = 0
    lock = threading.Lock()

    def on_done(future):
        nonlocal done_count
        with lock:
            done_count += 1
            if done_count % 10 == 0 or done_count == total:
                print(f"  GitHub resolution: {done_count}/{total} done",
                      file=sys.stderr)

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
# BD KB version-by-date resolution
# ---------------------------------------------------------------------------

def _bd_find_component_by_github(bearer, owner_repo, bd_url, trust_cert=False):
    """Search BD KB for a component by GitHub owner/repo path.

    Returns (component_url, component_id) or (None, None).
    """
    q = urllib.request.quote(f"github:{owner_repo}")
    url = f"{bd_url.rstrip('/')}/api/components?q={q}&limit=5"
    try:
        resp = _api_request(url, bearer,
                            accept="application/vnd.blackducksoftware"
                                   ".component-detail-5+json",
                            trust_cert=trust_cert)
        data = json.loads(resp.read().decode())
    except Exception as exc:
        log.debug("BD component search failed for %s: %s", owner_repo, exc)
        return None, None

    if data.get("totalCount", 0) == 0:
        return None, None

    for item in data["items"]:
        if item.get("originId", "").lower() == owner_repo.lower():
            comp_url = item["component"]
            comp_id = comp_url.rsplit("/", 1)[-1]
            return comp_url, comp_id

    comp_url = data["items"][0].get("component")
    if comp_url:
        return comp_url, comp_url.rsplit("/", 1)[-1]
    return None, None


def _bd_find_version_near_date(bearer, comp_url, target_date,
                               bd_url, trust_cert=False):
    """Find the KB version closest to *target_date*.

    Prefers the earliest version on or after the date.  Falls back to the
    most recent version before the date when nothing later exists.
    Versions are sorted newest-first.

    Returns (version_name, released_date, ver_id) or (None, None, None).
    """
    url = f"{comp_url}/versions?limit=100&sort=releasedOn%20desc"
    try:
        resp = _api_request(url, bearer,
                            accept="application/vnd.blackducksoftware"
                                   ".component-detail-5+json",
                            trust_cert=trust_cert)
        data = json.loads(resp.read().decode())
    except Exception as exc:
        log.debug("BD version search failed for %s: %s", comp_url, exc)
        return None, None, None

    candidate_after = (None, None, None)
    candidate_before = (None, None, None)
    for v in data.get("items", []):
        released = v.get("releasedOn", "")[:10]
        if not released:
            continue
        ver_href = v.get("_meta", {}).get("href", "")
        ver_id = ver_href.rsplit("/", 1)[-1] if ver_href else None
        if released >= target_date:
            candidate_after = (v["versionName"], released, ver_id)
        else:
            if candidate_before[0] is None:
                candidate_before = (v["versionName"], released, ver_id)
            break

    if candidate_after[0] is not None:
        return candidate_after
    return candidate_before


def _bd_get_first_origin(bearer, comp_url, ver_id, trust_cert=False):
    """Get the first origin ID for a component version."""
    url = f"{comp_url}/versions/{ver_id}/origins?limit=1"
    try:
        resp = _api_request(url, bearer,
                            accept="application/vnd.blackducksoftware"
                                   ".component-detail-5+json",
                            trust_cert=trust_cert)
        data = json.loads(resp.read().decode())
    except Exception as exc:
        log.debug("BD origin lookup failed: %s", exc)
        return None

    items = data.get("items", [])
    if items:
        href = items[0].get("_meta", {}).get("href", "")
        if href:
            return href.rsplit("/", 1)[-1]
    return None


def _resolve_one_bd_kb(entry, bearer, bd_url, trust_cert):
    """Resolve a single github_commit entry via BD KB. Thread-safe."""
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
    """Resolve BD KB versions by date for remaining github_commit packages.

    For packages still in github_commit tier (no GitHub tags/releases found),
    searches the BD KB for the component by GitHub path, then finds the
    nearest version to the last_upgrade_date (preferring on or after).

    Matched packages get BD references added and are promoted to cpe_lookup
    tier (since they use BD internal references, same as CPE-resolved ones).

    Returns the number of packages promoted.
    """
    commit_entries = packages_by_tier.get("github_commit", [])
    if not commit_entries:
        return 0

    total = len(commit_entries)
    print(f"\nResolving BD KB versions by date for {total} "
          f"remaining commit-hash packages...", file=sys.stderr)

    done_count = 0
    lock = threading.Lock()

    def on_done(future):
        nonlocal done_count
        with lock:
            done_count += 1
            if done_count % 5 == 0 or done_count == total:
                print(f"  BD KB resolution: {done_count}/{total} done",
                      file=sys.stderr)

    futures = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        for entry in commit_entries:
            f = executor.submit(_resolve_one_bd_kb, entry, bearer,
                                bd_url, trust_cert)
            f.add_done_callback(on_done)
            futures.append(f)

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
            pkg["externalRefs"].extend([
                {"referenceCategory": "OTHER",
                 "referenceType": "BlackDuck-Component",
                 "referenceLocator": result["comp_id"]},
                {"referenceCategory": "OTHER",
                 "referenceType": "BlackDuck-ComponentVersion",
                 "referenceLocator": result["ver_id"]},
            ])
            if result["origin_id"]:
                pkg["externalRefs"].append(
                    {"referenceCategory": "OTHER",
                     "referenceType": "BlackDuck-ComponentOrigin",
                     "referenceLocator": result["origin_id"]})

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
# Main workflow
# ---------------------------------------------------------------------------

def collect_external_packages(repo_matches, aosp_root, android_version):
    """Parse metadata for all external repos and classify into tiers.

    Returns packages_by_tier dict: {tier_name: [{package, info}, ...]}.
    """
    packages_by_tier = {
        "github_purl": [],
        "cpe_lookup": [],
        "github_commit": [],
        "custom": [],
    }
    seen_spdx_ids = set()

    for repo_path in sorted(repo_matches.keys()):
        if not repo_path.startswith("external/"):
            continue

        metadata = {"name": None, "version": None, "cpe": None,
                    "github_url": None, "closest_version": None,
                    "top_version": None, "license_type": None,
                    "all_versions": []}
        if aosp_root:
            metadata_path = os.path.join(aosp_root, repo_path, "METADATA")
            metadata = parse_metadata(metadata_path)

        tier, pkg, info = classify_package(metadata, repo_path)

        if pkg["SPDXID"] in seen_spdx_ids:
            suffix = repo_path.replace("/", "-").replace(".", "-")
            pkg["SPDXID"] = f"SPDXRef-{suffix}"
        seen_spdx_ids.add(pkg["SPDXID"])

        packages_by_tier[tier].append({"package": pkg, "info": info})

    return packages_by_tier


def run_upload_workflow(packages_by_tier, bearer, bd_url, bd_project,
                        bd_version, trust_cert, skip_upload=False):
    """Execute the 2-pass upload workflow.

    Pass 1: Upload with tiers 1-3 (no autocreate) to check what matches.
    Pass 2: Add BD refs from CPE lookup for failed items, upload with autocreate.
    """
    all_packages = []
    for tier_entries in packages_by_tier.values():
        for entry in tier_entries:
            all_packages.append(entry["package"])

    if not all_packages:
        print("No packages to upload", file=sys.stderr)
        return

    doc_namespace = (f"https://aosp.spdx.org/sbom/"
                     f"{bd_project}-{bd_version}-{uuid.uuid4().hex[:8]}")

    # --- Pass 1: exploratory upload ---
    print(f"\n=== Pass 1: Exploratory upload ({len(all_packages)} packages) ===",
          file=sys.stderr)
    doc = build_spdx_document(all_packages, f"{bd_project}-{bd_version}",
                              doc_namespace)
    sbom_json = json.dumps(doc, indent=2)

    if skip_upload:
        output_path = f"{bd_project}-{bd_version}-sbom.spdx.json"
        with open(output_path, "w") as f:
            f.write(sbom_json)
        print(f"SBOM written to {output_path} (upload skipped)", file=sys.stderr)
        return

    status, scan_url = bd_upload_spdx(bearer, sbom_json, bd_url,
                                      autocreate=False,
                                      trust_cert=trust_cert)
    print(f"Upload HTTP {status}, polling scan...", file=sys.stderr)

    summary = bd_poll_scan(bearer, scan_url, bd_url, trust_cert=trust_cert)
    scan_state = summary.get("scanState")
    match_count = summary.get("matchCount", 0)
    print(f"Scan state: {scan_state}, matches: {match_count}", file=sys.stderr)

    events = bd_get_import_events(bearer, scan_url, bd_url,
                                  trust_cert=trust_cert)
    matched = [e for e in events
               if e["event"] == "COMPONENT_MAPPING_SUCCEEDED"]
    failed = [e for e in events
              if e["event"] == "COMPONENT_MAPPING_FAILED"]

    print(f"Pass 1 results: {len(matched)} matched, {len(failed)} failed",
          file=sys.stderr)

    # Clean up exploratory codelocation
    codeloc_href = _get_codeloc_href(summary)
    if codeloc_href:
        bd_delete_codelocation(bearer, codeloc_href, trust_cert)
        print("Cleaned up exploratory codelocation", file=sys.stderr)

    # --- Pass 2: final upload with autocreate ---
    all_packages_final = []
    for tier_entries in packages_by_tier.values():
        for entry in tier_entries:
            all_packages_final.append(entry["package"])

    doc_namespace_final = (f"https://aosp.spdx.org/sbom/"
                           f"{bd_project}-{bd_version}-final")
    doc_final = build_spdx_document(
        all_packages_final, f"{bd_project}-{bd_version}", doc_namespace_final)
    sbom_final = json.dumps(doc_final, indent=2)

    print(f"\n=== Pass 2: Final upload with autocreate ===", file=sys.stderr)
    status2, scan_url2 = bd_upload_spdx(bearer, sbom_final, bd_url,
                                        autocreate=True,
                                        trust_cert=trust_cert)
    print(f"Upload HTTP {status2}, polling scan...", file=sys.stderr)

    summary2 = bd_poll_scan(bearer, scan_url2, bd_url, trust_cert=trust_cert)
    scan_state2 = summary2.get("scanState")
    match_count2 = summary2.get("matchCount", 0)
    print(f"Scan state: {scan_state2}, matches: {match_count2}", file=sys.stderr)

    events2 = bd_get_import_events(bearer, scan_url2, bd_url,
                                   trust_cert=trust_cert)
    matched2 = [e for e in events2
                if e["event"] == "COMPONENT_MAPPING_SUCCEEDED"]
    failed2 = [e for e in events2
               if e["event"] == "COMPONENT_MAPPING_FAILED"]

    print(f"Pass 2 results: {len(matched2)} matched, {len(failed2)} failed",
          file=sys.stderr)

    # Map to project version
    codeloc_href2 = _get_codeloc_href(summary2)
    if codeloc_href2:
        project_href = bd_find_or_create_project(
            bearer, bd_project, bd_url, trust_cert)
        version_href = bd_find_or_create_version(
            bearer, project_href, bd_version, bd_url, trust_cert)
        bd_map_codelocation(bearer, codeloc_href2, version_href, trust_cert)
        print(f"Mapped codelocation to {bd_project}/{bd_version}",
              file=sys.stderr)

    # --- Final report ---
    print_report(packages_by_tier, events2)


def print_report(packages_by_tier, final_events):
    """Print a summary report of the matching results."""
    event_map = {}
    for e in final_events:
        event_map[e.get("importComponentName", "")] = e

    tier_labels = {
        "github_purl": "Tier 1: GitHub PURL",
        "cpe_lookup": "Tier 2: CPE -> BD Reference",
        "github_commit": "Tier 3: GitHub (commit hash)",
        "custom": "Tier 4: Custom Component",
    }

    print("\n" + "=" * 70)
    print("EXTERNAL PACKAGE MATCHING REPORT")
    print("=" * 70)

    total = 0
    total_matched = 0
    total_failed = 0

    for tier_name in ["github_purl", "cpe_lookup", "github_commit", "custom"]:
        entries = packages_by_tier.get(tier_name, [])
        if not entries:
            continue

        print(f"\n--- {tier_labels[tier_name]} ({len(entries)} packages) ---")
        matched = 0
        failed = 0
        for entry in entries:
            pkg = entry["package"]
            name = pkg["name"]
            event = event_map.get(name, {})
            status = event.get("event", "NO_EVENT")

            if status == "COMPONENT_MAPPING_SUCCEEDED":
                bd_name = event.get("componentName", "")
                bd_ver = event.get("componentVersionName", "")
                matched += 1
                log.debug("  MATCHED: %s -> %s %s", name, bd_name, bd_ver)
            elif status == "COMPONENT_MAPPING_FAILED":
                reason = event.get("failureReason", "")[:60]
                failed += 1
                log.debug("  FAILED:  %s (%s)", name, reason)
            else:
                failed += 1
                log.debug("  NO EVENT: %s", name)

        total += len(entries)
        total_matched += matched
        total_failed += failed
        print(f"  Matched: {matched}/{len(entries)}")
        if failed:
            print(f"  Failed:  {failed}/{len(entries)}")

    print(f"\n{'=' * 70}")
    print(f"TOTAL: {total_matched}/{total} matched "
          f"({total_matched * 100 // max(total, 1)}%)")
    if total_failed:
        print(f"       {total_failed} failed")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Generate SPDX 2.3 SBOM from AOSP external packages "
                    "and upload to Black Duck SCA"
    )
    parser.add_argument(
        "--module-info", required=True,
        help="Path to module-info.json from the AOSP build",
    )
    parser.add_argument(
        "--repo-list", required=True,
        help="Path to repo-list.txt from 'repo list'",
    )
    parser.add_argument(
        "--android-version", required=True,
        help="Android version string, e.g. android-16.0.0_r4",
    )
    parser.add_argument(
        "--bd-project", required=True,
        help="Black Duck project name",
    )
    parser.add_argument(
        "--bd-version", required=True,
        help="Black Duck project version",
    )
    parser.add_argument(
        "--aosp-root", default=None,
        help="Path to AOSP source root (for reading METADATA files)",
    )
    parser.add_argument(
        "--bd-api-token",
        default=os.environ.get("BLACKDUCK_API_TOKEN"),
        help="Black Duck API token (default: $BLACKDUCK_API_TOKEN)",
    )
    parser.add_argument(
        "--bd-url",
        default=os.environ.get("BLACKDUCK_URL"),
        help="Black Duck server URL (default: $BLACKDUCK_URL)",
    )
    parser.add_argument(
        "--bd-trust-cert", action="store_true",
        default=os.environ.get("BLACKDUCK_TRUST_CERT", "").lower()
        in ("1", "true", "yes"),
        help="Trust Black Duck server certificate",
    )
    parser.add_argument(
        "--list-packages", action="store_true",
        help="List package classification and exit without uploading",
    )
    parser.add_argument(
        "--metadata-dir", default=None,
        help="Directory containing METADATA files (one per package, named by "
             "package directory). Overrides --aosp-root for metadata lookup.",
    )
    parser.add_argument(
        "--skip-upload", action="store_true",
        help="Generate SBOM file but do not upload to Black Duck",
    )
    parser.add_argument(
        "--github-token",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub API token for higher rate limits "
             "(default: $GITHUB_TOKEN). Without a token, rate limit "
             "is 60 requests/hour.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    repos = parse_repo_list(args.repo_list)
    print(f"Loaded {len(repos)} repos", file=sys.stderr)

    installed_paths = extract_installed_paths(args.module_info)
    print(f"Found {len(installed_paths)} installed paths", file=sys.stderr)

    repo_matches, unmatched = map_paths_to_repos(installed_paths, repos)
    print(f"Mapped to {len(repo_matches)} repos "
          f"({len(unmatched)} unmatched)", file=sys.stderr)

    # Collect and classify external packages
    if args.metadata_dir:
        packages_by_tier = collect_from_metadata_dir(
            repo_matches, args.metadata_dir, args.android_version)
    else:
        packages_by_tier = collect_external_packages(
            repo_matches, args.aosp_root, args.android_version)

    # Resolve GitHub versions for commit-hash packages
    gh_promoted = resolve_github_versions(
        packages_by_tier, github_token=args.github_token)

    # Summary
    total = sum(len(v) for v in packages_by_tier.values())
    print(f"\nClassification of {total} external packages:", file=sys.stderr)
    for tier, entries in packages_by_tier.items():
        print(f"  {tier}: {len(entries)}", file=sys.stderr)

    if args.list_packages:
        print("\n--- Package Classification ---")
        for tier_name in ["github_purl", "cpe_lookup", "github_commit", "custom"]:
            entries = packages_by_tier.get(tier_name, [])
            if not entries:
                continue
            print(f"\n[{tier_name}] ({len(entries)} packages)")
            for entry in entries:
                pkg = entry["package"]
                info = entry["info"]
                purl = ""
                for ref in pkg["externalRefs"]:
                    if ref["referenceType"] == "purl":
                        purl = ref["referenceLocator"]
                        break
                print(f"  {info['repo_path']}: {pkg['name']} "
                      f"{pkg['versionInfo']} -> {purl}")
        return

    # Validate BD credentials
    if not args.bd_api_token:
        print("ERROR: --bd-api-token or $BLACKDUCK_API_TOKEN required",
              file=sys.stderr)
        sys.exit(1)
    if not args.bd_url:
        print("ERROR: --bd-url or $BLACKDUCK_URL required", file=sys.stderr)
        sys.exit(1)

    # Authenticate
    print("\nAuthenticating to Black Duck...", file=sys.stderr)
    bearer = bd_authenticate(args.bd_api_token, args.bd_url, args.bd_trust_cert)
    print("Authenticated successfully", file=sys.stderr)

    # Resolve remaining commit-hash packages via BD KB version-by-date
    kb_promoted = resolve_bd_kb_versions(
        packages_by_tier, bearer, args.bd_url, args.bd_trust_cert)
    if kb_promoted:
        print(f"BD KB date-resolved {kb_promoted} packages", file=sys.stderr)

    # Resolve CPE packages (tier 2) before upload
    cpe_resolved = resolve_cpe_packages(
        packages_by_tier, bearer, args.bd_url, args.bd_trust_cert)
    if cpe_resolved:
        print(f"CPE pre-resolved {cpe_resolved} packages", file=sys.stderr)

    # Run upload workflow
    run_upload_workflow(
        packages_by_tier, bearer, args.bd_url,
        args.bd_project, args.bd_version, args.bd_trust_cert,
        skip_upload=args.skip_upload,
    )


def collect_from_metadata_dir(repo_matches, metadata_dir, android_version):
    """Collect packages using pre-extracted metadata files from a directory."""
    packages_by_tier = {
        "github_purl": [],
        "cpe_lookup": [],
        "github_commit": [],
        "custom": [],
    }
    seen_spdx_ids = set()

    for repo_path in sorted(repo_matches.keys()):
        if not repo_path.startswith("external/"):
            continue

        pkg_name = repo_path.split("/")[-1]
        metadata_path = os.path.join(metadata_dir, pkg_name)

        metadata = {"name": None, "version": None, "cpe": None,
                    "github_url": None, "closest_version": None,
                    "top_version": None, "license_type": None,
                    "all_versions": []}

        if os.path.isfile(metadata_path):
            metadata = parse_metadata(metadata_path)
        else:
            log.debug("No metadata file for %s at %s", pkg_name, metadata_path)

        tier, pkg, info = classify_package(metadata, repo_path)

        if pkg["SPDXID"] in seen_spdx_ids:
            suffix = repo_path.replace("/", "-").replace(".", "-")
            pkg["SPDXID"] = f"SPDXRef-{suffix}"
        seen_spdx_ids.add(pkg["SPDXID"])

        packages_by_tier[tier].append({"package": pkg, "info": info})

    return packages_by_tier


if __name__ == "__main__":
    main()
