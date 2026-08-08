"""SPDX document construction, package classification, and external package collection."""

import logging
import os
import re
import uuid
from datetime import datetime, timezone

from aosp_metadata import _has_github, _is_commit_hash, parse_github_path, parse_metadata

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


def build_spdx_package(spdx_id, name, version, download_location,
                       license_spdx, purl=None, cpe=None, bd_ref=None):
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


def _sanitize_purl_version(version):
    if not version:
        return "unknown"
    return re.sub(r'[^a-zA-Z0-9._-]', '-', version)


def classify_package(metadata, repo_path, android_version):
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

    if github_path and version and _is_commit_hash(version):
        purl = f"pkg:github/{github_path}@{version}"
        pkg = build_spdx_package(
            spdx_id, name, version,
            github_url, license_spdx, purl=purl,
        )
        return "github_commit", pkg, info

    pkg_name = f"platform-{repo_path.replace('/', '-')}"
    purl = f"pkg:android/{pkg_name}@{android_version}"
    pkg = build_spdx_package(
        spdx_id, pkg_name, android_version,
        github_url or "NOASSERTION", license_spdx, purl=purl,
    )
    return "custom", pkg, info


def collect_platform_packages(repo_matches, android_version):
    """Build SPDX packages for non-external (platform) repos.

    Each repo gets a pkg:android/platform-{dashed-path}@{android_version} PURL.
    Returns a list of SPDX package dicts.
    """
    packages = []
    seen_spdx_ids = set()

    for repo_path in sorted(repo_matches.keys()):
        if repo_path.startswith("external/"):
            continue

        pkg_name = f"platform-{repo_path.replace('/', '-')}"
        safe_id = re.sub(r'[^a-zA-Z0-9._-]', '-', pkg_name)
        spdx_id = f"SPDXRef-{safe_id}"

        if spdx_id in seen_spdx_ids:
            suffix = repo_path.replace("/", "-").replace(".", "-")
            spdx_id = f"SPDXRef-{suffix}"
        seen_spdx_ids.add(spdx_id)

        purl = f"pkg:android/{pkg_name}@{android_version}"
        pkg = build_spdx_package(
            spdx_id, pkg_name, android_version,
            "NOASSERTION", "NOASSERTION", purl=purl,
        )
        packages.append(pkg)

    return packages


def collect_external_packages(repo_matches, aosp_root, android_version):
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

        tier, pkg, info = classify_package(metadata, repo_path, android_version)

        if pkg["SPDXID"] in seen_spdx_ids:
            suffix = repo_path.replace("/", "-").replace(".", "-")
            pkg["SPDXID"] = f"SPDXRef-{suffix}"
        seen_spdx_ids.add(pkg["SPDXID"])

        packages_by_tier[tier].append({"package": pkg, "info": info})

    return packages_by_tier


def collect_from_metadata_dir(repo_matches, metadata_dir, android_version):
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

        sub_path = repo_path.split("/", 1)[1]

        metadata_path = os.path.join(metadata_dir, sub_path, "METADATA")

        metadata = {"name": None, "version": None, "cpe": None,
                    "github_url": None, "closest_version": None,
                    "top_version": None, "license_type": None,
                    "all_versions": []}

        if os.path.isfile(metadata_path):
            metadata = parse_metadata(metadata_path)
        else:
            log.debug("No metadata file for %s", sub_path)

        tier, pkg, info = classify_package(metadata, repo_path, android_version)

        if pkg["SPDXID"] in seen_spdx_ids:
            suffix = repo_path.replace("/", "-").replace(".", "-")
            pkg["SPDXID"] = f"SPDXRef-{suffix}"
        seen_spdx_ids.add(pkg["SPDXID"])

        packages_by_tier[tier].append({"package": pkg, "info": info})

    return packages_by_tier
