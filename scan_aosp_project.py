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
import sys

__version__ = "1.0"
import uuid

from aosp_metadata import extract_installed_paths, map_paths_to_repos, parse_repo_list
from bd_api import (
    bd_authenticate,
    bd_delete_codelocation,
    bd_find_or_create_project,
    bd_find_or_create_version,
    bd_get_import_events,
    bd_poll_scan,
    bd_upload_spdx,
    _get_codeloc_href,
)
from detect_scan import run_sigscan_external
from resolve_external import (
    resolve_aosp_repo_packages,
    resolve_bd_kb_versions,
    resolve_cpe_packages,
    resolve_github_versions,
)
from spdx_builder import (
    build_spdx_document,
    collect_external_packages,
    collect_from_metadata_dir,
    collect_platform_packages,
)

log = logging.getLogger(__name__)

VALID_SCAN_MODES = {
    "GITHUB_REPOS", "KB_LOOKUP", "CPE_LOOKUP", "AOSP_REPOS", "SIG_SCAN",
    "CUSTOM_COMPS",
}
PRESET_MODES = {
    "DEFAULT": {"GITHUB_REPOS", "KB_LOOKUP", "CPE_LOOKUP", "CUSTOM_COMPS"},
    "ALL": {"GITHUB_REPOS", "KB_LOOKUP", "CPE_LOOKUP", "AOSP_REPOS", "SIG_SCAN",
            "CUSTOM_COMPS"},
    "NONE": set(),
}


def parse_scan_modes(raw):
    """Parse --external-scan-modes value into a set of active modes.

    Accepts a comma-delimited list of mode names, or a preset
    (ALL, DEFAULT, NONE).  Returns a frozenset of active mode strings.
    """
    if raw is None:
        return frozenset(PRESET_MODES["DEFAULT"])

    raw = raw.strip().upper()
    if raw in PRESET_MODES:
        return frozenset(PRESET_MODES[raw])

    modes = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if token in PRESET_MODES:
            modes |= PRESET_MODES[token]
        elif token in VALID_SCAN_MODES:
            modes.add(token)
        else:
            valid = ", ".join(sorted(VALID_SCAN_MODES | set(PRESET_MODES)))
            print(f"ERROR: Unknown scan mode '{token}'. "
                  f"Valid modes: {valid}", file=sys.stderr)
            sys.exit(1)
    return frozenset(modes)


def _upload_and_map(packages, bearer, bd_url, bd_project, bd_version,
                    trust_cert, autocreate, doc_suffix, label):
    """Upload an SPDX SBOM and map the codelocation to the project version."""
    doc_namespace = (f"https://aosp.spdx.org/sbom/"
                     f"{bd_project}-{bd_version}-{doc_suffix}")
    doc = build_spdx_document(
        packages, f"{bd_project}-{bd_version}-{doc_suffix}", doc_namespace)
    sbom_json = json.dumps(doc, indent=2)

    ac_label = "autocreate=on" if autocreate else "autocreate=off"
    print(f"\n=== {label} ({len(packages)} packages, {ac_label}) ===",
          file=sys.stderr)

    status, scan_url = bd_upload_spdx(bearer, sbom_json, bd_url,
                                      autocreate=autocreate,
                                      trust_cert=trust_cert,
                                      project_name=bd_project,
                                      version_name=bd_version)
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
    print(f"Results: {len(matched)} matched, {len(failed)} failed",
          file=sys.stderr)

    return events


def run_platform_upload(platform_packages, bearer, bd_url, bd_project,
                        bd_version, trust_cert, skip_upload=False,
                        autocreate=True):
    """Upload platform repo packages as a single SPDX SBOM (no exploratory pass)."""
    if not platform_packages:
        print("No platform packages to upload", file=sys.stderr)
        return

    if skip_upload:
        doc_namespace = (f"https://aosp.spdx.org/sbom/"
                         f"{bd_project}-{bd_version}-platform")
        doc = build_spdx_document(
            platform_packages, f"{bd_project}-{bd_version}-platform",
            doc_namespace)
        output_path = f"{bd_project}-{bd_version}-platform-sbom.spdx.json"
        with open(output_path, "w") as f:
            json.dump(doc, f, indent=2)
        print(f"Platform SBOM written to {output_path} (upload skipped)",
              file=sys.stderr)
        return

    events = _upload_and_map(
        platform_packages, bearer, bd_url, bd_project, bd_version,
        trust_cert, autocreate=autocreate, doc_suffix="platform",
        label="Platform upload")

    matched = sum(1 for e in events
                  if e["event"] == "COMPONENT_MAPPING_SUCCEEDED")
    print(f"\nPlatform: {matched}/{len(platform_packages)} matched",
          file=sys.stderr)


def run_upload_workflow(packages_by_tier, bearer, bd_url, bd_project,
                        bd_version, trust_cert, skip_upload=False,
                        autocreate=True):
    """Execute the 2-pass upload workflow for external packages.

    Pass 1: Upload without autocreate to check what matches.
    Pass 2: Upload with autocreate (if enabled) to create custom components.
    """
    all_packages = []
    for tier_entries in packages_by_tier.values():
        for entry in tier_entries:
            all_packages.append(entry["package"])

    if not all_packages:
        print("No external packages to upload", file=sys.stderr)
        return

    if skip_upload:
        doc_namespace = (f"https://aosp.spdx.org/sbom/"
                         f"{bd_project}-{bd_version}-external")
        doc = build_spdx_document(
            all_packages, f"{bd_project}-{bd_version}-external", doc_namespace)
        output_path = f"{bd_project}-{bd_version}-external-sbom.spdx.json"
        with open(output_path, "w") as f:
            json.dump(doc, f, indent=2)
        print(f"External SBOM written to {output_path} (upload skipped)",
              file=sys.stderr)
        return

    # --- Pass 1: exploratory upload ---
    doc_namespace = (f"https://aosp.spdx.org/sbom/"
                     f"{bd_project}-{bd_version}-{uuid.uuid4().hex[:8]}")
    doc = build_spdx_document(all_packages, f"{bd_project}-{bd_version}",
                              doc_namespace)
    sbom_json = json.dumps(doc, indent=2)

    print(f"\n=== External Pass 1: Exploratory upload "
          f"({len(all_packages)} packages) ===", file=sys.stderr)
    status, scan_url = bd_upload_spdx(bearer, sbom_json, bd_url,
                                      autocreate=False,
                                      trust_cert=trust_cert,
                                      project_name=bd_project,
                                      version_name=bd_version)
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

    codeloc_href = _get_codeloc_href(summary)
    if codeloc_href:
        bd_delete_codelocation(bearer, codeloc_href, trust_cert)
        print("Cleaned up exploratory codelocation", file=sys.stderr)

    # --- Pass 2: final upload ---
    events2 = _upload_and_map(
        all_packages, bearer, bd_url, bd_project, bd_version,
        trust_cert, autocreate=autocreate, doc_suffix="external",
        label="External Pass 2: Final upload")

    # --- Final report ---
    print_report(packages_by_tier, events2)


def print_report(packages_by_tier, final_events):
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
        "--version", action="version",
        version=f"%(prog)s {__version__}",
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
        "--external-scan-modes", default=None,
        help="Comma-separated scan modes: GITHUB_REPOS,KB_LOOKUP,CPE_LOOKUP,"
             "AOSP_REPOS,SIG_SCAN,CUSTOM_COMPS. Presets: ALL, DEFAULT, NONE. "
             "Default: DEFAULT (GITHUB_REPOS,KB_LOOKUP,CPE_LOOKUP,"
             "CUSTOM_COMPS)",
    )
    parser.add_argument(
        "--no-custom-components", action="store_true",
        help="Disable autocreate for all uploads (platform and external). "
             "Overrides CUSTOM_COMPS scan mode.",
    )
    parser.add_argument(
        "--external-repo-custom", default="AOSP_REPOS",
        choices=["AOSP_REPOS", "OTHER"],
        help="PURL type for external custom components. AOSP_REPOS (default) "
             "uses pkg:android/platform-* for all. OTHER uses pkg:github "
             "where available, pkg:generic otherwise.",
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

    print(f"scan_aosp_project v{__version__}", file=sys.stderr)

    scan_modes = parse_scan_modes(args.external_scan_modes)
    print(f"External scan modes: {', '.join(sorted(scan_modes)) or 'NONE'}",
          file=sys.stderr)

    repos = parse_repo_list(args.repo_list)
    print(f"Loaded {len(repos)} repos", file=sys.stderr)

    installed_paths = extract_installed_paths(args.module_info)
    print(f"Found {len(installed_paths)} installed paths", file=sys.stderr)

    repo_matches, unmatched = map_paths_to_repos(installed_paths, repos)
    print(f"Mapped to {len(repo_matches)} repos "
          f"({len(unmatched)} unmatched)", file=sys.stderr)

    # Collect platform (non-external) repos
    platform_packages = collect_platform_packages(
        repo_matches, args.android_version)
    print(f"Collected {len(platform_packages)} platform repo packages",
          file=sys.stderr)

    # Collect and classify external packages
    packages_by_tier = {
        "github_purl": [], "cpe_lookup": [],
        "github_commit": [], "custom": [],
    }

    if not scan_modes:
        print("External scanning disabled (mode NONE)", file=sys.stderr)
    elif args.metadata_dir:
        packages_by_tier = collect_from_metadata_dir(
            repo_matches, args.metadata_dir, args.android_version,
            custom_purl=args.external_repo_custom)
    else:
        packages_by_tier = collect_external_packages(
            repo_matches, args.aosp_root, args.android_version,
            custom_purl=args.external_repo_custom)

    # Resolve GitHub versions for commit-hash packages
    if "GITHUB_REPOS" in scan_modes:
        gh_promoted = resolve_github_versions(
            packages_by_tier, github_token=args.github_token)

    # Summary
    total_external = sum(len(v) for v in packages_by_tier.values())
    print(f"\nClassification: {len(platform_packages)} platform, "
          f"{total_external} external packages of which:", file=sys.stderr)
    for tier, entries in packages_by_tier.items():
        if entries:
            print(f"  {tier}: {len(entries)}", file=sys.stderr)

    if args.list_packages:
        print("\n--- Package Classification ---")

        if platform_packages:
            print(f"\n[platform] ({len(platform_packages)} packages)")
            for pkg in platform_packages:
                purl = ""
                for ref in pkg["externalRefs"]:
                    if ref["referenceType"] == "purl":
                        purl = ref["referenceLocator"]
                        break
                print(f"  {pkg['name']} {pkg['versionInfo']} -> {purl}")

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
    if "KB_LOOKUP" in scan_modes:
        kb_promoted = resolve_bd_kb_versions(
            packages_by_tier, bearer, args.bd_url, args.bd_trust_cert)
        if kb_promoted:
            print(f"BD KB date-resolved {kb_promoted} packages",
                  file=sys.stderr)

    # Resolve CPE packages (tier 2) before upload
    if "CPE_LOOKUP" in scan_modes:
        cpe_resolved = resolve_cpe_packages(
            packages_by_tier, bearer, args.bd_url, args.bd_trust_cert)
        if cpe_resolved:
            print(f"CPE pre-resolved {cpe_resolved} packages",
                  file=sys.stderr)

    # Resolve packages via AOSP repo PURLs
    if "AOSP_REPOS" in scan_modes:
        aosp_resolved = resolve_aosp_repo_packages(
            packages_by_tier, args.android_version, bearer,
            args.bd_url, args.bd_trust_cert)
        if aosp_resolved:
            print(f"AOSP repo-resolved {aosp_resolved} packages",
                  file=sys.stderr)

    # Signature scan via Detect CLI
    if "SIG_SCAN" in scan_modes:
        if not args.aosp_root:
            print("ERROR: --aosp-root is required for SIG_SCAN mode",
                  file=sys.stderr)
            sys.exit(1)
        unmatched_repos = []
        for tier_name in ["github_commit", "custom"]:
            for entry in packages_by_tier.get(tier_name, []):
                if not entry.get("bd_ref"):
                    repo_path = entry["info"].get("repo_path", "")
                    unmatched_repos.append((repo_path, "unmatched"))
        if unmatched_repos:
            print(f"\nRunning signature scan for {len(unmatched_repos)} "
                  f"unmatched external repos...", file=sys.stderr)
            run_sigscan_external(
                unmatched_repos, args.aosp_root,
                args.bd_project, args.bd_version,
                args.bd_api_token, args.bd_url, args.bd_trust_cert,
                detect_tools="SIGNATURE_SCAN",
                codelocation_prefix="sigscan-",
            )
        else:
            print("SIG_SCAN: no unmatched repos to scan", file=sys.stderr)

    autocreate = not args.no_custom_components

    if not args.skip_upload:
        print("\nEnsuring project version exists...", file=sys.stderr)
        project_href = bd_find_or_create_project(
            bearer, args.bd_project, args.bd_url, args.bd_trust_cert)
        bd_find_or_create_version(
            bearer, project_href, args.bd_version, args.bd_url,
            args.bd_trust_cert)
        print(f"Project version ready: {args.bd_project} / {args.bd_version}",
              file=sys.stderr)

    # Upload platform repos (single pass)
    run_platform_upload(
        platform_packages, bearer, args.bd_url,
        args.bd_project, args.bd_version, args.bd_trust_cert,
        skip_upload=args.skip_upload,
        autocreate=autocreate,
    )

    # Upload external packages (2-pass exploratory workflow)
    ext_autocreate = ("CUSTOM_COMPS" in scan_modes) and autocreate
    run_upload_workflow(
        packages_by_tier, bearer, args.bd_url,
        args.bd_project, args.bd_version, args.bd_trust_cert,
        skip_upload=args.skip_upload,
        autocreate=ext_autocreate,
    )


if __name__ == "__main__":
    main()
