#!/usr/bin/env python3
"""Generate a Black Duck BDIO v2 file from AOSP build artifacts (legacy)."""

import argparse
import json
import logging
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone

from aosp_metadata import (
    _has_github,
    extract_installed_paths,
    map_paths_to_repos,
    parse_github_path,
    parse_metadata,
    parse_repo_list,
)
from detect_scan import run_sigscan_external

log = logging.getLogger(__name__)

BDIO = "https://blackducksoftware.github.io/bdio#"


def val(v):
    return [{"@value": v}]


def component_id(namespace, name, version):
    return f"http:{namespace}/{name}/{version}"


def build_component_node(comp_id, identifier, name, namespace, version):
    return {
        "@id": comp_id,
        "@type": [f"{BDIO}Component"],
        f"{BDIO}hasIdentifier": val(identifier),
        f"{BDIO}hasName": val(name),
        f"{BDIO}hasNamespace": val(namespace),
        f"{BDIO}hasVersion": val(version),
    }


def build_dependency_ref(target_id):
    return {
        "@type": [f"{BDIO}Dependency"],
        f"{BDIO}dependsOn": [{"@id": target_id}],
    }


def build_github_component(github_path, pkg_version):
    comp_id = component_id("github", github_path, pkg_version)
    identifier = f"{github_path}:{pkg_version}"
    log.debug("GitHub component: %s -> %s", github_path, identifier)

    return comp_id, identifier, build_component_node(
        comp_id, identifier, github_path, "github", pkg_version,
    )


def build_platform_component(repo_path, android_version):
    pkg_name = f"platform-{repo_path.replace('/', '-')}"

    comp_id = component_id("android", pkg_name, android_version)
    identifier = f"{pkg_name}:{android_version}"
    log.debug("Platform component: %s -> %s", repo_path, identifier)

    return comp_id, identifier, build_component_node(
        comp_id, identifier, pkg_name, "android", android_version,
    )


def generate_bdio(component_ids, component_nodes, bd_project, bd_version):
    doc_uuid = str(uuid.uuid4())
    doc_urn = f"urn:uuid:{doc_uuid}"
    mytime = datetime.now(timezone.utc)
    log.debug("Generating BDIO: project=%s version=%s uuid=%s components=%d",
              bd_project, bd_version, doc_uuid, len(component_ids))

    project_id = component_id(
        "android", f"{bd_project}/{bd_version}", f"{bd_version}/-android"
    )
    project_identifier = f"{bd_project}:{bd_version}:-android"

    dependencies = [build_dependency_ref(cid) for cid in component_ids]

    project_node = {
        "@id": project_id,
        "@type": [f"{BDIO}Project"],
        f"{BDIO}hasDependency": dependencies,
        f"{BDIO}hasIdentifier": val(project_identifier),
        f"{BDIO}hasName": val(bd_project),
        f"{BDIO}hasNamespace": val("android"),
        f"{BDIO}hasVersion": val(bd_version),
    }

    root_id = f"http:detect/{bd_project}/{bd_version}"
    root_node = {
        "@id": root_id,
        "@type": [f"{BDIO}Project"],
        f"{BDIO}hasIdentifier": val(f"{bd_project}/{bd_version}"),
        f"{BDIO}hasName": val(bd_project),
        f"{BDIO}hasNamespace": val("root"),
        f"{BDIO}hasSubproject": [{"@id": project_id}],
        f"{BDIO}hasVersion": val(bd_version),
    }

    graph = [project_node, root_node] + component_nodes

    header = {
        "@id": doc_urn,
        "@type": "PACKAGE_MANAGER",
        f"{BDIO}hasCreationDateTime": [{
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
            "@value": mytime.isoformat(),
        }],
        f"{BDIO}hasName": val(f"{bd_project}/{bd_version} bdio"),
        f"{BDIO}hasProject": val(bd_project),
        f"{BDIO}hasProjectVersion": val(bd_version),
        f"{BDIO}hasPublisher": [{
            "@type": f"{BDIO}Products",
            "@value": "aosp-bdio-generator",
        }],
        "@graph": [],
    }

    entry = {
        "@id": doc_urn,
        "@type": "PACKAGE_MANAGER",
        "@graph": graph,
    }

    return header, entry


def _bd_authenticate(bd_api_token, bd_url, bd_trust_cert):
    url = f"{bd_url.rstrip('/')}/api/tokens/authenticate"
    req = urllib.request.Request(url, data=b"", method="POST")
    req.add_header("Authorization", f"token {bd_api_token}")
    req.add_header("Accept", "application/vnd.blackducksoftware.user-4+json")

    ctx = None
    if bd_trust_cert:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    log.debug("Authenticating to %s", url)
    response = urllib.request.urlopen(req, context=ctx)
    data = json.loads(response.read())
    return data["bearerToken"]


def upload_bdio(bdio_path, bd_project, bd_version, bd_api_token, bd_url,
                bd_trust_cert):
    bearer_token = _bd_authenticate(bd_api_token, bd_url, bd_trust_cert)

    boundary = uuid.uuid4().hex
    content_type = f"multipart/form-data; boundary={boundary}"

    parts = []

    with open(bdio_path, "rb") as f:
        file_data = f.read()
    filename = os.path.basename(bdio_path)
    parts.append(
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        f"Content-Type: application/vnd.blackducksoftware.bdio+zip\r\n"
        f"\r\n"
    )
    parts.append(file_data)
    parts.append(b"\r\n")

    for field_name, field_value in [("projectName", bd_project),
                                     ("versionName", bd_version)]:
        parts.append(
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"{field_name}\"\r\n"
            f"\r\n"
            f"{field_value}\r\n"
        )

    parts.append(f"--{boundary}--\r\n")

    body = b""
    for part in parts:
        body += part.encode("utf-8") if isinstance(part, str) else part

    url = f"{bd_url.rstrip('/')}/api/scan/data"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {bearer_token}")
    req.add_header("Content-Type", content_type)

    ctx = None
    if bd_trust_cert:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    log.debug("Uploading BDIO to %s (%d bytes)", url, len(body))
    response = urllib.request.urlopen(req, context=ctx)
    status = response.getcode()
    log.debug("Upload response: %d", status)
    return status


def main():
    parser = argparse.ArgumentParser(
        description="Generate Black Duck BDIO v2 from AOSP build artifacts"
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
        "--bd_project", required=True,
        help="Black Duck project name",
    )
    parser.add_argument(
        "--bd_version", required=True,
        help="Black Duck project version",
    )
    parser.add_argument(
        "--aosp-root", default=None,
        help="Path to AOSP source root (for reading METADATA files in external/)",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Output BDIO file path (default: aosp-sbom.bdio). "
             "If omitted and BD credentials are set, the file is auto-uploaded",
    )
    parser.add_argument(
        "--subfolder",
        help="Only process repos/paths within this subfolder (e.g. external)",
    )
    parser.add_argument(
        "--list-packages", action="store_true",
        help="List package identifiers and exit without generating BDIO",
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
        default=os.environ.get("BLACKDUCK_TRUST_CERT", "").lower() in ("1", "true", "yes"),
        help="Trust Black Duck server certificate (default: $BLACKDUCK_TRUST_CERT)",
    )
    parser.add_argument(
        "--sigscan-external", action="store_true", default=False,
        help="Run signature scan on external repos",
    )
    parser.add_argument(
        "--exclude-subfolders",
        default="",
        help="Comma-separated list of top-level subfolders to exclude "
             "(e.g. external,prebuilts). Repos within these folders are "
             "omitted from the BDIO. If 'external' is excluded, "
             "--sigscan-external is ignored.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    output_specified = args.output is not None
    if not output_specified:
        args.output = "aosp-sbom.bdio"

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    subfolder = args.subfolder.rstrip('/') if args.subfolder else None
    if subfolder:
        log.debug("Subfolder filter: %s", subfolder)

    exclude_subfolders = set()
    if args.exclude_subfolders:
        exclude_subfolders = {f.strip().rstrip('/')
                              for f in args.exclude_subfolders.split(',')
                              if f.strip()}
    if exclude_subfolders:
        log.debug("Excluding subfolders: %s", ", ".join(sorted(exclude_subfolders)))
        if not args.list_packages:
            print(f"Excluding subfolders: {', '.join(sorted(exclude_subfolders))}",
                  file=sys.stderr)

    repos = parse_repo_list(args.repo_list)
    if subfolder:
        before = len(repos)
        repos = {k: v for k, v in repos.items()
                 if k == subfolder or k.startswith(subfolder + '/')}
        log.debug("Subfolder filtered repos: %d -> %d", before, len(repos))
    if exclude_subfolders:
        before = len(repos)
        repos = {k: v for k, v in repos.items()
                 if not any(k == ex or k.startswith(ex + '/')
                            for ex in exclude_subfolders)}
        log.debug("Exclude-subfolders filtered repos: %d -> %d", before, len(repos))
    if not args.list_packages:
        print(f"Loaded {len(repos)} repos from {args.repo_list}", file=sys.stderr)

    installed_paths = extract_installed_paths(args.module_info)
    if subfolder:
        before = len(installed_paths)
        installed_paths = [p for p in installed_paths
                           if p == subfolder or p.startswith(subfolder + '/')]
        log.debug("Subfolder filtered paths: %d -> %d", before, len(installed_paths))
    if exclude_subfolders:
        before = len(installed_paths)
        installed_paths = [p for p in installed_paths
                           if not any(p == ex or p.startswith(ex + '/')
                                      for ex in exclude_subfolders)]
        log.debug("Exclude-subfolders filtered paths: %d -> %d",
                  before, len(installed_paths))
    if not args.list_packages:
        print(f"Found {len(installed_paths)} installed paths", file=sys.stderr)

    repo_matches, unmatched = map_paths_to_repos(installed_paths, repos)
    if not args.list_packages:
        print(
            f"Mapped to {len(repo_matches)} repos "
            f"({len(unmatched)} paths unmatched)",
            file=sys.stderr,
        )

    component_ids = []
    component_identifiers = []
    component_nodes = []
    external_count = 0
    platform_count = 0
    skipped_external = []

    for repo_path in sorted(repo_matches.keys()):
        if repo_path.startswith("external/"):
            log.debug("Processing external repo: %s", repo_path)
            metadata = {"name": None, "version": None, "cpe": None,
                        "github_url": None}
            if args.aosp_root:
                metadata_path = os.path.join(args.aosp_root, repo_path, "METADATA")
                metadata = parse_metadata(metadata_path)
            else:
                log.debug("No --aosp-root, skipping METADATA for %s", repo_path)

            github_url = metadata.get("github_url")
            if not github_url:
                log.debug("Skipping %s: no GitHub URL found", repo_path)
                skipped_external.append((repo_path, "no GitHub URL"))
                continue

            github_path = parse_github_path(github_url)
            if not github_path:
                log.debug("Skipping %s: could not parse github path from %s",
                          repo_path, github_url)
                skipped_external.append(
                    (repo_path, f"bad GitHub URL: {github_url}"))
                continue

            pkg_version = metadata["version"] or args.android_version
            log.debug("External %s -> github:%s@%s", repo_path, github_path,
                      pkg_version)
            comp_id, identifier, node = build_github_component(
                github_path, pkg_version,
            )
            external_count += 1
        else:
            comp_id, identifier, node = build_platform_component(
                repo_path, args.android_version,
            )
            platform_count += 1
        component_ids.append(comp_id)
        component_identifiers.append(identifier)
        component_nodes.append(node)

    if args.list_packages:
        for identifier in component_identifiers:
            print(identifier)
        return

    if skipped_external:
        print(
            f"Skipped {len(skipped_external)} external repos (non-github):",
            file=sys.stderr,
        )
        for path, reason in skipped_external:
            print(f"  {path}: {reason}", file=sys.stderr)

    print(
        f"Generated {len(component_nodes)} components "
        f"({platform_count} platform, {external_count} external)",
        file=sys.stderr,
    )

    header, entry = generate_bdio(
        component_ids, component_nodes, args.bd_project, args.bd_version,
    )

    with zipfile.ZipFile(args.output, 'w', zipfile.ZIP_DEFLATED) as zf:
        header_json = json.dumps(header, indent=2)
        entry_json = json.dumps(entry, indent=2)
        zf.writestr("bdio-header.jsonld", header_json)
        zf.writestr("bdio-entry-00.jsonld", entry_json)
        log.debug("BDIO header size: %d bytes, entry size: %d bytes",
                  len(header_json), len(entry_json))

    print(f"BDIO written to {args.output}", file=sys.stderr)

    if not output_specified and args.bd_api_token and args.bd_url:
        print("Uploading BDIO to Black Duck...", file=sys.stderr)
        try:
            status = upload_bdio(
                args.output, args.bd_project, args.bd_version,
                args.bd_api_token, args.bd_url, args.bd_trust_cert,
            )
            print(f"Upload successful (HTTP {status})", file=sys.stderr)
        except urllib.error.HTTPError as e:
            print(f"ERROR: Upload failed: HTTP {e.code} {e.reason}",
                  file=sys.stderr)
            sys.exit(1)
        except urllib.error.URLError as e:
            print(f"ERROR: Upload failed: {e.reason}", file=sys.stderr)
            sys.exit(1)

    if args.sigscan_external and "external" in exclude_subfolders:
        print("--sigscan-external ignored: 'external' is in --exclude-subfolders",
              file=sys.stderr)
    elif args.sigscan_external and skipped_external:
        missing = []
        if not args.bd_api_token:
            missing.append("--bd-api-token or $BLACKDUCK_API_TOKEN")
        if not args.bd_url:
            missing.append("--bd-url or $BLACKDUCK_URL")
        if not args.aosp_root:
            missing.append("--aosp-root")
        if missing:
            print(f"ERROR: --sigscan-external requires: {', '.join(missing)}",
                  file=sys.stderr)
            sys.exit(1)
        run_sigscan_external(
            skipped_external, args.aosp_root, args.bd_project, args.bd_version,
            args.bd_api_token, args.bd_url, args.bd_trust_cert,
        )


if __name__ == "__main__":
    main()
