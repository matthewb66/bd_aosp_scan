#!/usr/bin/env python3
"""Generate a Black Duck BDIO v2 file from AOSP build artifacts."""

import argparse
import json
import logging
import os
import re
import subprocess
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone

log = logging.getLogger(__name__)

BDIO = "https://blackducksoftware.github.io/bdio#"


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


def parse_metadata(metadata_path):
    result = {"name": None, "version": None, "cpe": None, "homepage": None,
              "git_url": None}

    try:
        with open(metadata_path) as f:
            content = f.read()
    except (OSError, IOError):
        log.debug("No METADATA file at %s", metadata_path)
        return result

    name_match = re.search(r'^name:\s*"([^"]*)"', content, re.MULTILINE)
    if name_match:
        result["name"] = name_match.group(1)

    version_match = re.search(r'^\s*version:\s*"([^"]*)"', content, re.MULTILINE)
    if version_match:
        result["version"] = version_match.group(1)

    cpe_match = re.search(
        r'identifier\s*\{[^}]*type:\s*"cpe"[^}]*value:\s*"([^"]*)"',
        content, re.DOTALL
    )
    if not cpe_match:
        cpe_match = re.search(
            r'identifier\s*\{[^}]*value:\s*"(cpe:[^"]*)"[^}]*type:\s*"cpe"',
            content, re.DOTALL
        )
    if cpe_match:
        result["cpe"] = cpe_match.group(1)

    for block in re.findall(r'url\s*\{(.*?)\}', content, flags=re.DOTALL):
        if re.search(r'type:\s*GIT', block, re.IGNORECASE):
            match = re.search(r'value:\s*"([^"]+)"', block)
            if match:
                result["git_url"] = match.group(1)
                break

    if not result["git_url"]:
        for block in re.findall(r'identifier\s*\{(.*?)\}', content, flags=re.DOTALL):
            if re.search(r'type:\s*"[Gg]it"', block):
                match = re.search(r'value:\s*"([^"]+)"', block)
                if match:
                    result["git_url"] = match.group(1)
                    break

    log.debug("METADATA %s: name=%s version=%s cpe=%s git_url=%s",
              metadata_path, result["name"], result["version"],
              result["cpe"], result["git_url"])
    return result


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


def parse_github_path(git_url):
    match = re.match(
        r'https?://github\.com/([^/]+/[^/]+?)(?:\.git)?(?:/.*)?$', git_url,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


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


SIGSCAN_BATCH_SIZE = 4 * 1024 * 1024 * 1024  # 4 GB


def dir_size(path):
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def run_detect(scan_dir, bd_project, bd_version, bd_api_token, bd_url,
               bd_trust_cert, batch_num):
    detect_script = os.path.join(tempfile.gettempdir(), "detect11.sh")
    if not os.path.exists(detect_script):
        subprocess.run(
            ["curl", "-s", "-L",
             "https://detect.blackduck.com/detect11.sh",
             "-o", detect_script],
            check=True,
        )
        os.chmod(detect_script, 0o755)

    cmd = [
        "bash", detect_script,
        f"--blackduck.api.token={bd_api_token}",
        f"--blackduck.url={bd_url}",
        f"--detect.project.name={bd_project}",
        f"--detect.project.version.name={bd_version}",
        f"--detect.source.path={scan_dir}",
        f"--detect.project.codelocation.suffix=-{batch_num}",
        "--detect.excluded.directories='*test*'",
        "--detect.excluded.directories.search.depth=8"
    ]
    if bd_trust_cert:
        cmd.append("--blackduck.trust.cert=true")

    print(f"Running Detect signature scan (batch {batch_num})...",
          file=sys.stderr)
    log.debug("Detect command: %s", " ".join(cmd))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"Detect batch {batch_num} exited with code {result.returncode}",
              file=sys.stderr)
    else:
        print(f"Detect batch {batch_num} completed successfully",
              file=sys.stderr)


def run_sigscan_external(skipped_external, aosp_root, bd_project, bd_version,
                         bd_api_token, bd_url, bd_trust_cert):
    external_dir = os.path.join(aosp_root, "external")
    bdignore_path = os.path.join(external_dir, ".bdignore")

    all_folders = set()
    for entry in os.listdir(external_dir):
        if os.path.isdir(os.path.join(external_dir, entry)):
            all_folders.add(entry)

    batch_num = 1
    batch_size = 0
    batch_repos = 0
    batch_folder_names = set()
    total_repos = 0

    print(f"Preparing signature scan for {len(skipped_external)} external repos",
          file=sys.stderr)

    def _run_batch():
        nonlocal batch_num, batch_size, batch_repos, batch_folder_names
        print(f"Batch {batch_num}: {batch_repos} repos, "
              f"{batch_size / (1024**3):.1f} GB — running Detect",
              file=sys.stderr)
        exclude = all_folders - batch_folder_names
        print("Creating .bdignore file:")
        with open(bdignore_path, "w") as f:
            for folder in sorted(exclude):
                f.write(f"/{folder}/\n")
                print(f"/{folder}/")
        log.debug(".bdignore excludes %d of %d folders",
                  len(exclude), len(all_folders))
        try:
            run_detect(external_dir, bd_project, bd_version, bd_api_token,
                       bd_url, bd_trust_cert, batch_num)
        finally:
            if os.path.exists(bdignore_path):
                os.remove(bdignore_path)
        batch_num += 1
        batch_size = 0
        batch_repos = 0
        batch_folder_names = set()

    try:
        for repo_path, reason in skipped_external:
            src = os.path.join(aosp_root, repo_path)
            if not os.path.isdir(src):
                print(f"  Skipping {repo_path}: not a directory", file=sys.stderr)
                continue

            repo_size = dir_size(src)
            log.debug("%s size: %.1f MB", repo_path, repo_size / (1024 * 1024))

            if batch_size > 0 and batch_size + repo_size > SIGSCAN_BATCH_SIZE:
                _run_batch()

            folder_name = repo_path.split("/", 1)[1] if "/" in repo_path else repo_path
            batch_folder_names.add(folder_name)
            batch_size += repo_size
            batch_repos += 1
            total_repos += 1
            print(f"  Added {total_repos}/{len(skipped_external)}: "
                  f"{repo_path} ({repo_size / (1024 * 1024):.1f} MB)",
                  file=sys.stderr)

        if batch_repos > 0:
            _run_batch()

        print(f"Signature scan complete: {total_repos} repos in "
              f"{batch_num - 1} batch(es)", file=sys.stderr)
    finally:
        if os.path.exists(bdignore_path):
            os.remove(bdignore_path)


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

    repos = parse_repo_list(args.repo_list)
    if subfolder:
        before = len(repos)
        repos = {k: v for k, v in repos.items()
                 if k == subfolder or k.startswith(subfolder + '/')}
        log.debug("Subfolder filtered repos: %d -> %d", before, len(repos))
    if not args.list_packages:
        print(f"Loaded {len(repos)} repos from {args.repo_list}", file=sys.stderr)

    installed_paths = extract_installed_paths(args.module_info)
    if subfolder:
        before = len(installed_paths)
        installed_paths = [p for p in installed_paths
                           if p == subfolder or p.startswith(subfolder + '/')]
        log.debug("Subfolder filtered paths: %d -> %d", before, len(installed_paths))
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
                        "homepage": None, "git_url": None}
            if args.aosp_root:
                metadata_path = os.path.join(args.aosp_root, repo_path, "METADATA")
                metadata = parse_metadata(metadata_path)
            else:
                log.debug("No --aosp-root, skipping METADATA for %s", repo_path)

            git_url = metadata.get("git_url")
            if not git_url or not re.search(r'github\.com', git_url, re.IGNORECASE):
                log.debug("Skipping %s: %s", repo_path, git_url or "no GIT URL")
                skipped_external.append(
                    (repo_path, git_url or "no GIT URL")
                )
                continue

            github_path = parse_github_path(git_url)
            if not github_path:
                log.debug("Skipping %s: could not parse github path from %s",
                          repo_path, git_url)
                skipped_external.append((repo_path, f"bad github URL: {git_url}"))
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

    if args.sigscan_external and skipped_external:
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
