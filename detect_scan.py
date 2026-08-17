"""Detect CLI invocation and signature scan batching."""

import logging
import os
import subprocess
import sys
import tempfile

log = logging.getLogger(__name__)

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
               bd_trust_cert, batch_num, detect_tools=None,
               codelocation_prefix=""):
    detect_script = os.path.join(tempfile.gettempdir(), "detect11.sh")
    if not os.path.exists(detect_script):
        subprocess.run(
            ["curl", "-s", "-L",
             "https://detect.blackduck.com/detect11.sh",
             "-o", detect_script],
            check=True,
        )
        os.chmod(detect_script, 0o755)

    suffix = f"-{codelocation_prefix}{batch_num}" if codelocation_prefix \
        else f"-{batch_num}"
    cmd = [
        "bash", detect_script,
        f"--blackduck.api.token={bd_api_token}",
        f"--blackduck.url={bd_url}",
        f"--detect.project.name={bd_project}",
        f"--detect.project.version.name={bd_version}",
        f"--detect.source.path={scan_dir}",
        f"--detect.project.codelocation.suffix={suffix}",
        "--detect.excluded.directories='*test*'",
        "--detect.excluded.directories.search.depth=8",
    ]
    if detect_tools:
        cmd.append(f"--blackduck.tools={detect_tools}")
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


def _build_bdignore_tree(batch_repo_paths, external_dir):
    """Write .bdignore files at each directory level to include only batch repos.

    Returns list of absolute paths to all .bdignore files created.
    """
    include_tree = {}
    for repo_path in batch_repo_paths:
        parts = repo_path.split("/")[1:]
        for i in range(len(parts)):
            parent_key = "/".join(parts[:i]) if i > 0 else ""
            include_tree.setdefault(parent_key, set()).add(parts[i])

    created_files = []
    for dir_key, included_children in include_tree.items():
        abs_dir = os.path.join(external_dir, dir_key) if dir_key else external_dir

        if not os.path.isdir(abs_dir):
            log.debug("Skipping .bdignore for non-existent dir: %s", abs_dir)
            continue

        try:
            all_children = {
                entry for entry in os.listdir(abs_dir)
                if os.path.isdir(os.path.join(abs_dir, entry))
            }
        except OSError:
            log.debug("Cannot list directory: %s", abs_dir)
            continue

        exclude = all_children - included_children
        if not exclude:
            continue

        bdignore_path = os.path.join(abs_dir, ".bdignore")
        with open(bdignore_path, "w") as f:
            for folder in sorted(exclude):
                f.write(f"/{folder}/\n")
        created_files.append(bdignore_path)
        log.debug(".bdignore at %s: excluding %d of %d folders",
                  abs_dir, len(exclude), len(all_children))

    return created_files


def _cleanup_bdignore_files(file_paths):
    for path in file_paths:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError as e:
            log.warning("Failed to remove %s: %s", path, e)


def run_sigscan_external(skipped_external, aosp_root, bd_project, bd_version,
                         bd_api_token, bd_url, bd_trust_cert,
                         detect_tools=None, codelocation_prefix=""):
    external_dir = os.path.join(aosp_root, "external")
    all_created_bdignore = []

    batch_num = 1
    batch_size = 0
    batch_repos = 0
    batch_repo_paths = []
    total_repos = 0

    print(f"Preparing signature scan for {len(skipped_external)} external repos",
          file=sys.stderr)

    def _run_batch():
        nonlocal batch_num, batch_size, batch_repos, batch_repo_paths
        print(f"Batch {batch_num}: {batch_repos} repos, "
              f"{batch_size / (1024**3):.1f} GB — running Detect",
              file=sys.stderr)
        created_files = _build_bdignore_tree(batch_repo_paths, external_dir)
        all_created_bdignore.extend(created_files)
        try:
            run_detect(external_dir, bd_project, bd_version, bd_api_token,
                       bd_url, bd_trust_cert, batch_num,
                       detect_tools=detect_tools,
                       codelocation_prefix=codelocation_prefix)
        finally:
            _cleanup_bdignore_files(created_files)
        batch_num += 1
        batch_size = 0
        batch_repos = 0
        batch_repo_paths = []

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

            batch_repo_paths.append(repo_path)
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
        _cleanup_bdignore_files(all_created_bdignore)
