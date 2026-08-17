#!/usr/bin/env python3
"""
delete_custom_components.py

Finds and deletes all custom component versions from a Black Duck server.
When the last version of a custom component is deleted, the parent component
is also deleted.

Reads connection details from environment variables:
  BLACKDUCK_URL           – e.g. https://sca.demo.blackduck.com
  BLACKDUCK_API_TOKEN     – API token
  BLACKDUCK_TRUST_CERT    – set to 'true' to skip TLS verification (optional)

Usage:
  python delete_custom_components.py [--dry-run]
"""

import argparse
import logging
import os
import re
import sys
from collections import defaultdict

from blackduck import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# Matches .../api/components/{compId}/versions/{verId}
_COMP_VER_RE = re.compile(
    r'/api/components/([^/]+)/versions/([^/?]+)'
)


def connect() -> Client:
    bd_url = os.environ.get('BLACKDUCK_URL', '').rstrip('/')
    bd_api = os.environ.get('BLACKDUCK_API_TOKEN', '')
    trust_cert = os.environ.get('BLACKDUCK_TRUST_CERT', '').lower() == 'true'

    if not bd_url or not bd_api:
        logger.error(
            "BLACKDUCK_URL and BLACKDUCK_API_TOKEN environment variables must be set"
        )
        sys.exit(1)

    logger.info(f"Connecting to Black Duck: {bd_url}")
    bd = Client(
        token=bd_api,
        base_url=bd_url,
        verify=(not trust_cert),
        timeout=60,
    )
    return bd


def fetch_custom_versions_by_component(bd: Client) -> dict[str, list[str]]:
    """
    Pages through /api/approval-status/component-versions?filter=componentSource:custom
    and returns a dict mapping componentId -> [versionId, ...].
    """
    base_url = bd.base_url.rstrip('/')
    limit = 100
    offset = 0
    comp_versions: dict[str, list[str]] = defaultdict(list)

    while True:
        url = (
            f"{base_url}/api/approval-status/component-versions"
            f"?filter=componentSource%3Acustom&limit={limit}&offset={offset}"
        )
        logger.info(f"  Fetching custom component versions (offset={offset}) …")
        data = bd.get_json(
            url,
            headers={'Accept': 'application/vnd.blackducksoftware.internal-1+json'},
        )

        total = data.get('totalCount', 0)
        items = data.get('items', [])

        if not items:
            break

        for item in items:
            href = item.get('_meta', {}).get('href', '')
            match = _COMP_VER_RE.search(href)
            if match:
                comp_versions[match.group(1)].append(match.group(2))
            else:
                logger.warning(f"  Could not parse IDs from href: {href}")

        offset += len(items)
        logger.info(f"  Retrieved {offset} / {total}")

        if offset >= total:
            break

    return dict(comp_versions)


def delete_component_version(bd: Client, base_url: str, component_id: str,
                             version_id: str, dry_run: bool) -> bool:
    delete_url = f"{base_url}/api/components/{component_id}/versions/{version_id}"

    if dry_run:
        logger.info(f"  [DRY RUN] Would DELETE version  {delete_url}")
        return True

    try:
        response = bd.session.delete(delete_url)
        if response.status_code == 204:
            logger.info(f"  Deleted version  component={component_id}  version={version_id}")
            return True
        else:
            logger.warning(
                f"  DELETE version returned {response.status_code} for "
                f"component={component_id} version={version_id}: {response.text[:200]}"
            )
            return False
    except Exception as e:
        logger.error(f"  Error deleting version {delete_url}: {e}")
        return False


def delete_component(bd: Client, base_url: str, component_id: str, dry_run: bool) -> bool:
    delete_url = f"{base_url}/api/components/{component_id}"

    if dry_run:
        logger.info(f"  [DRY RUN] Would DELETE component {delete_url}")
        return True

    try:
        response = bd.session.delete(delete_url)
        if response.status_code == 204:
            logger.info(f"  Deleted component  component={component_id}")
            return True
        else:
            logger.warning(
                f"  DELETE component returned {response.status_code} for "
                f"component={component_id}: {response.text[:200]}"
            )
            return False
    except Exception as e:
        logger.error(f"  Error deleting component {delete_url}: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Delete all custom component versions from a Black Duck server, "
                    "then delete the parent component when its last version is removed"
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help="List what would be deleted without actually deleting anything",
    )
    args = parser.parse_args()

    if args.dry_run:
        logger.info("DRY RUN mode – no deletions will be performed")

    bd = connect()
    base_url = bd.base_url.rstrip('/')

    logger.info("Fetching custom component versions …")
    comp_versions = fetch_custom_versions_by_component(bd)

    total_versions = sum(len(v) for v in comp_versions.values())
    logger.info(
        f"Found {total_versions} custom component version(s) "
        f"across {len(comp_versions)} component(s)"
    )

    if not comp_versions:
        logger.info("Nothing to delete.")
        return

    versions_deleted = 0
    versions_failed = 0
    components_deleted = 0
    components_failed = 0

    for component_id, version_ids in comp_versions.items():
        # Delete all versions except the last — the API rejects deletion of the
        # last version. The parent component DELETE below handles the last one.
        all_but_last = version_ids[:-1]
        ver_ok = True
        for version_id in all_but_last:
            if delete_component_version(bd, base_url, component_id, version_id, args.dry_run):
                versions_deleted += 1
            else:
                versions_failed += 1
                ver_ok = False

        if ver_ok:
            # Delete the parent component (implicitly removes the last version)
            if delete_component(bd, base_url, component_id, args.dry_run):
                components_deleted += 1
                versions_deleted += 1  # last version removed via parent delete
            else:
                components_failed += 1
        else:
            logger.warning(
                f"  Skipping parent component deletion for component={component_id} "
                f"(one or more earlier version deletions failed)"
            )
            components_failed += 1

    action = "Would delete" if args.dry_run else "Deleted"
    logger.info(
        f"{action} {versions_deleted} version(s) ({versions_failed} failed); "
        f"{action.lower()} {components_deleted} parent component(s) "
        f"({components_failed} skipped/failed)"
    )


if __name__ == '__main__':
    main()
