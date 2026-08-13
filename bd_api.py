"""Black Duck REST API helpers: auth, CPE lookup, component search, upload, polling."""

import json
import logging
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

from aosp_metadata import _is_commit_hash

log = logging.getLogger(__name__)


def _ssl_ctx(trust_cert):
    if not trust_cert:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _api_request(url, bearer, method="GET", data=None, accept=None,
                 content_type=None, trust_cert=False, timeout=60):
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {bearer}")
    if accept:
        req.add_header("Accept", accept)
    if content_type:
        req.add_header("Content-Type", content_type)
    ctx = _ssl_ctx(trust_cert)
    resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
    return resp


def bd_authenticate(api_token, bd_url, trust_cert=False):
    """Authenticate and return (bearer_token, user_url)."""
    base = bd_url.rstrip("/")
    url = f"{base}/api/tokens/authenticate"
    req = urllib.request.Request(url, data=b"", method="POST")
    req.add_header("Authorization", f"token {api_token}")
    req.add_header("Accept", "application/vnd.blackducksoftware.user-4+json")
    resp = urllib.request.urlopen(req, context=_ssl_ctx(trust_cert))
    data = json.loads(resp.read())
    bearer = data["bearerToken"]
    log.debug("Auth response keys: %s", list(data.keys()))

    user_url = None
    for link in data.get("_meta", {}).get("links", []):
        if link["rel"] == "user":
            user_url = link["href"]
            break
    if not user_url:
        for candidate in (f"{base}/api/current-user",
                          f"{base}/api/currentuser"):
            try:
                _api_request(
                    candidate, bearer,
                    accept="application/vnd.blackducksoftware.user-4+json",
                    trust_cert=trust_cert)
                user_url = candidate
                break
            except Exception:
                continue
    log.debug("User URL: %s", user_url)

    return bearer, user_url


# ---------------------------------------------------------------------------
# CPE lookup
# ---------------------------------------------------------------------------

def _bd_cpe_direct_query(bearer, cpe, bd_url, trust_cert=False):
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

        if "cpe-origins" in links:
            origin_result = _follow_origins(bearer, links["cpe-origins"], trust_cert)
            if origin_result:
                return origin_result

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
    _, cpe_product, cpe_version = _parse_cpe_string(cpe_from_metadata)
    product = cpe_product or pkg_name.lower().replace(' ', '_')
    clean_ver = _extract_clean_version(pkg_version)
    if cpe_version:
        clean_ver = cpe_version

    if cpe_from_metadata:
        result = _bd_cpe_direct_query(bearer, cpe_from_metadata, bd_url,
                                      trust_cert)
        if result:
            log.debug("  CPE strategy 1 (exact METADATA CPE): matched")
            return result

    if not product:
        return None

    if clean_ver:
        cpe = f"cpe:2.3:a:*:{product}:{clean_ver}:*:*:*:*:*:*:*"
        result = _bd_cpe_direct_query(bearer, cpe, bd_url, trust_cert)
        if result:
            log.debug("  CPE strategy 2 (wildcard vendor, ver=%s): matched",
                      clean_ver)
            return result

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


# ---------------------------------------------------------------------------
# Upload / scan polling
# ---------------------------------------------------------------------------

def bd_upload_spdx(bearer, sbom_content, bd_url, autocreate=False,
                   trust_cert=False, project_name=None, version_name=None):
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
    query_parts = []
    if project_name:
        query_parts.append(
            f"projectName={urllib.request.quote(project_name, safe='')}")
    if version_name:
        query_parts.append(
            f"versionName={urllib.request.quote(version_name, safe='')}")
    if query_parts:
        url = f"{url}?{'&'.join(query_parts)}"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {bearer}")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    ctx = _ssl_ctx(trust_cert)
    log.debug("SPDX upload URL: %s", url)
    max_retries = 3
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                req = urllib.request.Request(url, data=body, method="POST")
                req.add_header("Authorization", f"Bearer {bearer}")
                req.add_header("Content-Type",
                               f"multipart/form-data; boundary={boundary}")
            resp = urllib.request.urlopen(req, context=ctx)
            scan_url = resp.headers.get("Location", "")
            return resp.getcode(), scan_url
        except urllib.error.HTTPError as e:
            if e.code >= 500 and attempt < max_retries - 1:
                wait = 10 * (attempt + 1)
                print(f"SPDX upload failed: HTTP {e.code} — "
                      f"retrying in {wait}s (attempt {attempt + 1}/"
                      f"{max_retries})", file=sys.stderr)
                time.sleep(wait)
                continue
            error_body = ""
            try:
                error_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            print(f"SPDX upload failed: HTTP {e.code} {e.reason}\n"
                  f"URL: {url}\nResponse: {error_body[:2000]}",
                  file=sys.stderr)
            raise


def bd_poll_scan(bearer, scan_url, bd_url, trust_cert=False,
                 max_polls=30, interval=5):
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
    scan_id = scan_url.rstrip("/").split("/")[-1]
    url = (f"{bd_url.rstrip('/')}/api/bom-import/{scan_id}/"
           f"component-import-events?limit=1000")
    resp = _api_request(url, bearer, trust_cert=trust_cert)
    data = json.loads(resp.read())
    return data.get("items", [])


# ---------------------------------------------------------------------------
# Project / version / codelocation management
# ---------------------------------------------------------------------------

def bd_find_or_create_project(bearer, project_name, bd_url, trust_cert=False):
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
    payload = json.dumps({"mappedProjectVersion": version_href}).encode()
    _api_request(
        codeloc_href, bearer, method="PUT", data=payload,
        content_type="application/json", trust_cert=trust_cert,
    )


def bd_delete_codelocation(bearer, codeloc_href, trust_cert=False):
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
# BOM component queries and CPE management
# ---------------------------------------------------------------------------

def bd_get_bom_components(bearer, version_href, trust_cert=False):
    """Return all BOM components for a project version (handles pagination)."""
    items = []
    limit = 1000
    offset = 0
    while True:
        url = f"{version_href}/components?limit={limit}&offset={offset}"
        resp = _api_request(
            url, bearer,
            accept="application/vnd.blackducksoftware"
                   ".bill-of-materials-6+json",
            trust_cert=trust_cert)
        data = json.loads(resp.read())
        page = data.get("items", [])
        items.extend(page)
        total = data.get("totalCount", len(items))
        if len(items) >= total or not page:
            break
        offset += limit
    return items


def bd_set_component_version_cpe(bearer, version_href, cpe,
                                 trust_cert=False):
    """Set CPE on a custom component version via PUT. Returns True on success."""
    payload = json.dumps({"cpe": cpe}).encode()
    try:
        _api_request(
            version_href, bearer, method="PUT", data=payload,
            content_type="application/vnd.blackducksoftware"
                         ".component-detail-5+json",
            accept="application/vnd.blackducksoftware"
                   ".component-detail-5+json",
            trust_cert=trust_cert)
        return True
    except urllib.error.HTTPError as exc:
        log.debug("Failed to set CPE %s on %s: %s",
                  cpe, version_href, exc)
        return False


# ---------------------------------------------------------------------------
# KB search (GitHub, AOSP, version-by-date)
# ---------------------------------------------------------------------------

def _bd_find_component_by_github(bearer, owner_repo, bd_url, trust_cert=False):
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


def _bd_find_component_by_android(bearer, aosp_name, bd_url, trust_cert=False):
    q = urllib.request.quote(f"android:{aosp_name}")
    url = f"{bd_url.rstrip('/')}/api/components?q={q}&limit=5"
    try:
        resp = _api_request(url, bearer,
                            accept="application/vnd.blackducksoftware"
                                   ".component-detail-5+json",
                            trust_cert=trust_cert)
        data = json.loads(resp.read().decode())
    except Exception as exc:
        log.debug("BD AOSP component search failed for %s: %s",
                  aosp_name, exc)
        return None, None

    if data.get("totalCount", 0) == 0:
        return None, None

    comp_url = data["items"][0].get("component")
    if comp_url:
        return comp_url, comp_url.rsplit("/", 1)[-1]
    return None, None


def _bd_find_version_by_name(bearer, comp_url, version_name,
                             bd_url, trust_cert=False):
    q = urllib.request.quote(version_name)
    url = f"{comp_url}/versions?limit=100&q={q}"
    try:
        resp = _api_request(url, bearer,
                            accept="application/vnd.blackducksoftware"
                                   ".component-detail-5+json",
                            trust_cert=trust_cert)
        data = json.loads(resp.read().decode())
    except Exception as exc:
        log.debug("BD version search failed for %s: %s", comp_url, exc)
        return None, None

    for v in data.get("items", []):
        if v.get("versionName") == version_name:
            ver_href = v.get("_meta", {}).get("href", "")
            ver_id = ver_href.rsplit("/", 1)[-1] if ver_href else None
            if ver_id:
                return v["versionName"], ver_id
    return None, None
