"""Version normalization and matching utilities for tag/version comparison."""

import re


def normalize_version(tag_string):
    """Extract the core version number from a tag or version string.

    Examples:
        v1.0.29         -> 1.0.29
        libusb-1.0.29   -> 1.0.29
        curl-8_16_0     -> 8.16.0
        BCEL_6_2        -> 6.2
        R_2_7_1         -> 2.7.1
        v1.0.29-rc1     -> 1.0.29
        release-1.2.3   -> 1.2.3
        rel/foo-1.2.3   -> 1.2.3
    """
    if not tag_string:
        return None
    s = tag_string.strip()

    if '/' in s:
        s = s.rsplit('/', 1)[-1]

    for prefix in ('release-', 'rel-', 'v_', 'R_', 'V_'):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    else:
        if re.match(r'^[vV]\d', s):
            s = s[1:]

    m = re.match(r'^([a-zA-Z][\w]*(?:[-_][a-zA-Z][\w]*)*)[-_](\d[\d._].*)', s)
    if m:
        s = m.group(2)

    s = s.replace('_', '.')

    s = re.sub(r'[-.]?(rc|beta|alpha|pre|dev|post|snapshot)\d*$', '',
               s, flags=re.IGNORECASE)

    if re.match(r'^\d[\d.]*', s):
        return s
    return None


def version_matches(v1, v2):
    """Check if two normalized version strings are equivalent.

    Ignores trailing .0 segments: 1.2 matches 1.2.0.
    """
    if v1 == v2:
        return True

    def strip_trailing_zeros(v):
        parts = v.split('.')
        while len(parts) > 1 and parts[-1] == '0':
            parts.pop()
        return '.'.join(parts)

    return strip_trailing_zeros(v1) == strip_trailing_zeros(v2)


def find_best_tag_match(tags, target_version):
    """Find the best matching tag for a target version.

    Normalizes each tag, finds matches against target_version, and ranks
    by preference: shorter tags, v-prefixed, no qualifiers.

    Returns the best tag name string, or None if no match.
    """
    matches = []
    for tag in tags:
        norm = normalize_version(tag)
        if norm and version_matches(norm, target_version):
            score = 0
            if re.search(r'(rc|beta|alpha|pre|dev|post|snapshot)\d*',
                         tag, re.IGNORECASE):
                score += 100
            if re.match(r'^[vV]\d', tag):
                score -= 5
            elif not re.match(r'^\d', tag):
                score += 10
            score += len(tag)
            matches.append((score, tag))

    if not matches:
        return None
    matches.sort()
    return matches[0][1]
