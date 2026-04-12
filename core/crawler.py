import re
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup


def _xml_parser():
    """Return the best available BeautifulSoup parser for XML documents."""
    try:
        import lxml  # noqa: F401
        return "lxml-xml"
    except ImportError:
        pass
    return "html.parser"


_XML_PARSER = _xml_parser()


def _to_absolute(ref, base_url, target_domain):
    """Convert a relative or protocol-relative URL to an absolute URL.
    Returns None if the URL belongs to a different domain."""
    if not ref or not ref.strip():
        return None

    ref = ref.strip()

    if ref.startswith("//"):
        ref = "https:" + ref
    elif ref.startswith("/"):
        ref = base_url.rstrip("/") + ref
    elif not ref.startswith("http"):
        ref = base_url.rstrip("/") + "/" + ref

    parsed = urlparse(ref)
    if parsed.netloc and parsed.netloc != target_domain:
        return None

    return ref


def fetch_robots(base_url, timeout=5, headers=None):
    """Fetch and parse robots.txt for disallowed/allowed paths and sitemap URLs."""
    result = {"paths": [], "sitemaps": []}
    robots_url = base_url.rstrip("/") + "/robots.txt"

    try:
        resp = requests.get(robots_url, headers=headers, timeout=timeout,
                            verify=False, allow_redirects=True)
        if resp.status_code != 200:
            return result

        paths = set()
        sitemaps = []

        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Extract Disallow / Allow paths
            for directive in ("Disallow:", "Allow:"):
                if line.lower().startswith(directive.lower()):
                    path = line[len(directive):].strip()
                    if path and path != "/":
                        # Remove wildcards and query strings
                        path = path.split("*")[0].split("?")[0].rstrip("$")
                        if path and path.startswith("/"):
                            paths.add(path)
                    break

            # FIX #1: Proper sitemap URL extraction
            # Original code used line.split(":", 1) which breaks on "https://"
            if line.lower().startswith("sitemap:"):
                sitemap_url = line[len("Sitemap:"):].strip()
                # Handle case-insensitive "Sitemap:" with varying cases
                if not sitemap_url:
                    # Try splitting after first colon that's part of directive
                    idx = line.lower().index("sitemap:")
                    sitemap_url = line[idx + len("sitemap:"):].strip()

                if sitemap_url:
                    if sitemap_url.startswith("//"):
                        sitemap_url = "https:" + sitemap_url
                    elif sitemap_url.startswith("/"):
                        sitemap_url = base_url.rstrip("/") + sitemap_url
                    # Only add if it looks like a valid URL
                    if sitemap_url.startswith("http"):
                        sitemaps.append(sitemap_url)

        result["paths"] = sorted(paths)
        result["sitemaps"] = sitemaps

    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    return result


def fetch_sitemap(sitemap_url, timeout=5, headers=None, visited=None, depth=0,
                  max_paths=500, max_sitemaps=5):
    """Recursively fetch and parse sitemap XML files for URL paths.

    Args:
        max_paths: Maximum total paths to collect (default: 500).
                   Prevents 20,000+ path explosions from large sitemaps.
        max_sitemaps: Maximum nested sitemaps to follow (default: 5).
    """
    MAX_DEPTH = 5
    if depth > MAX_DEPTH:
        return []

    if visited is None:
        visited = set()

    if sitemap_url in visited:
        return []
    visited.add(sitemap_url)

    paths = set()

    try:
        resp = requests.get(sitemap_url, headers=headers, timeout=timeout, verify=False)
        if resp.status_code != 200:
            return []

        soup = BeautifulSoup(resp.text, _XML_PARSER)

        # Handle sitemap index files (nested sitemaps) — with limit
        sitemap_tags = soup.find_all("sitemap")
        if sitemap_tags:
            sitemaps_followed = 0
            for sm in sitemap_tags:
                if sitemaps_followed >= max_sitemaps:
                    break
                loc = sm.find("loc")
                if loc and loc.text:
                    nested_paths = fetch_sitemap(
                        loc.text.strip(), timeout, headers, visited, depth + 1,
                        max_paths=max_paths - len(paths), max_sitemaps=max_sitemaps,
                    )
                    paths.update(nested_paths)
                    sitemaps_followed += 1
                    if len(paths) >= max_paths:
                        break

        # Handle regular URL entries — with limit
        url_tags = soup.find_all("url")
        for url_tag in url_tags:
            if len(paths) >= max_paths:
                break
            loc = url_tag.find("loc")
            if loc and loc.text:
                full_url = loc.text.strip()
                parsed = urlparse(full_url)
                path = parsed.path
                if path and path != "/":
                    paths.add(path.rstrip("/") if path != "/" else path)

    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    return sorted(paths)


def discover_js_files(base_url, timeout=5, headers=None):
    """Discover JavaScript files from the target's homepage HTML."""
    js_files = set()
    target_domain = urlparse(base_url).netloc

    try:
        resp = requests.get(base_url, headers=headers, timeout=timeout, verify=False)
        if resp.status_code != 200:
            return []

        soup = BeautifulSoup(resp.text, "html.parser")

        # Find <script src="..."> tags
        for script in soup.find_all("script", src=True):
            src = script["src"].strip()
            if not src:
                continue

            abs_url = _to_absolute(src, base_url, target_domain)
            if not abs_url:
                continue

            parsed = urlparse(abs_url)
            if (parsed.path.endswith(".js")
                    or ".js?" in parsed.path
                    or ".js?" in abs_url):
                js_files.add(abs_url)
            elif any(kw in abs_url for kw in ("/js/", "/javascript/", "bundle", "chunk")):
                js_files.add(abs_url)

        # FIX #2: Also check template literals (backtick strings) for JS refs
        for script in soup.find_all("script"):
            if script.string:
                # Match both quoted and backtick-quoted JS file references
                inline_refs = re.findall(
                    r'["\'\`]([^"\'\`]+\.js(?:\?[^"\'\`]*)?)["\'\`]',
                    script.string
                )
                for ref in inline_refs:
                    abs_url = _to_absolute(ref, base_url, target_domain)
                    if abs_url:
                        js_files.add(abs_url)

    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    return sorted(js_files)