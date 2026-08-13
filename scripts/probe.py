#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""One-shot reconnaissance of the Larimer County inspections portal.

This session's network policy blocks inspections.myhealthdepartment.com, so this
script runs in CI (which has open egress) and dumps everything needed to write
the real scraper into the job log. It is throwaway: delete once scraper.py works.
"""

from __future__ import annotations

import json
import re
import sys
from urllib.parse import urljoin, urlparse

import httpx

BASE = "https://inspections.myhealthdepartment.com"
LANDING = f"{BASE}/larimer-county-health"
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Patterns worth knowing about when reverse-engineering the portal's data layer.
INTERESTING = [
    (r"task=([A-Za-z0-9_]+)", "task param"),
    (r"['\"](/[A-Za-z0-9_\-./]*(?:api|search|data|json|ajax)[A-Za-z0-9_\-./]*)['\"]", "path"),
    (r"(https?://[A-Za-z0-9._\-]+/[A-Za-z0-9_\-./]*(?:api|search|data|json)[^\s'\"]*)", "abs url"),
    (r"\.(?:get|post)\(\s*['\"]([^'\"]{4,120})['\"]", "http call"),
    (r"url\s*:\s*['\"]([^'\"]{4,120})['\"]", "url option"),
    (r"fetch\(\s*['\"]([^'\"]{4,120})['\"]", "fetch"),
]

client = httpx.Client(
    headers={"User-Agent": UA, "Accept": "*/*"},
    follow_redirects=True,
    timeout=45.0,
)


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n== {title}\n{'=' * 78}", flush=True)


def get(url: str, **kw):
    try:
        r = client.get(url, **kw)
        print(f"  GET {url}\n    -> {r.status_code} {r.headers.get('content-type', '?')} "
              f"{len(r.content)}B final={r.url}")
        return r
    except Exception as exc:  # noqa: BLE001 - probe should never hard-fail
        print(f"  GET {url}\n    -> ERROR {type(exc).__name__}: {exc}")
        return None


def grep(label: str, text: str) -> set[str]:
    """Print every interesting match in `text`, return the discovered task names."""
    tasks: set[str] = set()
    for pattern, kind in INTERESTING:
        hits = sorted(set(re.findall(pattern, text)))
        if not hits:
            continue
        print(f"    [{kind}] {len(hits)} unique")
        for hit in hits[:40]:
            print(f"      {hit}")
        if len(hits) > 40:
            print(f"      ... +{len(hits) - 40} more")
        if kind == "task param":
            tasks.update(hits)
    return tasks


def main() -> int:
    discovered_tasks: set[str] = set()

    rule("1. Landing page")
    resp = get(LANDING)
    if resp is None:
        return 1
    html = resp.text
    print(f"\n  --- first 4000 chars of HTML ---\n{html[:4000]}")

    rule("2. Inline scripts / embedded config")
    for i, body in enumerate(re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.S)):
        body = body.strip()
        if len(body) < 40:
            continue
        print(f"\n  --- inline script #{i} ({len(body)}B) ---")
        print("  " + body[:2500].replace("\n", "\n  "))
        discovered_tasks |= grep(f"inline#{i}", body)

    rule("3. Forms, data-* attributes, and iframes")
    for tag in re.findall(r"<(?:form|iframe)\b[^>]*>", html, re.I):
        print(f"  {tag[:300]}")
    data_attrs = sorted(set(re.findall(r"(data-[a-z0-9\-]+)\s*=", html, re.I)))
    print(f"  data-* attributes present: {data_attrs}")

    rule("4. Same-origin JavaScript bundles")
    srcs = re.findall(r"<script\b[^>]*\bsrc=['\"]([^'\"]+)['\"]", html, re.I)
    print(f"  {len(srcs)} script tags with src:")
    for s in srcs:
        print(f"    {s}")
    for src in srcs:
        full = urljoin(str(resp.url), src)
        if urlparse(full).netloc != urlparse(BASE).netloc:
            continue  # third-party (analytics, CDN jQuery) - not our data layer
        js = get(full)
        if js is None or js.status_code != 200:
            continue
        print(f"    --- grepping {full} ---")
        discovered_tasks |= grep(full, js.text)

    rule("5. Candidate data endpoints")
    print(f"  tasks discovered so far: {sorted(discovered_tasks)}")
    # `task=` is this vendor's dispatch convention (seen in their /print/ URLs).
    guesses = sorted(discovered_tasks) or [
        "getSearchResults", "getResults", "search", "getFacilities",
        "getInspections", "getEstablishments", "getList",
    ]
    for task in guesses:
        for path in ("/larimer-county-health/", "/larimer-county-health/search/"):
            r = get(
                f"{BASE}{path}",
                params={"task": task, "path": "larimer-county-health"},
                headers={"X-Requested-With": "XMLHttpRequest",
                         "Accept": "application/json, text/plain, */*"},
            )
            if r is None or r.status_code != 200:
                continue
            body = r.text.strip()
            looks_json = body[:1] in "[{" or "json" in r.headers.get("content-type", "")
            print(f"      JSON-ish={looks_json}  first 600 chars:")
            print("      " + body[:600].replace("\n", "\n      "))

    rule("6. Robots / sitemap / well-known data files")
    for path in ("/robots.txt", "/sitemap.xml", "/larimer-county-health/sitemap.xml"):
        r = get(BASE + path)
        if r is not None and r.status_code == 200:
            print("      " + r.text[:1200].replace("\n", "\n      "))

    rule("DONE")
    print(json.dumps({"tasks": sorted(discovered_tasks), "scripts": srcs}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
