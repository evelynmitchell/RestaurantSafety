#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Characterise the 403 the Larimer inspections portal returns to CI runners.

Round 1 got 403 on every path including /robots.txt. That is either (a) the
portal blocking datacenter IP ranges, or (b) it sniffing for a full browser
header set. Those have very different consequences for this project, so this
round tells them apart before any scraper gets written.
"""

from __future__ import annotations

import sys

import httpx

PORTAL = "https://inspections.myhealthdepartment.com/larimer-county-health"
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# What a real Chrome tab sends. If this gets through and a bare UA does not,
# the block is header-based; if both 403, it is the runner's IP.
FULL_BROWSER = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
              "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Ch-Ua": '"Chromium";v="126", "Not:A-Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n== {title}\n{'=' * 78}", flush=True)


def attempt(label: str, url: str, headers: dict[str, str] | None) -> None:
    print(f"\n  [{label}] {url}")
    try:
        with httpx.Client(follow_redirects=True, timeout=30.0) as c:
            r = c.get(url, headers=headers or {})
    except Exception as exc:  # noqa: BLE001
        print(f"    ERROR {type(exc).__name__}: {exc}")
        return
    print(f"    status={r.status_code} bytes={len(r.content)}")
    # Response headers name the WAF/CDN doing the blocking (Server, CF-Ray,
    # X-Amzn-*, Akamai, Incapsula) - that determines whether this is fixable.
    for k, v in sorted(r.headers.items()):
        print(f"      {k}: {v[:160]}")
    body = r.text.strip()
    if body:
        print(f"    body[:400]: {body[:400]!r}")


def main() -> int:
    rule("0. Control - is general egress working from this runner?")
    attempt("control", "https://example.com", FULL_BROWSER)
    attempt("control-ip", "https://api.ipify.org?format=json", FULL_BROWSER)

    rule("1. Portal with a FULL browser header set")
    attempt("full-headers", PORTAL, FULL_BROWSER)

    rule("2. Portal with bare UA only (round 1 behaviour, for comparison)")
    attempt("bare-ua", PORTAL, {"User-Agent": UA})

    rule("3. Portal with no custom headers at all")
    attempt("no-headers", PORTAL, None)

    rule("4. Portal root and robots (is the whole host blocked, or just the path?)")
    attempt("host-root", "https://inspections.myhealthdepartment.com/", FULL_BROWSER)
    attempt("robots", "https://inspections.myhealthdepartment.com/robots.txt", FULL_BROWSER)
    attempt("vendor-www", "https://www.myhealthdepartment.com/", FULL_BROWSER)

    rule("5. Larimer County's own site - is there an alternate route to the data?")
    attempt(
        "larimer-food-safety",
        "https://www.larimer.gov/health/environmental-health/food-safety-program/"
        "restaurant-grocery-store-inspections",
        FULL_BROWSER,
    )

    rule("DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
