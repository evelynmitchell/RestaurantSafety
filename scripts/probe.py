#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Round 3: is the backing services API reachable where the portal is not?

A browser capture of the portal's bootstrap call revealed a generic RPC envelope
(`{task, dataObjectName, data}`, `authenticated: false`) and, more importantly,
that the portal delegates data to services-api.hscloudsuite.com - a different
host from the IP-blocked inspections.myhealthdepartment.com. If that host serves
CI runners, the project is viable from GitHub Actions after all.
"""

from __future__ import annotations

import sys

import httpx

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
JSON_HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "Origin": "https://inspections.myhealthdepartment.com",
    "Referer": "https://inspections.myhealthdepartment.com/larimer-county-health",
}

# The exact call captured from the browser. If this returns the same payload
# from CI, public reads work unauthenticated from a datacenter IP.
BOOTSTRAP = {
    "task": "readOne",
    "dataObjectName": "jurisdictions",
    "data": {"path": "larimer-county-health"},
}

HOSTS = [
    "https://services-api.hscloudsuite.com/",
    "https://services-print-api.hscloudsuite.com/",
    "https://next.hscloudsuite.com/",
]


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n== {title}\n{'=' * 78}", flush=True)


def show(label: str, r: httpx.Response) -> None:
    print(f"    status={r.status_code} bytes={len(r.content)} "
          f"server={r.headers.get('server', '?')} ctype={r.headers.get('content-type', '?')}")
    print(f"    body[:700]: {r.text[:700]!r}")


def req(label: str, method: str, url: str, **kw) -> None:
    print(f"\n  [{label}] {method} {url}")
    try:
        with httpx.Client(follow_redirects=True, timeout=30.0) as c:
            r = c.request(method, url, headers=JSON_HEADERS, **kw)
    except Exception as exc:  # noqa: BLE001
        print(f"    ERROR {type(exc).__name__}: {exc}")
        return
    show(label, r)


def main() -> int:
    rule("1. Are the hscloudsuite hosts reachable at all?")
    for host in HOSTS:
        req(host, "GET", host)

    rule("2. Replay the captured bootstrap RPC against candidate endpoints")
    # The capture did not include the request URL, so try the plausible mounts.
    paths = ["", "api", "api/", "data", "rpc", "services", "v1", "api/v1"]
    for base in ("https://services-api.hscloudsuite.com/",
                 "https://inspections.myhealthdepartment.com/"):
        for path in paths:
            req(f"POST {base}{path}", "POST", base + path, json=BOOTSTRAP)

    rule("3. Does the blocked portal host behave differently for POST?")
    req("portal-post-root", "POST", "https://inspections.myhealthdepartment.com/",
        json=BOOTSTRAP)

    rule("DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
