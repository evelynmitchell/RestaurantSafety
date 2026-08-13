# Restaurant Safety — Larimer County

A GitHub Pages site listing food-service establishments in Larimer County,
Colorado that failed their most recent health inspection badly enough that the
county ordered a **reinspection**.

Data comes from the Larimer County Department of Health and Environment's public
inspection portal at
<https://inspections.myhealthdepartment.com/larimer-county-health>. Neither the
county nor the State of Colorado publishes an API for it, so this project scrapes
the portal on a schedule.

**Status:** in development.

## Layout

| Path | Purpose |
| --- | --- |
| `scripts/probe.py` | Throwaway portal reconnaissance (see below) |
| `.github/workflows/` | Scheduled scrape + Pages deploy |

## Development

This project uses [uv](https://docs.astral.sh/uv/).

```sh
uv run scripts/probe.py
```

## Why a probe script?

The portal is a vendor SaaS app (My Health Department) with no documented API.
`scripts/probe.py` runs in CI and dumps the portal's script bundles, embedded
config, and candidate data endpoints to the job log so the real scraper can be
written against the actual structure rather than guesswork. It is deleted once
the scraper works.
