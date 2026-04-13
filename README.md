# plecost-db

CVE database builder for [Plecost](https://github.com/Plecost/plecost) — the professional WordPress security scanner.

This repository contains the tooling to generate and maintain the daily-updated CVE database that Plecost uses for vulnerability correlation. End users do not need this repo — they get the database automatically via `plecost update-db`.

---

## Overview

`plecost-db` provides two CLI commands:

| Command | Description |
|---------|-------------|
| `plecost-db build-db` | Full database build from NVD (maintainers, one-time) |
| `plecost-db sync-db` | Incremental daily sync from NVD (used by GitHub Actions) |

The daily GitHub Actions workflow runs `sync-db`, generates a JSON patch file, and publishes it as a release asset under the `db-patches` tag. Plecost users download these patches via `plecost update-db`.

---

## Installation

This tool is not published to PyPI. Install directly from source:

```bash
git clone https://github.com/Plecost/plecost-db.git
cd plecost-db
pip install -e ".[dev]"
```

> **Requires** `plecost>=4.0.0` as a dependency (installed automatically).

---

## Usage

### Build the database from scratch

Downloads up to 5 years of WordPress CVEs from the [NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities):

```bash
plecost-db build-db [--db-url sqlite:///path/to/plecost.db] [--years 5] [--nvd-key API_KEY]
```

| Option | Description | Env Var | Default |
|--------|-------------|---------|---------|
| `--db-url` | Database destination URL | `PLECOST_DB_URL` | `~/.plecost/db/plecost.db` |
| `--years` | Years of NVD history to download | — | 5 |
| `--nvd-key` | NVD API key for higher rate limits | `NVD_API_KEY` | — |

> Without an NVD API key, requests are rate-limited to 1 per 6 seconds. A full 5-year build takes 30–60 minutes. Get a free key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

### Incremental sync

Fetches only CVEs modified since the last sync:

```bash
plecost-db sync-db [--db-url sqlite:///path/to/plecost.db] [--nvd-key API_KEY] [--output-patch patch.json]
```

| Option | Description | Env Var |
|--------|-------------|---------|
| `--db-url` | Database to update | `PLECOST_DB_URL` |
| `--nvd-key` | NVD API key | `NVD_API_KEY` |
| `--output-patch` | Write a JSON patch file for distribution | — |

### PostgreSQL support

```bash
pip install "plecost[postgres]"

plecost-db build-db --db-url postgresql+asyncpg://user:pass@host/plecost
plecost-db sync-db  --db-url postgresql+asyncpg://user:pass@host/plecost
```

---

## How the patch system works

The daily workflow generates incremental JSON patch files instead of redistributing the full SQLite database:

| Run | What happens | Typical size |
|-----|-------------|--------------|
| First `plecost update-db` | Downloads `full.json` with all historical CVEs | ~10–50 MB |
| Subsequent `plecost update-db` | Downloads only today's patch | <100 KB |
| No changes | Compares checksum only, downloads nothing | 64 bytes |

Each patch is a JSON file with `upsert` and `delete` arrays, verified with SHA256 before being applied.

For full architecture details, see [`docs/cve-patch-system/`](docs/cve-patch-system/README.md).

---

## Running tests

```bash
python3 -m pytest tests/ -v
```

---

## License

Same as Plecost: [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/).

**Author:** Dani (cr0hn) — [cr0hn@cr0hn.com](mailto:cr0hn@cr0hn.com)
