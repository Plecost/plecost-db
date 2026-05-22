# CHANGELOG

## [1.2.0] - 2026-05-22

### Fixed
- `updater.py`: Replaced single-pass Jaro-Winkler (threshold 0.82) with a cascaded multi-stage CVE→slug normalization pipeline to eliminate false positives:
  1. **Canonical slug exact match** — underscores/spaces converted to hyphens before set lookup (conf=1.0); fixes `contact_form_7` → `contact-form-7`.
  2. **URL reference extraction** (`_extract_slug_from_refs`) — slug parsed deterministically from `wordpress.org/plugins/`, `wordpress.org/themes/`, `plugins.svn.wordpress.org/`, and `plugins.trac.wordpress.org/` URLs; only accepted if slug exists in known wordlists (conf=0.95); eliminates FPs like `element_pack` being mapped to `elementor`.
  3. **Jaro-Winkler threshold raised from 0.82 to 0.90** — eliminates known false positives (e.g. `element_pack`→`elementor` at score 0.8828, `word_replacer_pro`→`wordfence`).
  4. **No match → silent skip** — the `slug=product, conf=0.5` fallback that inserted ~1740 garbage records is removed entirely; unmatched CVEs are silently skipped.
- `updater.py`: Added `_is_prerelease_cpe()` — CPE URIs with `:beta:`, `:rc:`, or `:alpha:` qualifiers are discarded before slug matching, preventing wildcard version ranges from prerelease entries.
- `updater.py`: Pre-compute `plugin_slugs_set` and `theme_slugs_set` as sets for O(1) membership checks in `process_nvd_batch()`.

### Added
- `_extract_slug_from_refs(refs, plugin_slugs, theme_slugs)` — new function with 4 URL patterns.
- `_is_prerelease_cpe(cpe_uri)` — detects pre-release CPE qualifiers.
- `_canonical_slug(s)` — converts CPE product names to hyphenated WordPress slug format.
- 17 new unit tests covering all 5 acceptance criteria (AC-1 through AC-5) plus helpers and AC-6/AC-7 regression coverage.

## [1.1.0] - 2026-04-14

### Fixed
- `updater.py`: NVD API enforces a 120-day maximum window per request when date filters are used. `build-db --years 5` was passing a 1825-day range, causing all NVD requests to return HTTP 404 silently. Fixed by paginating in 90-day windows so every request stays under the limit.
- `incremental.py`: Same 90-day window fix applied to `_fetch_modified` for `lastModStartDate`/`lastModEndDate` parameters.

## [1.0.0] - 2026-04-13

### Added
- Inicialización del paquete `plecost-db-tool` con `pyproject.toml` y estructura base
- `plecost_db/updater.py`: copia exacta de `plecost/database/updater.py` con `DatabaseUpdater`, `process_nvd_batch` y funciones auxiliares (`_normalize`, `_jaro_winkler`, `_match_slug`)
- `plecost_db/incremental.py`: copia de `plecost/database/incremental.py` con import cambiado a `from plecost_db.updater import process_nvd_batch`
- `plecost_db/cli.py`: CLI con comandos `build-db` (construcción completa desde NVD) y `sync-db` (sincronización incremental)
- Tests unitarios: `tests/unit/test_updater.py` (10 tests), `tests/unit/test_incremental.py` (3 tests)
- Test de integración: `tests/integration/test_database_updater.py` (1 test)
- Entrypoint `plecost-db` disponible tras instalación
