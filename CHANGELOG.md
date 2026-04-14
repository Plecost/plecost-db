# CHANGELOG

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
