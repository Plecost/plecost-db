# CHANGELOG

## [1.0.0] - 2026-04-13

### Added
- Inicialización del paquete `plecost-db-tool` con `pyproject.toml` y estructura base
- `plecost_db/updater.py`: copia exacta de `plecost/database/updater.py` con `DatabaseUpdater`, `process_nvd_batch` y funciones auxiliares (`_normalize`, `_jaro_winkler`, `_match_slug`)
- `plecost_db/incremental.py`: copia de `plecost/database/incremental.py` con import cambiado a `from plecost_db.updater import process_nvd_batch`
- `plecost_db/cli.py`: CLI con comandos `build-db` (construcción completa desde NVD) y `sync-db` (sincronización incremental)
- Tests unitarios: `tests/unit/test_updater.py` (10 tests), `tests/unit/test_incremental.py` (3 tests)
- Test de integración: `tests/integration/test_database_updater.py` (1 test)
- Entrypoint `plecost-db` disponible tras instalación
