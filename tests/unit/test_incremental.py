# plecost-db/tests/unit/test_incremental.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import respx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from plecost_db.incremental import IncrementalUpdater, NVD_CVE_API
from plecost.database.models import Base, DbMetadata


def _make_nvd_response(cve_ids: list[str] | None = None) -> dict:
    if not cve_ids:
        return {"totalResults": 0, "vulnerabilities": []}
    vulns = []
    for cve_id in cve_ids:
        vulns.append({
            "cve": {
                "id": cve_id,
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {}, "references": [],
                "published": "2024-01-01T00:00:00.000",
                "configurations": [],
            }
        })
    return {"totalResults": len(vulns), "vulnerabilities": vulns}


async def _make_db_sf(*, last_sync: str | None = None):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    if last_sync:
        async with sf() as session:
            session.add(DbMetadata(key="last_nvd_sync", value=last_sync))
            await session.commit()
    return engine, sf


@respx.mock
async def test_incremental_reads_last_sync_date(tmp_path):
    last_sync = "2024-06-01T00:00:00.000"
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    file_engine = create_async_engine(db_url)
    async with file_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    file_sf = async_sessionmaker(file_engine, expire_on_commit=False)
    async with file_sf() as session:
        session.add(DbMetadata(key="last_nvd_sync", value=last_sync))
        await session.commit()
    await file_engine.dispose()

    nvd_route = respx.get(NVD_CVE_API).mock(
        return_value=httpx.Response(200, json=_make_nvd_response())
    )
    updater = IncrementalUpdater(db_url=db_url)
    await updater.run()

    assert nvd_route.called
    url_str = str(nvd_route.calls[0].request.url)
    assert "lastModStartDate" in url_str
    assert "2024-06-01" in url_str


@respx.mock
async def test_incremental_updates_sync_date(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    old_sync = "2024-01-01T00:00:00.000"
    seed_engine = create_async_engine(db_url)
    async with seed_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    seed_sf = async_sessionmaker(seed_engine, expire_on_commit=False)
    async with seed_sf() as session:
        session.add(DbMetadata(key="last_nvd_sync", value=old_sync))
        await session.commit()
    await seed_engine.dispose()

    respx.get(NVD_CVE_API).mock(return_value=httpx.Response(200, json=_make_nvd_response()))
    before = datetime.now(timezone.utc).replace(microsecond=0)
    await IncrementalUpdater(db_url=db_url).run()
    after = datetime.now(timezone.utc).replace(microsecond=0)

    read_engine = create_async_engine(db_url)
    read_sf = async_sessionmaker(read_engine, expire_on_commit=False)
    async with read_sf() as session:
        row = await session.get(DbMetadata, "last_nvd_sync")
    assert row is not None
    assert row.value != old_sync
    new_dt = datetime.strptime(row.value, "%Y-%m-%dT%H:%M:%S.000").replace(tzinfo=timezone.utc)
    assert before <= new_dt <= after + timedelta(seconds=2)
    await read_engine.dispose()


@respx.mock
async def test_incremental_no_prior_sync(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    init_engine = create_async_engine(db_url)
    async with init_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await init_engine.dispose()

    nvd_route = respx.get(NVD_CVE_API).mock(return_value=httpx.Response(200, json=_make_nvd_response()))
    before_run = datetime.now(timezone.utc)
    await IncrementalUpdater(db_url=db_url).run()

    assert nvd_route.called
    from urllib.parse import urlparse, parse_qs
    params = parse_qs(urlparse(str(nvd_route.calls[0].request.url)).query)
    start_date_str = params.get("lastModStartDate", [None])[0]
    assert start_date_str is not None
    start_dt = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M:%S.000").replace(tzinfo=timezone.utc)
    assert start_dt >= before_run - timedelta(days=3)
    assert start_dt <= before_run
