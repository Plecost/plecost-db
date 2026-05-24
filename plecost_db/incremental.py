from __future__ import annotations
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from plecost.database.engine import make_engine, make_session_factory
from plecost.database.models import Base, DbMetadata, PluginsWordlist, ThemesWordlist
from plecost_db.updater import process_nvd_batch

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
METADATA_KEY_LAST_SYNC = "last_nvd_sync"

# Retry configuration for NVD API rate limiting and transient server errors
_RETRY_429_WAITS = (30, 60, 120)   # seconds; HTTP 429 Too Many Requests
_RETRY_5XX_WAITS = (10, 30)         # seconds; HTTP 5xx server errors


class NVDHTTPError(Exception):
    """Raised when the NVD API returns a non-recoverable non-200 response."""
    def __init__(self, status_code: int) -> None:
        super().__init__(f"NVD API returned HTTP {status_code}")
        self.status_code = status_code


class IncrementalUpdater:
    """
    Applies only CVEs modified/published since the last synchronization.
    Requires an existing DB with db_metadata.last_nvd_sync.
    """

    def __init__(
        self,
        db_url: str,
        nvd_api_key: str | None = None,
        output_patch: str | None = None,
    ) -> None:
        self._db_url = db_url
        self._api_key = nvd_api_key
        self._output_patch = output_patch

    async def run(self) -> int:
        """Returns the number of CVEs processed."""
        engine = make_engine(self._db_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sf = make_session_factory(engine)

        last_sync = await self._get_last_sync(sf)
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        headers: dict[str, str] = {
            "User-Agent": "Plecost/4.0 (security research; github.com/Plecost/plecost)"
        }
        if self._api_key:
            headers["apiKey"] = self._api_key

        # Get known slugs for fuzzy matching
        plugin_slugs, theme_slugs = await self._get_slugs(sf)

        # Accumulator for the daily patch JSON
        patch_records: list[dict[str, Any]] = []

        total = 0
        async with httpx.AsyncClient(timeout=60, headers=headers) as client:
            try:
                # AC-13: _fetch_modified checkpoints last_nvd_sync after EACH
                # successfully completed 90-day window, so a mid-run failure
                # only re-processes the current (incomplete) window on the
                # next run — not the entire range from the beginning.
                total = await self._fetch_modified(
                    client, sf, last_sync, now_str, plugin_slugs, theme_slugs,
                    patch_records,
                )
            except NVDHTTPError:
                pass  # partial progress already checkpointed per-window above

        await engine.dispose()

        # Write daily patch JSON if requested
        if self._output_patch is not None:
            patch: dict[str, Any] = {
                "date": now.strftime("%Y-%m-%d"),
                "source": "nvd",
                "upsert": patch_records,
                "delete": [],
            }
            output_path = Path(self._output_patch)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(patch, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        return total

    async def _get_last_sync(self, sf: async_sessionmaker) -> str:  # type: ignore[type-arg]
        async with sf() as session:
            row = await session.get(DbMetadata, METADATA_KEY_LAST_SYNC)
            if row:
                return str(row.value)
            # If there is no last_sync, use 2 days ago as a safe fallback
            fallback = datetime.now(timezone.utc) - timedelta(days=2)
            return fallback.strftime("%Y-%m-%dT%H:%M:%S.000")

    async def _set_last_sync(self, sf: async_sessionmaker, value: str) -> None:  # type: ignore[type-arg]
        async with sf() as session:
            row = await session.get(DbMetadata, METADATA_KEY_LAST_SYNC)
            if row:
                row.value = value
            else:
                session.add(DbMetadata(key=METADATA_KEY_LAST_SYNC, value=value))
            await session.commit()

    async def _get_slugs(self, sf: async_sessionmaker) -> tuple[list[str], list[str]]:  # type: ignore[type-arg]
        async with sf() as session:
            plugins = (await session.execute(select(PluginsWordlist.slug))).scalars().all()
            themes = (await session.execute(select(ThemesWordlist.slug))).scalars().all()
        return list(plugins), list(themes)

    async def _nvd_request(
        self,
        client: httpx.AsyncClient,
        params: dict[str, str | int],
    ) -> dict[str, Any]:
        """
        Perform a single NVD API GET with retry logic for rate-limit and server errors.

        - HTTP 429: retry up to 3 times with exponential backoff (30 s, 60 s, 120 s)
        - HTTP 5xx: retry up to 2 times with shorter backoff (10 s, 30 s)
        - Other non-200: raise NVDHTTPError immediately (caller handles)
        """
        retry_429 = 0
        retry_5xx = 0
        while True:
            r = await client.get(NVD_CVE_API, params=params, timeout=60)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                if retry_429 < len(_RETRY_429_WAITS):
                    await asyncio.sleep(_RETRY_429_WAITS[retry_429])
                    retry_429 += 1
                    continue
                raise NVDHTTPError(429)
            if r.status_code >= 500:
                if retry_5xx < len(_RETRY_5XX_WAITS):
                    await asyncio.sleep(_RETRY_5XX_WAITS[retry_5xx])
                    retry_5xx += 1
                    continue
                raise NVDHTTPError(r.status_code)
            raise NVDHTTPError(r.status_code)

    async def _fetch_modified(
        self,
        client: httpx.AsyncClient,
        sf: async_sessionmaker,  # type: ignore[type-arg]
        last_sync: str,
        end_date: str,
        plugin_slugs: list[str],
        theme_slugs: list[str],
        collected: list[dict[str, Any]] | None = None,
    ) -> int:
        # NVD API enforces a 120-day max window per request when date filters are
        # used. Slice the range into 90-day windows to stay safely under the limit.
        NVD_WINDOW_DAYS = 90
        delay = 6 if not self._api_key else 0.6
        total_processed = 0

        window_start = datetime.fromisoformat(last_sync.rstrip("Z")).replace(tzinfo=timezone.utc)  # G2-020
        overall_end = datetime.fromisoformat(end_date.rstrip("Z")).replace(tzinfo=timezone.utc)  # G2-020

        while window_start < overall_end:
            window_end = min(window_start + timedelta(days=NVD_WINDOW_DAYS), overall_end)
            mod_start = window_start.strftime("%Y-%m-%dT%H:%M:%S.000")
            mod_end = window_end.strftime("%Y-%m-%dT%H:%M:%S.999")
            window_end_str = window_end.strftime("%Y-%m-%dT%H:%M:%S.999")
            start_index = 0

            while True:
                params: dict[str, str | int] = {
                    "keywordSearch": "wordpress",
                    "lastModStartDate": mod_start,
                    "lastModEndDate": mod_end,
                    "resultsPerPage": 2000,
                    "startIndex": start_index,
                }
                try:
                    data = await self._nvd_request(client, params)
                except (NVDHTTPError, Exception):
                    # Window failed — do not checkpoint; let caller decide
                    raise

                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                await process_nvd_batch(vulns, sf, plugin_slugs, theme_slugs, collected)
                total_processed += len(vulns)

                total = data.get("totalResults", 0)
                start_index += len(vulns)
                if start_index >= total:
                    break
                await asyncio.sleep(delay)

            # Window completed successfully — checkpoint last_nvd_sync so a
            # future failure re-processes only the current (not yet started)
            # window, not the full range from the original last_sync.
            await self._set_last_sync(sf, window_end_str)

            # Advance by 1 second (not 1 day) to avoid losing CVEs modified in the
            # last 24 h of the previous window on the next iteration.
            window_start = window_end + timedelta(seconds=1)
            await asyncio.sleep(delay)

        return total_processed
