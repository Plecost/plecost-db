# plecost-db/tests/unit/test_updater_fixes.py
"""
Tests for SPEC LOCK v1 acceptance criteria:
  AC-2  [G-005]:  _upsert_vuln_free updates title/remediation/has_exploit on higher confidence
  AC-4  [G2-018]: process_nvd_batch deduplicates collected by (cve_id, slug)
  AC-6  [G2-019]: KEV fetch failure → WARNING logged, has_exploit=False, no raise
  AC-8  [G2-019]: KEV-present CVE → has_exploit=True; KEV failure → has_exploit=False, no raise
  AC-10 [G2-020]: _fetch_modified does not raise TypeError with naive ISO string
"""
from __future__ import annotations

import logging

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from plecost.database.models import Base, NormalizedVuln
from plecost_db.incremental import IncrementalUpdater, NVD_CVE_API
from plecost_db.updater import (
    CISA_KEV_URL,
    _upsert_vuln_free,
    process_nvd_batch,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_normalized_vuln(
    cve_id: str,
    slug: str,
    *,
    confidence: float = 1.0,
    title: str = "Original Title",
    remediation: str = "Original Remediation",
    has_exploit: bool = False,
) -> NormalizedVuln:
    return NormalizedVuln(
        cve_id=cve_id,
        software_type="plugin",
        slug=slug,
        cpe_vendor="testvendor",
        cpe_product="testproduct",
        match_confidence=confidence,
        cvss_score=7.5,
        severity="HIGH",
        title=title,
        description="Test description",
        remediation=remediation,
        references_json="[]",
        has_exploit=has_exploit,
        published_at="2024-01-01T00:00:00.000",
    )


def _make_cve_item(
    cve_id: str,
    vendor: str,
    product: str,
    target_sw: str = "wordpress",
    refs: list[str] | None = None,
    nodes: list[dict] | None = None,
) -> dict:
    """Build a minimal NVD CVE item with one CPE node."""
    cpe_uri = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:{target_sw}:*:*"
    cpe_match: dict = {"vulnerable": True, "criteria": cpe_uri}
    references = [{"url": u, "source": "test"} for u in (refs or [])]
    config_nodes = nodes or [{"cpeMatch": [cpe_match]}]
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"Test description for {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
            },
            "references": references,
            "published": "2024-01-01T00:00:00.000",
            "configurations": [{"nodes": config_nodes}],
        }
    }


def _make_cve_two_nodes(
    cve_id: str,
    vendor: str,
    product: str,
    target_sw: str = "wordpress",
) -> dict:
    """Build a CVE item with TWO separate CPE nodes mapping to the same product/slug."""
    cpe_uri = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:{target_sw}:*:*"
    node_a = {"cpeMatch": [{"vulnerable": True, "criteria": cpe_uri, "versionEndExcluding": "1.5.0"}]}
    node_b = {"cpeMatch": [{"vulnerable": True, "criteria": cpe_uri, "versionEndExcluding": "2.0.0"}]}
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"Test description for {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
            },
            "references": [],
            "published": "2024-01-01T00:00:00.000",
            "configurations": [{"nodes": [node_a, node_b]}],
        }
    }


@pytest.fixture
async def db_session():
    """Yields a SQLAlchemy AsyncSession backed by an in-memory SQLite DB."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        yield session
    await engine.dispose()


@pytest.fixture
async def db_sf():
    """Yields an async_sessionmaker backed by an in-memory SQLite DB."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


# ---------------------------------------------------------------------------
# AC-2 [G-005]: _upsert_vuln_free updates title/remediation/has_exploit on higher confidence
# ---------------------------------------------------------------------------

async def test_upsert_vuln_free_updates_on_higher_confidence(db_session):
    """AC-2: second call with higher confidence must update title, remediation, has_exploit."""
    low_conf = _make_normalized_vuln(
        "CVE-2024-1001", "test-plugin",
        confidence=0.7,
        title="Old Title",
        remediation="Old Remediation",
        has_exploit=False,
    )
    db_session.add(low_conf)
    await db_session.commit()

    high_conf = _make_normalized_vuln(
        "CVE-2024-1001", "test-plugin",
        confidence=0.9,
        title="New Title",
        remediation="New Remediation",
        has_exploit=True,
    )
    await _upsert_vuln_free(db_session, high_conf)
    await db_session.commit()

    result = (await db_session.execute(
        select(NormalizedVuln).where(
            NormalizedVuln.cve_id == "CVE-2024-1001",
            NormalizedVuln.slug == "test-plugin",
        )
    )).scalar_one()

    assert result.title == "New Title"
    assert result.remediation == "New Remediation"
    assert result.has_exploit is True
    assert result.match_confidence == 0.9


async def test_upsert_vuln_free_no_update_on_same_confidence(db_session):
    """AC-2 (negative): lower or equal confidence MUST NOT overwrite title/remediation/has_exploit."""
    original = _make_normalized_vuln(
        "CVE-2024-1002", "test-plugin2",
        confidence=0.9,
        title="Kept Title",
        remediation="Kept Remediation",
        has_exploit=True,
    )
    db_session.add(original)
    await db_session.commit()

    lower_conf = _make_normalized_vuln(
        "CVE-2024-1002", "test-plugin2",
        confidence=0.7,
        title="Should Not Replace",
        remediation="Should Not Replace",
        has_exploit=False,
    )
    await _upsert_vuln_free(db_session, lower_conf)
    await db_session.commit()

    result = (await db_session.execute(
        select(NormalizedVuln).where(
            NormalizedVuln.cve_id == "CVE-2024-1002",
            NormalizedVuln.slug == "test-plugin2",
        )
    )).scalar_one()

    assert result.title == "Kept Title"
    assert result.remediation == "Kept Remediation"
    assert result.has_exploit is True
    assert result.match_confidence == 0.9


# ---------------------------------------------------------------------------
# AC-4 [G2-018]: process_nvd_batch deduplicates collected by (cve_id, slug)
# ---------------------------------------------------------------------------

@respx.mock
async def test_process_nvd_batch_deduplicates_collected(db_sf):
    """AC-4: two CPE nodes for the same CVE+slug → exactly one entry in collected."""
    respx.get(CISA_KEV_URL).mock(
        return_value=httpx.Response(200, json={"vulnerabilities": []})
    )
    respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

    cve = _make_cve_two_nodes("CVE-2024-2001", vendor="testvendor", product="test-plugin-dup")
    collected: list = []

    async with httpx.AsyncClient() as client:
        await process_nvd_batch(
            [cve], db_sf,
            plugin_slugs=["test-plugin-dup"],
            theme_slugs=[],
            collected=collected,
            http_client=client,
        )

    assert len(collected) == 1, (
        f"Expected exactly 1 collected entry for (cve_id, slug), got {len(collected)}"
    )
    assert collected[0]["cve_id"] == "CVE-2024-2001"
    assert collected[0]["slug"] == "test-plugin-dup"


@respx.mock
async def test_process_nvd_batch_keeps_higher_confidence_in_collected(db_sf):
    """AC-4 (higher confidence wins): when two CPE nodes map to the same (cve_id, slug)
    with different confidences, the higher-confidence entry must replace the lower one.

    Node 1: product='contact-form-7x' → canonical 'contact-form-7x' NOT in wordlist →
            falls through to Jaro-Winkler → fuzzy match to 'contact-form-7' with
            conf ≈ 0.9846 (< 1.0).  This entry lands in collected first.
    Node 2: product='contact-form-7'  → canonical 'contact-form-7' IS in wordlist →
            exact match → conf = 1.0.  This triggers the `elif confidence > ...` branch
            and REPLACES the first entry.

    The key assertion is collected[0]["match_confidence"] == 1.0, proving the replacement
    actually happened (not just deduplication at equal confidence).
    """
    respx.get(CISA_KEV_URL).mock(
        return_value=httpx.Response(200, json={"vulnerabilities": []})
    )
    respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

    # Node 1: fuzzy CPE product — canonical slug 'contact-form-7x' is NOT in the wordlist,
    # so the pipeline falls through to Jaro-Winkler and returns conf < 1.0.
    cpe_fuzzy = "cpe:2.3:a:testvendor:contact-form-7x:*:*:*:*:*:wordpress:*:*"
    node_fuzzy = {"cpeMatch": [{"vulnerable": True, "criteria": cpe_fuzzy, "versionEndExcluding": "1.0.0"}]}

    # Node 2: exact CPE product — canonical slug 'contact-form-7' IS in the wordlist,
    # so Stage 0b fires and returns conf = 1.0, which replaces the fuzzy entry above.
    cpe_exact = "cpe:2.3:a:testvendor:contact-form-7:*:*:*:*:*:wordpress:*:*"
    node_exact = {"cpeMatch": [{"vulnerable": True, "criteria": cpe_exact, "versionEndExcluding": "2.0.0"}]}

    cve = {
        "cve": {
            "id": "CVE-2024-2002",
            "descriptions": [{"lang": "en", "value": "Higher confidence replacement test"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
            "references": [],
            "published": "2024-01-01T00:00:00.000",
            # node_fuzzy is processed FIRST so it enters collected with conf < 1.0
            "configurations": [{"nodes": [node_fuzzy, node_exact]}],
        }
    }

    collected: list = []
    async with httpx.AsyncClient() as client:
        await process_nvd_batch(
            [cve], db_sf,
            # Only 'contact-form-7' (exact) is in the wordlist; 'contact-form-7x' is NOT,
            # which forces the fuzzy path for node 1.
            plugin_slugs=["contact-form-7"],
            theme_slugs=[],
            collected=collected,
            http_client=client,
        )

    assert len(collected) == 1, (
        f"Expected exactly 1 collected entry for (cve_id, slug), got {len(collected)}"
    )
    assert collected[0]["slug"] == "contact-form-7"
    # The exact-match node (conf=1.0) must have replaced the fuzzy node (conf<1.0).
    # If the elif branch never fired, the confidence would be the fuzzy value (~0.9846).
    assert collected[0]["match_confidence"] == 1.0, (
        f"Expected conf=1.0 after replacement, got {collected[0]['match_confidence']!r}. "
        "The elif high-confidence replacement branch did not fire."
    )


# ---------------------------------------------------------------------------
# AC-8a [G2-019]: KEV-present CVE → has_exploit=True
# ---------------------------------------------------------------------------

@respx.mock
async def test_process_nvd_batch_has_exploit_true_if_in_kev(db_sf):
    """AC-8a: when CVE ID appears in CISA KEV, collected entry has has_exploit=True."""
    cve_id = "CVE-2024-3001"
    respx.get(CISA_KEV_URL).mock(
        return_value=httpx.Response(200, json={"vulnerabilities": [{"cveID": cve_id}]})
    )
    respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

    cve = _make_cve_item(cve_id, vendor="woo", product="woocommerce")
    collected: list = []

    async with httpx.AsyncClient() as client:
        await process_nvd_batch(
            [cve], db_sf,
            plugin_slugs=["woocommerce"],
            theme_slugs=[],
            collected=collected,
            http_client=client,
        )

    assert len(collected) == 1
    assert collected[0]["has_exploit"] is True, "has_exploit must be True when CVE is in KEV"


# ---------------------------------------------------------------------------
# AC-8b [G2-019]: KEV fetch failure → has_exploit=False, no raise
# ---------------------------------------------------------------------------

@respx.mock
async def test_process_nvd_batch_kev_failure_fallback(db_sf):
    """AC-8b: when KEV endpoint returns 500, has_exploit falls back to False and no exception raised."""
    cve_id = "CVE-2024-3002"
    respx.get(CISA_KEV_URL).mock(return_value=httpx.Response(500))
    respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

    cve = _make_cve_item(cve_id, vendor="woo", product="woocommerce")
    collected: list = []

    # Must not raise
    async with httpx.AsyncClient() as client:
        await process_nvd_batch(
            [cve], db_sf,
            plugin_slugs=["woocommerce"],
            theme_slugs=[],
            collected=collected,
            http_client=client,
        )

    assert len(collected) == 1
    assert collected[0]["has_exploit"] is False, "has_exploit must be False when KEV fetch fails"


# ---------------------------------------------------------------------------
# AC-6 [G2-019]: KEV fetch failure → WARNING logged
# ---------------------------------------------------------------------------

@respx.mock
async def test_process_nvd_batch_kev_failure_logs_warning(db_sf, caplog):
    """AC-6: KEV fetch failure must emit a WARNING log message."""
    cve_id = "CVE-2024-3003"
    respx.get(CISA_KEV_URL).mock(return_value=httpx.Response(500))
    respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

    cve = _make_cve_item(cve_id, vendor="woo", product="woocommerce")
    collected: list = []

    with caplog.at_level(logging.WARNING, logger="plecost_db.updater"):
        async with httpx.AsyncClient() as client:
            await process_nvd_batch(
                [cve], db_sf,
                plugin_slugs=["woocommerce"],
                theme_slugs=[],
                collected=collected,
                http_client=client,
            )

    warning_records = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warning_records) >= 1, "Expected at least one WARNING log when KEV fetch fails"
    assert any("KEV" in r.message or "kev" in r.message.lower() or "CISA" in r.message
               for r in warning_records), "WARNING message should mention KEV/CISA"
    # AC-6 postcondition: when KEV fetch fails, has_exploit must default to False (not True,
    # not None).  This guards against a regression where KEV failure silently set has_exploit=True.
    assert len(collected) == 1, "Expected exactly one collected entry"
    assert collected[0]["has_exploit"] is False, (
        "has_exploit must be False when KEV fetch fails — KEV absence must not imply exploit"
    )


# ---------------------------------------------------------------------------
# AC-10 [G2-020]: _fetch_modified does not raise TypeError with naive ISO string
# ---------------------------------------------------------------------------

@respx.mock
async def test_fetch_modified_naive_last_sync_vs_aware_end_date_does_not_raise(db_sf):
    """AC-10: _fetch_modified must not raise TypeError when last_sync is a naive ISO string
    and end_date is an aware-formatted ISO string (with +00:00 offset).

    G2-020 bug scenario:
      Pre-fix code:
        window_start = datetime.fromisoformat(last_sync.rstrip("Z"))
            → naive datetime  (no tzinfo)
        overall_end  = datetime.fromisoformat(end_date.rstrip("Z"))
            → end_date has '+00:00' suffix; rstrip("Z") leaves it untouched;
              fromisoformat parses it as an AWARE datetime  (tzinfo=UTC+00:00)
        window_start < overall_end
            → TypeError: can't compare offset-naive and offset-aware datetimes

      Post-fix (G2-020) adds .replace(tzinfo=timezone.utc) to BOTH sides, making
      the comparison safe regardless of the input format.

    The test uses:
      - last_sync = naive ISO string (no tz suffix) — as stored by older DB rows
      - end_date  = ISO string with +00:00 suffix   — as produced when the caller
                    builds end_date from datetime.now(timezone.utc).isoformat()

    The NVD mock returns 0 results → the inner loop exits immediately and no
    real HTTP is performed.  The assertion 'result == 0' confirms the function
    completed normally; the absence of TypeError confirms the fix is in place.
    """
    # last_sync: naive ISO (no timezone info) — common in older DB rows
    naive_last_sync = "2026-05-01T00:00:00.000"

    # end_date: aware ISO with UTC offset — produced by datetime.now(timezone.utc).isoformat()
    # rstrip("Z") leaves "+00:00" intact; pre-fix fromisoformat returns an *aware* datetime,
    # which when compared against the *naive* window_start triggers TypeError.
    aware_end_date = "2026-05-02T00:00:00.000+00:00"

    # NVD returns 0 results → loop terminates immediately without making real requests
    respx.get(NVD_CVE_API).mock(
        return_value=httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
    )
    respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

    updater = IncrementalUpdater(db_url="sqlite+aiosqlite:///:memory:", nvd_api_key=None)

    async with httpx.AsyncClient() as client:
        # Pre-fix: raises TypeError at 'window_start < overall_end'.
        # Post-fix: both sides get .replace(tzinfo=timezone.utc) → comparison is safe.
        result = await updater._fetch_modified(
            client=client,
            sf=db_sf,                  # use the fixture's session factory (not a dead engine)
            last_sync=naive_last_sync,
            end_date=aware_end_date,
            plugin_slugs=[],
            theme_slugs=[],
            collected=None,
        )

    # Exact assertion: 0 CVEs processed (NVD returned empty list)
    assert result == 0, f"Expected 0 processed CVEs, got {result}"
