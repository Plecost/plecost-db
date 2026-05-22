# plecost-db/tests/unit/test_updater.py
from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from plecost.database.models import Base, NormalizedVuln
from plecost_db.updater import (
    process_nvd_batch,
    _normalize,
    _jaro_winkler,
    _match_slug,
    _extract_slug_from_refs,
    _is_prerelease_cpe,
    _canonical_slug,
)


def _make_cve(
    cve_id: str,
    vendor: str,
    product: str,
    target_sw: str = "*",
    version_end_excl: str | None = None,
) -> dict:
    cpe_uri = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:{target_sw}:*:*"
    cpe_match: dict = {"vulnerable": True, "criteria": cpe_uri}
    if version_end_excl:
        cpe_match["versionEndExcluding"] = version_end_excl
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"Test description for {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
            },
            "references": [],
            "published": "2024-01-01T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [cpe_match]}]}],
        }
    }


def _make_cve_with_refs(
    cve_id: str,
    vendor: str,
    product: str,
    target_sw: str = "*",
    refs: list[str] | None = None,
    version_end_excl: str | None = None,
) -> dict:
    """Like _make_cve but allows passing reference URLs."""
    cpe_uri = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:{target_sw}:*:*"
    cpe_match: dict = {"vulnerable": True, "criteria": cpe_uri}
    if version_end_excl:
        cpe_match["versionEndExcluding"] = version_end_excl
    references = [{"url": url, "source": "test"} for url in (refs or [])]
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"Test description for {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
            },
            "references": references,
            "published": "2024-01-01T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [cpe_match]}]}],
        }
    }


@pytest.fixture
async def db_sf():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


async def test_process_nvd_batch_core_vuln(db_sf):
    cve = _make_cve("CVE-2024-0001", vendor="wordpress", product="wordpress")
    await process_nvd_batch([cve], db_sf, [], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 1
    assert results[0].software_type == "core"
    assert results[0].slug == "wordpress"
    assert results[0].match_confidence == 1.0


async def test_process_nvd_batch_plugin_vuln(db_sf):
    cve = _make_cve("CVE-2024-0002", vendor="woocommerce", product="woocommerce", target_sw="wordpress")
    await process_nvd_batch([cve], db_sf, ["woocommerce"], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 1
    assert results[0].software_type == "plugin"
    assert results[0].slug == "woocommerce"


async def test_process_nvd_batch_skips_non_wordpress(db_sf):
    cve = _make_cve("CVE-2024-0003", vendor="apache", product="httpd", target_sw="linux")
    await process_nvd_batch([cve], db_sf, [], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 0


async def test_upsert_updates_on_higher_confidence(db_sf):
    async with db_sf() as session:
        session.add(NormalizedVuln(
            cve_id="CVE-2024-0004", software_type="plugin", slug="woocommerce",
            cpe_vendor="acmecorp", cpe_product="woocomerce", match_confidence=0.7,
            cvss_score=7.5, severity="HIGH", title="Test", description="Test desc",
            remediation="Update", references_json="[]", published_at="2024-01-01",
        ))
        await session.commit()
    cve_high = _make_cve("CVE-2024-0004", vendor="woocommerce", product="woocommerce", target_sw="wordpress")
    await process_nvd_batch([cve_high], db_sf, ["woocommerce"], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 1
    assert results[0].match_confidence == 1.0


def test_normalize_function():
    assert _normalize("hello-world_test") == "helloworldtest"
    assert _normalize("Hello World") == "helloworld"


def test_jaro_winkler_exact():
    assert _jaro_winkler("abc", "abc") == 1.0


def test_jaro_winkler_empty():
    assert _jaro_winkler("", "abc") == 0.0
    assert _jaro_winkler("abc", "") == 0.0


def test_match_slug_exact():
    slug, confidence = _match_slug("woocommerce", ["woocommerce", "akismet"])
    assert slug == "woocommerce"
    assert confidence == 1.0


def test_match_slug_no_match():
    slug, confidence = _match_slug("completelydifferent", ["woocommerce", "akismet"])
    if slug is not None:
        assert confidence < 0.82
    else:
        assert confidence == 0.0


def test_match_slug_normalized_exact():
    slug, confidence = _match_slug("woo-commerce", ["woocommerce"])
    assert slug == "woocommerce"
    assert confidence == 1.0


# ---------------------------------------------------------------------------
# AC-1: URL ref extraction takes priority over Jaro-Winkler
# ---------------------------------------------------------------------------
async def test_url_ref_extraction_takes_priority_over_jw(db_sf):
    """Slug from URL reference must win over Jaro-Winkler fuzzy match."""
    # CVE whose product would fuzzy-match 'elementor' but the URL says 'bdthemes-element-pack-lite'
    cve = _make_cve_with_refs(
        "CVE-2024-ELEM",
        vendor="bdthemes", product="element_pack",
        target_sw="wordpress",
        refs=["https://plugins.trac.wordpress.org/browser/bdthemes-element-pack-lite/trunk/"]
    )
    await process_nvd_batch([cve], db_sf,
                            ["elementor", "bdthemes-element-pack-lite"], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 1
    assert results[0].slug == "bdthemes-element-pack-lite"
    assert results[0].match_confidence == 0.95


# ---------------------------------------------------------------------------
# AC-2: No fallback — CVE without a match must not be inserted
# ---------------------------------------------------------------------------
async def test_no_match_does_not_insert_record(db_sf):
    """CVE with no slug match must NOT be inserted in normalized_vulns."""
    cve = _make_cve("CVE-2024-NOMATCH", vendor="somevendor",
                    product="completely_unknown_plugin", target_sw="wordpress")
    await process_nvd_batch([cve], db_sf, ["contact-form-7", "woocommerce"], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 0  # nothing inserted


# ---------------------------------------------------------------------------
# AC-3: Canonical slug match (underscore → hyphen)
# ---------------------------------------------------------------------------
async def test_canonical_slug_underscore_to_hyphen(db_sf):
    """CPE product with underscores must match the hyphenated slug."""
    cve = _make_cve("CVE-2024-CANON", vendor="vendor",
                    product="contact_form_7", target_sw="wordpress")
    await process_nvd_batch([cve], db_sf, ["contact-form-7"], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 1
    assert results[0].slug == "contact-form-7"
    assert results[0].match_confidence == 1.0


# ---------------------------------------------------------------------------
# AC-4: Prerelease CPE is silently discarded
# ---------------------------------------------------------------------------
async def test_prerelease_cpe_is_skipped(db_sf):
    """CVE with beta/rc/alpha in CPE URI must not be inserted."""
    cve_beta = {
        "cve": {
            "id": "CVE-2024-BETA",
            "descriptions": [{"lang": "en", "value": "Beta test"}],
            "metrics": {},
            "references": [],
            "published": "2024-01-01T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:wordpress:wordpress:5.8:beta1:*:*:*:*:*:*"
            }]}]}],
        }
    }
    await process_nvd_batch([cve_beta], db_sf, [], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 0


# ---------------------------------------------------------------------------
# AC-5: JW false-positive eliminated — element_pack does NOT match elementor
# ---------------------------------------------------------------------------
async def test_jw_fp_element_pack_not_matched_to_elementor(db_sf):
    """element_pack JW score against elementor is 0.8828 < 0.90 → must not match."""
    cve = _make_cve("CVE-2024-JWNOMATCH", vendor="bdthemes",
                    product="element_pack", target_sw="wordpress")
    await process_nvd_batch([cve], db_sf, ["elementor"], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 0  # elementor must not be assigned


# ---------------------------------------------------------------------------
# Unit tests for new helper functions
# ---------------------------------------------------------------------------
def test_extract_slug_from_refs_plugin():
    slug, sw_type = _extract_slug_from_refs(
        ["https://wordpress.org/plugins/bdthemes-element-pack-lite/"],
        ["bdthemes-element-pack-lite", "elementor"],
        [],
    )
    assert slug == "bdthemes-element-pack-lite"
    assert sw_type == "plugin"


def test_extract_slug_from_refs_trac():
    slug, sw_type = _extract_slug_from_refs(
        ["https://plugins.trac.wordpress.org/browser/contact-form-7/trunk/"],
        ["contact-form-7"],
        [],
    )
    assert slug == "contact-form-7"
    assert sw_type == "plugin"


def test_extract_slug_from_refs_unknown_slug_returns_none():
    """Slug from URL not in wordlist must be rejected."""
    slug, sw_type = _extract_slug_from_refs(
        ["https://wordpress.org/plugins/malicious-injection/"],
        ["contact-form-7", "woocommerce"],
        [],
    )
    assert slug is None
    assert sw_type == ""


def test_extract_slug_from_refs_theme():
    slug, sw_type = _extract_slug_from_refs(
        ["https://wordpress.org/themes/twentytwentyfour/"],
        [],
        ["twentytwentyfour"],
    )
    assert slug == "twentytwentyfour"
    assert sw_type == "theme"


def test_is_prerelease_cpe_beta():
    assert _is_prerelease_cpe("cpe:2.3:a:wordpress:wordpress:5.8:beta1:*:*:*:*:*:*") is True


def test_is_prerelease_cpe_rc():
    assert _is_prerelease_cpe("cpe:2.3:a:wordpress:wordpress:6.0:rc2:*:*:*:*:*:*") is True


def test_is_prerelease_cpe_alpha():
    assert _is_prerelease_cpe("cpe:2.3:a:some:plugin:1.0:alpha:*:*:*:*:*:*") is True


def test_is_prerelease_cpe_stable():
    assert _is_prerelease_cpe("cpe:2.3:a:wordpress:wordpress:6.4.3:*:*:*:*:*:*:*") is False


def test_canonical_slug_underscores():
    assert _canonical_slug("contact_form_7") == "contact-form-7"


def test_canonical_slug_spaces():
    assert _canonical_slug("word press") == "word-press"


def test_canonical_slug_already_hyphenated():
    assert _canonical_slug("woo-commerce") == "woo-commerce"


# ---------------------------------------------------------------------------
# AC-6: JW matches with score >= 0.90 still work
# ---------------------------------------------------------------------------
async def test_jw_high_confidence_match_still_works(db_sf):
    """A very close JW match (>= 0.90) should still be inserted."""
    # 'woocomerce' (one 'm') is very close to 'woocommerce' → JW > 0.90
    cve = _make_cve("CVE-2024-JWGOOD", vendor="woo",
                    product="woocomerce", target_sw="wordpress")
    await process_nvd_batch([cve], db_sf, ["woocommerce"], [])
    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(results) == 1
    assert results[0].slug == "woocommerce"
    assert results[0].match_confidence >= 0.90
