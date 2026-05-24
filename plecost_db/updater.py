from __future__ import annotations
import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from plecost.database.engine import make_engine, make_session_factory
from plecost.database.models import Base, DbMetadata, NormalizedVuln, PluginsWordlist, ThemesWordlist

logger = logging.getLogger(__name__)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
WP_PLUGINS_API = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[per_page]=250&request[page]={page}"
WP_THEMES_API = "https://api.wordpress.org/themes/info/1.2/?action=query_themes&request[per_page]=100&request[page]={page}"


def _normalize(s: str) -> str:
    """Normalize for comparison: remove separators, lowercase."""
    return re.sub(r'[-_\s]', '', s).lower()


def _jaro_winkler(s1: str, s2: str) -> float:
    """
    Inline implementation of Jaro-Winkler to avoid an extra dependency.
    Returns similarity between 0.0 and 1.0.
    """
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0
    match_dist = max(len1, len2) // 2 - 1
    if match_dist < 0:
        match_dist = 0
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0
    for i in range(len1):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3
    # Winkler prefix bonus (unchanged)
    prefix = 0
    for i in range(min(4, len1, len2)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break
    return jaro + prefix * 0.1 * (1 - jaro)


def _parse_cpe(cpe_uri: str) -> tuple[str, str, str]:
    """
    Parse CPE 2.3: cpe:2.3:a:{vendor}:{product}:{version}:..:{target_sw}:..
    Returns (vendor, product, target_sw). target_sw is at position 10 (0-indexed from 'cpe').
    """
    parts = cpe_uri.split(':')
    if len(parts) < 13:
        return '', '', ''
    vendor = parts[3]
    product = parts[4]
    target_sw = parts[10]
    return vendor, product, target_sw


def _is_wp_plugin_cpe(target_sw: str) -> bool:
    return target_sw.lower() in ('wordpress', 'wordpress_plugin', '*')


_REF_SLUG_PATTERNS = [
    re.compile(r'wordpress\.org/plugins/([a-z0-9][a-z0-9\-]{0,100})(?:/|$)'),
    re.compile(r'wordpress\.org/themes/([a-z0-9][a-z0-9\-]{0,100})(?:/|$)'),
    re.compile(r'plugins\.svn\.wordpress\.org/([a-z0-9][a-z0-9\-]{0,100})/'),
    re.compile(r'plugins\.trac\.wordpress\.org/(?:browser|changeset/\d+)/([a-z0-9][a-z0-9\-]{0,100})'),
]

_PRERELEASE_RE = re.compile(r':(?:alpha|beta|rc)\d*:', re.IGNORECASE)


def _extract_slug_from_refs(refs: list[str], plugin_slugs: list[str], theme_slugs: list[str]) -> tuple[str | None, str]:
    """
    Try to extract the WordPress slug directly from CVE reference URLs.
    Returns (slug, software_type) or (None, '').
    Only returns slugs that exist in the known wordlists.
    """
    known_plugins = set(plugin_slugs)
    known_themes = set(theme_slugs)
    for url in refs:
        for pattern in _REF_SLUG_PATTERNS:
            m = pattern.search(url)
            if m:
                slug = m.group(1)
                if slug in known_plugins:
                    return slug, "plugin"
                if slug in known_themes:
                    return slug, "theme"
    return None, ""


def _is_prerelease_cpe(cpe_uri: str) -> bool:
    """Return True if the CPE URI refers to a pre-release version (alpha/beta/rc)."""
    return bool(_PRERELEASE_RE.search(cpe_uri))


def _canonical_slug(s: str) -> str:
    """Convert CPE product name to canonical WordPress slug format (underscores → hyphens)."""
    return re.sub(r'[_\s]+', '-', s.lower()).strip('-')


def _match_slug(cpe_product: str, known_slugs: list[str], threshold: float = 0.90) -> tuple[str | None, float]:
    """
    Try to map cpe_product to a known slug.
    1. Normalized exact match
    2. Jaro-Winkler fuzzy match
    Returns (slug, confidence) or (None, 0.0)
    """
    norm_product = _normalize(cpe_product)
    # Exact match
    for slug in known_slugs:
        if _normalize(slug) == norm_product:
            return slug, 1.0
    # Fuzzy
    best_slug = None
    best_score = 0.0
    for slug in known_slugs:
        score = _jaro_winkler(norm_product, _normalize(slug))
        if score > best_score:
            best_score = score
            best_slug = slug
    if best_score >= threshold and best_slug:
        return best_slug, best_score
    return None, 0.0


async def _upsert_vuln_free(session: AsyncSession, vuln: NormalizedVuln) -> None:
    from sqlalchemy import select
    existing = (await session.execute(
        select(NormalizedVuln).where(
            NormalizedVuln.cve_id == vuln.cve_id,
            NormalizedVuln.slug == vuln.slug,
        )
    )).scalar_one_or_none()
    if existing:
        if vuln.match_confidence > existing.match_confidence:
            for attr in ["cpe_vendor", "cpe_product", "match_confidence",
                         "version_start_incl", "version_start_excl",
                         "version_end_incl", "version_end_excl",
                         "cvss_score", "severity", "description", "references_json",
                         "title", "remediation", "has_exploit"]:  # G-005
                setattr(existing, attr, getattr(vuln, attr))
    else:
        session.add(vuln)


async def _fetch_kev_ids(client: httpx.AsyncClient) -> frozenset[str]:
    """Fetch CISA KEV CVE IDs. Returns empty frozenset on failure."""
    try:
        r = await client.get(CISA_KEV_URL, timeout=15)
        r.raise_for_status()
        data = r.json()
        return frozenset(v["cveID"] for v in data.get("vulnerabilities", []))
    except Exception as e:
        logger.warning("CISA KEV fetch failed: %s — has_exploit will be False for this batch", e)
        return frozenset()


async def process_nvd_batch(
    vulns: list[Any], sf: async_sessionmaker[AsyncSession],
    plugin_slugs: list[str], theme_slugs: list[str],
    collected: list[dict[str, Any]] | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> None:
    """Free reusable function called from both updater and incremental.

    If *collected* is provided, each processed vulnerability record (as a dict
    matching the daily-patch JSON schema) is appended to it in addition to
    being persisted to the database.

    *http_client* is an optional httpx.AsyncClient used for the CISA KEV lookup
    when *collected* is not None. If not provided, a temporary client is created.
    """
    # Pre-compute sets for O(1) membership checks
    plugin_slugs_set = set(plugin_slugs)
    theme_slugs_set = set(theme_slugs)

    # G2-019: Fetch CISA KEV once per batch (only when writing patch records)
    kev_ids: frozenset[str] = frozenset()
    if collected is not None:
        if http_client is not None:
            kev_ids = await _fetch_kev_ids(http_client)
        else:
            async with httpx.AsyncClient() as _tmp_client:
                kev_ids = await _fetch_kev_ids(_tmp_client)

    # G2-018: Deduplication tracker — (cve_id, slug) → index in collected
    _collected_seen: dict[tuple[str, str], int] = {}

    async with sf() as session:
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                ""
            )
            metrics = cve.get("metrics", {})
            cvss_score: float | None = None
            severity = "MEDIUM"
            if v31 := metrics.get("cvssMetricV31"):
                cvss_score = v31[0]["cvssData"]["baseScore"]
                severity = v31[0]["cvssData"]["baseSeverity"]
            elif v30 := metrics.get("cvssMetricV30"):
                cvss_score = v30[0]["cvssData"]["baseScore"]
                severity = v30[0]["cvssData"]["baseSeverity"]

            refs_list = [r2["url"] for r2 in cve.get("references", [])]
            refs = json.dumps(refs_list)
            published = cve.get("published", "")
            # Normalise published to a date-only string for the patch format
            published_date = published[:10] if published else ""

            # Extraer CPEs de configurations
            found_any = False
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if not cpe_match.get("vulnerable", False):
                            continue
                        cpe_uri = cpe_match.get("criteria", "")
                        vendor, product, target_sw = _parse_cpe(cpe_uri)
                        if not product:
                            continue

                        # Descartar CPEs de versiones prerelease (alpha/beta/rc)
                        if _is_prerelease_cpe(cpe_uri):
                            continue

                        v_start_i = cpe_match.get("versionStartIncluding")
                        v_start_e = cpe_match.get("versionStartExcluding")
                        v_end_i = cpe_match.get("versionEndIncluding")
                        v_end_e = cpe_match.get("versionEndExcluding")

                        # WordPress Core: CPE product="wordpress", vendor="wordpress" (unambiguous)
                        if vendor.lower() == "wordpress" and product.lower() == "wordpress":
                            vuln_obj = NormalizedVuln(
                                cve_id=cve_id,
                                software_type="core",
                                slug="wordpress",
                                cpe_vendor=vendor,
                                cpe_product=product,
                                match_confidence=1.0,
                                version_start_incl=v_start_i,
                                version_start_excl=v_start_e,
                                version_end_incl=v_end_i,
                                version_end_excl=v_end_e,
                                cvss_score=cvss_score,
                                severity=severity,
                                title=f"WordPress Core: {cve_id}",
                                description=desc,
                                remediation="Update WordPress to the latest version.",
                                references_json=refs,
                                has_exploit=False,  # KEV flag goes in patch records only (spec non-goal)
                                published_at=published,
                            )
                            await _upsert_vuln_free(session, vuln_obj)
                            if collected is not None:
                                _key = (cve_id, "wordpress")
                                _record = {
                                    "cve_id": cve_id,
                                    "software_type": "core",
                                    "slug": "wordpress",
                                    "cpe_vendor": vendor,
                                    "cpe_product": product,
                                    "match_confidence": 1.0,
                                    "version_start_incl": v_start_i,
                                    "version_start_excl": v_start_e,
                                    "version_end_incl": v_end_i,
                                    "version_end_excl": v_end_e,
                                    "cvss_score": cvss_score,
                                    "severity": severity,
                                    "title": f"WordPress Core: {cve_id}",
                                    "description": desc,
                                    "remediation": "Update WordPress to the latest version.",
                                    "references": refs_list,
                                    "has_exploit": cve_id in kev_ids,  # G2-019
                                    "published_at": published_date,
                                }
                                if _key not in _collected_seen:  # G2-018
                                    _collected_seen[_key] = len(collected)
                                    collected.append(_record)
                                elif _record["match_confidence"] > collected[_collected_seen[_key]]["match_confidence"]:  # G2-018: higher confidence replaces
                                    collected[_collected_seen[_key]] = _record
                            found_any = True
                            continue

                        # Plugins/Themes: filter by target_sw=wordpress
                        if not _is_wp_plugin_cpe(target_sw):
                            continue

                        # Multi-stage slug resolution pipeline
                        slug: str | None = None
                        conf: float = 0.0
                        sw_type: str = "plugin"

                        # ETAPA 0b: canonical slug exact match (underscore → hyphen)
                        canonical = _canonical_slug(product)
                        if canonical in plugin_slugs_set:
                            slug, conf, sw_type = canonical, 1.0, "plugin"
                        elif canonical in theme_slugs_set:
                            slug, conf, sw_type = canonical, 1.0, "theme"
                        else:
                            # ETAPA 1: extraer slug de URLs de referencia del CVE
                            slug, sw_type = _extract_slug_from_refs(refs_list, plugin_slugs, theme_slugs)
                            if slug:
                                conf = 0.95
                            else:
                                # ETAPA 2: Jaro-Winkler con threshold 0.90
                                slug, conf = _match_slug(product, plugin_slugs, threshold=0.90)
                                sw_type = "plugin"
                                if not slug:
                                    slug, conf = _match_slug(product, theme_slugs, threshold=0.90)
                                    sw_type = "theme"
                                if not slug:
                                    # Sin match suficiente → NO insertar, skip silencioso
                                    continue

                        vuln_obj = NormalizedVuln(
                            cve_id=cve_id,
                            software_type=sw_type,
                            slug=slug,
                            cpe_vendor=vendor,
                            cpe_product=product,
                            match_confidence=conf,
                            version_start_incl=v_start_i,
                            version_start_excl=v_start_e,
                            version_end_incl=v_end_i,
                            version_end_excl=v_end_e,
                            cvss_score=cvss_score,
                            severity=severity,
                            title=f"{product}: {cve_id}",
                            description=desc,
                            remediation="Update the plugin/theme to the latest version.",
                            references_json=refs,
                            has_exploit=False,  # KEV flag goes in patch records only (spec non-goal)
                            published_at=published,
                        )
                        await _upsert_vuln_free(session, vuln_obj)
                        if collected is not None:
                            _key = (cve_id, slug)
                            _record = {
                                "cve_id": cve_id,
                                "software_type": sw_type,
                                "slug": slug,
                                "cpe_vendor": vendor,
                                "cpe_product": product,
                                "match_confidence": conf,
                                "version_start_incl": v_start_i,
                                "version_start_excl": v_start_e,
                                "version_end_incl": v_end_i,
                                "version_end_excl": v_end_e,
                                "cvss_score": cvss_score,
                                "severity": severity,
                                "title": f"{product}: {cve_id}",
                                "description": desc,
                                "remediation": "Update the plugin/theme to the latest version.",
                                "references": refs_list,
                                "has_exploit": cve_id in kev_ids,  # G2-019
                                "published_at": published_date,
                            }
                            if _key not in _collected_seen:  # G2-018
                                _collected_seen[_key] = len(collected)
                                collected.append(_record)
                            elif _record["match_confidence"] > collected[_collected_seen[_key]]["match_confidence"]:  # G2-018: higher confidence replaces
                                collected[_collected_seen[_key]] = _record
                        found_any = True

            # If there were no useful configurations, skip
            if not found_any and desc:
                pass  # Skip CVEs without useful CPEs

        await session.commit()


class DatabaseUpdater:
    def __init__(self, db_url: str, years_back: int = 5, nvd_api_key: str | None = None) -> None:
        self._db_url = db_url
        self._years_back = years_back
        self._api_key = nvd_api_key

    async def run(self) -> None:
        engine = make_engine(self._db_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sf = make_session_factory(engine)

        headers: dict[str, str] = {"User-Agent": "Plecost/4.0 (security research; github.com/Plecost/plecost)"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        start_date = (datetime.now(timezone.utc) - timedelta(days=self._years_back * 365)).strftime("%Y-%m-%dT00:00:00.000")

        async with httpx.AsyncClient(timeout=60, headers=headers) as client:
            # Download wordlists first (slugs needed for matching)
            plugin_slugs = await self._fetch_plugin_slugs(client, sf)
            theme_slugs = await self._fetch_theme_slugs(client, sf)
            # Download and process CVEs from NVD
            await self._fetch_nvd(client, sf, plugin_slugs, theme_slugs, start_date)

        # Save synchronization metadata
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        async with sf() as session:
            existing = await session.get(DbMetadata, "last_nvd_sync")
            if existing:
                existing.value = now_str
            else:
                session.add(DbMetadata(key="last_nvd_sync", value=now_str))
            start_date_meta = await session.get(DbMetadata, "initial_sync_from")
            if not start_date_meta:
                session.add(DbMetadata(key="initial_sync_from", value=start_date))
            await session.commit()

        await engine.dispose()

    async def _fetch_plugin_slugs(
        self, client: httpx.AsyncClient, sf: async_sessionmaker[AsyncSession]
    ) -> list[str]:
        # Maps slug → active_installs for the DB upsert below
        slug_installs: dict[str, int] = {}
        for page in range(1, 20):  # up to 5000 plugins
            try:
                r = await client.get(WP_PLUGINS_API.format(page=page), timeout=30)
                data = r.json()
                plugins = data.get("plugins", {})
                if not plugins:
                    break
                if isinstance(plugins, dict):
                    # Keyed by slug; each value is a plugin info dict
                    for slug, info in plugins.items():
                        if slug:
                            installs = int(info.get("active_installs", 0)) if isinstance(info, dict) else 0
                            slug_installs[slug] = installs
                    page_count = len(plugins)
                else:
                    for p in plugins:
                        slug = p.get("slug", "") if isinstance(p, dict) else ""
                        if slug:
                            slug_installs[slug] = int(p.get("active_installs", 0))
                    page_count = len(plugins)
                if page_count < 250:
                    break
            except Exception:
                break
        # Save to DB
        async with sf() as session:
            for slug, active_installs in slug_installs.items():
                existing = await session.get(PluginsWordlist, slug)
                if not existing:
                    session.add(PluginsWordlist(slug=slug, active_installs=active_installs))
                else:
                    existing.active_installs = active_installs
            await session.commit()
        return list(slug_installs.keys())

    async def _fetch_theme_slugs(
        self, client: httpx.AsyncClient, sf: async_sessionmaker[AsyncSession]
    ) -> list[str]:
        slug_installs: dict[str, int] = {}
        for page in range(1, 10):
            try:
                r = await client.get(WP_THEMES_API.format(page=page), timeout=30)
                data = r.json()
                themes = data.get("themes", [])
                if not themes:
                    break
                for t in themes:
                    if isinstance(t, dict):
                        slug = t.get("slug", "")
                        if slug:
                            slug_installs[slug] = int(t.get("active_installs", 0))
                if len(themes) < 100:
                    break
            except Exception:
                break
        async with sf() as session:
            for slug, active_installs in slug_installs.items():
                existing = await session.get(ThemesWordlist, slug)
                if not existing:
                    session.add(ThemesWordlist(slug=slug, active_installs=active_installs))
                else:
                    existing.active_installs = active_installs
            await session.commit()
        return list(slug_installs.keys())

    async def _fetch_nvd(
        self, client: httpx.AsyncClient, sf: async_sessionmaker[AsyncSession], plugin_slugs: list[str], theme_slugs: list[str],
        start_date: str | None = None,
    ) -> None:
        # NVD API enforces a maximum 120-day window per request when date filters
        # are used. We slice the full range into 90-day windows to stay safely
        # under that limit, then paginate within each window.
        NVD_WINDOW_DAYS = 90
        results_per_page = 2000
        delay = 6 if not self._api_key else 0.6

        if start_date is None:
            start_date = (datetime.now(timezone.utc) - timedelta(days=self._years_back * 365)).strftime("%Y-%m-%dT00:00:00.000")

        window_start = datetime.strptime(start_date, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
        overall_end = datetime.now(timezone.utc)

        while window_start < overall_end:
            window_end = min(window_start + timedelta(days=NVD_WINDOW_DAYS), overall_end)
            pub_start = window_start.strftime("%Y-%m-%dT00:00:00.000")
            pub_end = window_end.strftime("%Y-%m-%dT23:59:59.999")
            start_index = 0

            while True:
                params: dict[str, str | int] = {
                    "keywordSearch": "wordpress",
                    "pubStartDate": pub_start,
                    "pubEndDate": pub_end,
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                }
                try:
                    r = await client.get(NVD_CVE_API, params=params, timeout=60)
                    if r.status_code != 200:
                        break
                    data = r.json()
                except Exception:
                    break

                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                await process_nvd_batch(vulns, sf, plugin_slugs, theme_slugs)

                total = data.get("totalResults", 0)
                start_index += len(vulns)
                if start_index >= total:
                    break
                await asyncio.sleep(delay)

            # AC-12: advance by 1 second (not 1 day) to avoid losing CVEs modified
            # in the final second of the previous window on the next iteration.
            window_start = window_end + timedelta(seconds=1)
            await asyncio.sleep(delay)
