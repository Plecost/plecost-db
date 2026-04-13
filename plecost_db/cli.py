# plecost-db/plecost_db/cli.py
from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(name="plecost-db", help="Herramienta de generación de la base de datos CVE para Plecost.")
console = Console()


@app.command("build-db")
def build_db(
    db_url: Optional[str] = typer.Option(
        None, "--db-url", envvar="PLECOST_DB_URL",
        help="Database URL. Default: sqlite at ~/.plecost/db/plecost.db",
    ),
    years: int = typer.Option(5, "--years", help="Years of NVD history to download"),
    nvd_api_key: Optional[str] = typer.Option(
        None, "--nvd-key", envvar="NVD_API_KEY",
        help="NVD API key for higher rate limit (free at nvd.nist.gov)",
    ),
) -> None:
    """Build the CVE database from scratch (maintainers only). Downloads N years from NVD."""
    from plecost_db.updater import DatabaseUpdater

    if not db_url:
        db_path = Path.home() / ".plecost" / "db" / "plecost.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite+aiosqlite:///{db_path}"

    console.print(f"[bold]Building CVE database from NVD (last {years} years)...[/bold]")
    console.print("[dim]This may take several minutes due to NVD rate limits.[/dim]")
    console.print(f"[dim]Target: {db_url}[/dim]")

    try:
        uvloop = __import__("uvloop")
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass

    asyncio.run(DatabaseUpdater(db_url, years_back=years, nvd_api_key=nvd_api_key).run())
    console.print("[green]Database built successfully[/green]")
    console.print("[dim]Upload plecost.db to GitHub releases tag 'db-patches' to enable update-db for users.[/dim]")


@app.command("sync-db")
def sync_db(
    db_url: Optional[str] = typer.Option(
        None, "--db-url", envvar="PLECOST_DB_URL",
        help="Database URL. Default: sqlite at ~/.plecost/db/plecost.db",
    ),
    nvd_api_key: Optional[str] = typer.Option(
        None, "--nvd-key", envvar="NVD_API_KEY",
        help="NVD API key for higher rate limit",
    ),
    output_patch: Optional[str] = typer.Option(
        None, "--output-patch",
        help="Path to write the generated daily JSON patch file",
    ),
) -> None:
    """Incremental sync: fetch only CVEs modified since last run. Used by CI."""
    from plecost_db.incremental import IncrementalUpdater

    if not db_url:
        db_path = Path.home() / ".plecost" / "db" / "plecost.db"
        db_url = f"sqlite+aiosqlite:///{db_path}"

    console.print("[bold]Syncing CVE database (incremental)...[/bold]")

    try:
        uvloop = __import__("uvloop")
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass

    count = asyncio.run(IncrementalUpdater(db_url, nvd_api_key=nvd_api_key, output_patch=output_patch).run())
    console.print(f"[green]Processed {count} CVEs[/green]")


if __name__ == "__main__":
    app()
