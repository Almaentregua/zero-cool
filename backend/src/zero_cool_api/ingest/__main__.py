"""Command line entry point: ``python -m zero_cool_api.ingest kev|nvd``."""

import argparse
import logging
import os
import sys

import httpx
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from zero_cool_api.db import create_db_engine, init_db
from zero_cool_api.http import FetchError
from zero_cool_api.ingest.kev import upsert_kev
from zero_cool_api.ingest.nvd import NvdAuthError, enrich_from_nvd
from zero_cool_api.sources.kev import fetch_kev
from zero_cool_api.sources.nvd import NvdClient


def run_kev(engine: Engine) -> int:
    """Download KEV and store it. Returns the process exit code."""
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            entries = fetch_kev(client)
    except FetchError as exc:
        print(f"Ingestion failed: {exc}", file=sys.stderr)
        return 1
    with sessionmaker(engine)() as session:
        created, updated = upsert_kev(session, entries)
    print(f"KEV: {created} created, {updated} updated ({len(entries)} entries)")
    return 0


def run_nvd(engine: Engine, limit: int | None, force: bool) -> int:
    """Enrich KEV vulnerabilities from NVD. Returns the process exit code."""
    api_key = os.environ.get("NVD_API_KEY") or None
    if api_key is None:
        print(
            "No NVD_API_KEY set: running at the slow public rate (about 6.5 s per CVE).\n"
            "See the README to set a free key.",
            file=sys.stderr,
        )

    def progress(done: int, total: int) -> None:
        if done % 25 == 0 or done == total:
            print(f"NVD: {done}/{total}", flush=True)

    with httpx.Client(timeout=30.0, follow_redirects=True) as http_client:
        client = NvdClient(http_client, api_key)
        with sessionmaker(engine)() as session:
            try:
                result = enrich_from_nvd(
                    session, client, limit=limit, force=force, progress=progress
                )
            except NvdAuthError as exc:
                print(f"Ingestion failed: {exc}", file=sys.stderr)
                return 1
    print(
        f"NVD: {result.enriched} enriched, {result.not_found} not found, "
        f"{result.failed} failed, {result.skipped_recent} skipped (recent)"
    )
    return 1 if result.failed else 0


def main(argv: list[str] | None = None) -> int:
    """Run an ingestion from the command line.

    Parameters:
        argv: Arguments; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code: 0 on success, 1 if something failed.
    """
    parser = argparse.ArgumentParser(prog="ingest", description="Ingest vulnerability data.")
    parser.add_argument("source", choices=["kev", "nvd"], help="Source to ingest.")
    parser.add_argument("--limit", type=int, help="nvd: query at most this many CVEs.")
    parser.add_argument("--force", action="store_true", help="nvd: ignore recently fetched data.")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    # httpx logs every request URL at INFO; keep the output readable.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    engine = create_db_engine()
    init_db(engine)
    if args.source == "kev":
        return run_kev(engine)
    return run_nvd(engine, args.limit, args.force)


if __name__ == "__main__":
    sys.exit(main())
