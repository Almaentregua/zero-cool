"""Command line entry point: ``python -m zero_cool_api.ingest kev``."""

import argparse
import logging
import sys

import httpx
from sqlalchemy.orm import sessionmaker

from zero_cool_api.db import create_db_engine, init_db
from zero_cool_api.http import FetchError
from zero_cool_api.ingest.kev import upsert_kev
from zero_cool_api.sources.kev import fetch_kev


def main(argv: list[str] | None = None) -> int:
    """Run an ingestion from the command line.

    Parameters:
        argv: Arguments; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code: 0 on success, 1 if a source could not be fetched.
    """
    parser = argparse.ArgumentParser(prog="ingest", description="Ingest vulnerability data.")
    parser.add_argument("source", choices=["kev"], help="Source to ingest.")
    parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    engine = create_db_engine()
    init_db(engine)
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


if __name__ == "__main__":
    sys.exit(main())
