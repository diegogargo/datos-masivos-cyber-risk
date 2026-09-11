"""Download the official CISA Known Exploited Vulnerabilities JSON feed."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parents[2]
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "datos-masivos-cyber-risk/0.1 (university project)"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def download_feed(timeout: int, retries: int) -> tuple[bytes, dict[str, Any]]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    with requests.Session() as session:
        for attempt in range(retries + 1):
            try:
                response = session.get(FEED_URL, headers=headers, timeout=timeout)
                if response.status_code == 429:
                    wait = float(response.headers.get("Retry-After", 2 ** attempt))
                    if attempt == retries:
                        response.raise_for_status()
                    time.sleep(wait)
                    continue
                if 500 <= response.status_code < 600 and attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                response.raise_for_status()
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise RuntimeError("CISA returned an invalid JSON response") from exc
                if not isinstance(payload, dict) or not isinstance(
                    payload.get("vulnerabilities"), list
                ):
                    raise RuntimeError("Unexpected CISA KEV response structure")
                return response.content, payload
            except (requests.Timeout, requests.ConnectionError) as exc:
                if attempt == retries:
                    raise RuntimeError(
                        f"CISA KEV request failed after {retries + 1} attempts"
                    ) from exc
                time.sleep(2 ** attempt)
            except requests.HTTPError as exc:
                raise RuntimeError(f"CISA KEV HTTP error: {exc}") from exc
    raise RuntimeError("CISA KEV request did not produce a response")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def run(args: argparse.Namespace) -> Path:
    raw_output = ROOT / "data" / "raw" / "cisa" / "kev_catalog.json"
    metadata_output = raw_output.with_name("kev_catalog.metadata.json")
    sample_output = ROOT / "data" / "sample" / "cisa_kev_sample.json"
    raw_output.parent.mkdir(parents=True, exist_ok=True)
    sample_output.parent.mkdir(parents=True, exist_ok=True)
    if raw_output.exists() and not args.force:
        print(f"Using existing file: {raw_output.relative_to(ROOT)}")
        return raw_output

    content, payload = download_feed(args.timeout, args.retries)
    extracted_at = utc_now()
    raw_output.write_bytes(content)
    metadata = {
        "source_url": FEED_URL,
        "extracted_at_utc": extracted_at,
        "catalog_version": payload.get("catalogVersion"),
        "date_released": payload.get("dateReleased"),
        "declared_count": payload.get("count"),
        "observed_count": len(payload["vulnerabilities"]),
    }
    metadata_output.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    sample = {
        **metadata,
        "sample_note": "First 25 records for structural review only.",
        "vulnerabilities": payload["vulnerabilities"][:25],
    }
    sample_output.write_text(
        json.dumps(sample, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"CISA KEV contains {len(payload['vulnerabilities'])} records")
    print(f"Saved raw feed to {raw_output.relative_to(ROOT)}")
    print(f"Saved structural sample to {sample_output.relative_to(ROOT)}")
    return raw_output


def main() -> None:
    run(parse_args())


if __name__ == "__main__":
    main()
