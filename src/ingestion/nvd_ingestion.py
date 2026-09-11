"""Download CVE records from the official NVD CVE API 2.0."""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import date, datetime, time as dt_time, timezone
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parents[2]
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_START = "2025-01-01"
DEFAULT_END = "2025-03-31"
USER_AGENT = "datos-masivos-cyber-risk/0.1 (university project)"
CVSS_PRIORITY = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def nvd_timestamp(day: str, end_of_day: bool = False) -> str:
    parsed = date.fromisoformat(day)
    value = datetime.combine(
        parsed,
        dt_time(23, 59, 59, 999000) if end_of_day else dt_time.min,
    )
    return value.isoformat(timespec="milliseconds")


def period_slug(start_date: str, end_date: str) -> str:
    if start_date == DEFAULT_START and end_date == DEFAULT_END:
        return "2025_q1"
    return f"{start_date.replace('-', '')}_{end_date.replace('-', '')}"


def request_json(
    session: requests.Session,
    params: dict[str, Any],
    headers: dict[str, str],
    timeout: int,
    retries: int,
) -> dict[str, Any]:
    """Request one page with explicit handling for network and JSON failures."""
    for attempt in range(retries + 1):
        try:
            response = session.get(API_URL, params=params, headers=headers, timeout=timeout)
            if response.status_code == 429:
                wait = float(response.headers.get("Retry-After", 6 * (attempt + 1)))
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
                raise RuntimeError("NVD returned an invalid JSON response") from exc
            if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                raise RuntimeError("Unexpected NVD response structure")
            return payload
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt == retries:
                raise RuntimeError(f"NVD request failed after {retries + 1} attempts") from exc
            time.sleep(2 ** attempt)
        except requests.HTTPError as exc:
            raise RuntimeError(f"NVD HTTP error: {exc}") from exc
    raise RuntimeError("NVD request did not produce a response")


def select_cvss(metrics: dict[str, Any] | None) -> dict[str, Any]:
    """Select one CVSS metric using the documented deterministic rule."""
    metrics = metrics or {}
    for metric_group in CVSS_PRIORITY:
        candidates = metrics.get(metric_group) or []
        if not candidates:
            continue
        ranked = sorted(
            candidates,
            key=lambda metric: (
                str(metric.get("type", "")).lower() != "primary",
                str(metric.get("source", "")).lower() != "nvd@nist.gov",
            ),
        )
        chosen = ranked[0]
        data = chosen.get("cvssData") or {}
        return {
            "cvss_version": data.get("version"),
            "cvss_source": chosen.get("source"),
            "base_score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or chosen.get("baseSeverity"),
            "attack_vector": data.get("attackVector"),
            "attack_complexity": data.get("attackComplexity"),
            "privileges_required": data.get("privilegesRequired"),
            "user_interaction": data.get("userInteraction"),
            "confidentiality_impact": data.get("confidentialityImpact")
            or data.get("vulnerableSystemConfidentiality"),
            "integrity_impact": data.get("integrityImpact")
            or data.get("vulnerableSystemIntegrity"),
            "availability_impact": data.get("availabilityImpact")
            or data.get("vulnerableSystemAvailability"),
        }
    return {
        "cvss_version": None,
        "cvss_source": None,
        "base_score": None,
        "severity": None,
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
        "confidentiality_impact": None,
        "integrity_impact": None,
        "availability_impact": None,
    }


def extract_cwe(weaknesses: list[dict[str, Any]] | None) -> str | None:
    """Return the first concrete CWE, preferring a Primary weakness."""
    weaknesses = weaknesses or []
    ranked = sorted(
        weaknesses,
        key=lambda weakness: str(weakness.get("type", "")).lower() != "primary",
    )
    for weakness in ranked:
        descriptions = weakness.get("description") or []
        english = [item for item in descriptions if item.get("lang") == "en"]
        for item in english + descriptions:
            value = item.get("value")
            if isinstance(value, str) and value.startswith("CWE-"):
                return value
    return None


def normalize_nvd_record(item: dict[str, Any], extracted_at: str) -> dict[str, Any]:
    """Flatten one NVD vulnerability wrapper into the analytical fields."""
    cve = item.get("cve") or {}
    record = {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cwe_id": extract_cwe(cve.get("weaknesses")),
        "nvd_extracted_at_utc": extracted_at,
    }
    record.update(select_cvss(cve.get("metrics")))
    return record


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-date", default=DEFAULT_START)
    parser.add_argument("--end-date", default=DEFAULT_END)
    parser.add_argument("--results-per-page", type=int, default=2000)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def run(args: argparse.Namespace) -> Path:
    date.fromisoformat(args.start_date)
    date.fromisoformat(args.end_date)
    if args.end_date < args.start_date:
        raise ValueError("end-date must be on or after start-date")
    if not 1 <= args.results_per_page <= 2000:
        raise ValueError("results-per-page must be between 1 and 2000")

    slug = period_slug(args.start_date, args.end_date)
    output = ROOT / "data" / "raw" / "nvd" / f"nvd_cves_{slug}.json"
    sample_output = ROOT / "data" / "sample" / f"nvd_sample_{slug}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    sample_output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not args.force:
        print(f"Using existing file: {output.relative_to(ROOT)}")
        return output

    api_key = os.getenv("NVD_API_KEY")
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    delay_seconds = 0.7 if api_key else 6.1
    base_params = {
        "pubStartDate": nvd_timestamp(args.start_date),
        "pubEndDate": nvd_timestamp(args.end_date, end_of_day=True),
        "resultsPerPage": args.results_per_page,
    }

    extracted_at = utc_now()
    vulnerabilities: list[dict[str, Any]] = []
    start_index = 0
    total_results: int | None = None
    response_metadata: dict[str, Any] = {}

    with requests.Session() as session:
        while total_results is None or start_index < total_results:
            params = {**base_params, "startIndex": start_index}
            page = request_json(session, params, headers, args.timeout, args.retries)
            page_records = page["vulnerabilities"]
            if total_results is None:
                total_results = int(page.get("totalResults", len(page_records)))
                response_metadata = {
                    key: page.get(key)
                    for key in ("resultsPerPage", "format", "version", "timestamp")
                }
                print(f"NVD reports {total_results} records for the requested period")
            vulnerabilities.extend(page_records)
            start_index += len(page_records)
            print(f"Downloaded {len(vulnerabilities)}/{total_results}")
            if not page_records or start_index >= total_results:
                break
            time.sleep(delay_seconds)

    payload = {
        "source_url": API_URL,
        "extracted_at_utc": extracted_at,
        "query": {
            "pub_start_date": args.start_date,
            "pub_end_date": args.end_date,
        },
        "response_metadata": response_metadata,
        "total_results": total_results,
        "vulnerabilities": vulnerabilities,
    }
    output.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    sample_payload = {**payload, "vulnerabilities": vulnerabilities[:25]}
    sample_payload["sample_note"] = "First 25 raw records for structural review only."
    sample_output.write_text(
        json.dumps(sample_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Saved raw data to {output.relative_to(ROOT)}")
    print(f"Saved structural sample to {sample_output.relative_to(ROOT)}")
    return output


def main() -> None:
    run(parse_args())


if __name__ == "__main__":
    main()
