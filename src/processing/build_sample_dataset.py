"""Normalize NVD and CISA KEV data and build the initial analytical dataset."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import pandas as pd

from src.ingestion.nvd_ingestion import normalize_nvd_record, period_slug


ROOT = Path(__file__).resolve().parents[2]
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
KEV_COLUMNS = {
    "cveID": "cve_id",
    "vendorProject": "vendor_project",
    "product": "product",
    "vulnerabilityName": "vulnerability_name",
    "dateAdded": "date_added",
    "shortDescription": "short_description",
    "requiredAction": "required_action",
    "dueDate": "due_date",
    "knownRansomwareCampaignUse": "known_ransomware_campaign_use",
    "notes": "notes",
}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing input: {path.relative_to(ROOT)}")
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in {path.relative_to(ROOT)}")
    return payload


def normalize_nvd(payload: dict[str, Any]) -> tuple[pd.DataFrame, int]:
    records = payload.get("vulnerabilities")
    if not isinstance(records, list):
        raise ValueError("NVD raw file does not contain a vulnerabilities list")
    extracted_at = str(payload.get("extracted_at_utc", ""))
    frame = pd.DataFrame(normalize_nvd_record(item, extracted_at) for item in records)
    if frame.empty:
        raise ValueError("NVD raw file contains no records")
    invalid = ~frame["cve_id"].fillna("").str.match(CVE_PATTERN)
    if invalid.any():
        examples = frame.loc[invalid, "cve_id"].head().tolist()
        raise ValueError(f"Invalid NVD CVE identifiers: {examples}")
    duplicate_count = int(frame.duplicated("cve_id", keep=False).sum())
    frame["published"] = pd.to_datetime(frame["published"], errors="coerce", utc=True)
    frame["last_modified"] = pd.to_datetime(
        frame["last_modified"], errors="coerce", utc=True
    )
    frame["base_score"] = pd.to_numeric(frame["base_score"], errors="coerce")
    frame = frame.sort_values(["cve_id", "last_modified"]).drop_duplicates(
        "cve_id", keep="last"
    )
    return frame.reset_index(drop=True), duplicate_count


def normalize_kev(
    payload: dict[str, Any], metadata: dict[str, Any]
) -> tuple[pd.DataFrame, int]:
    records = payload.get("vulnerabilities")
    if not isinstance(records, list):
        raise ValueError("CISA KEV raw file does not contain a vulnerabilities list")
    frame = pd.DataFrame(records).rename(columns=KEV_COLUMNS)
    for column in KEV_COLUMNS.values():
        if column not in frame:
            frame[column] = pd.NA
    frame = frame[list(KEV_COLUMNS.values())]
    invalid = ~frame["cve_id"].fillna("").str.match(CVE_PATTERN)
    if invalid.any():
        examples = frame.loc[invalid, "cve_id"].head().tolist()
        raise ValueError(f"Invalid KEV CVE identifiers: {examples}")
    duplicate_count = int(frame.duplicated("cve_id", keep=False).sum())
    frame["date_added"] = pd.to_datetime(frame["date_added"], errors="coerce", utc=True)
    frame["due_date"] = pd.to_datetime(frame["due_date"], errors="coerce", utc=True)
    frame["kev_extracted_at_utc"] = metadata.get("extracted_at_utc")
    frame = frame.sort_values(["cve_id", "date_added"]).drop_duplicates(
        "cve_id", keep="last"
    )
    return frame.reset_index(drop=True), duplicate_count


def build_dataset(nvd: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    kev_ids = set(kev["cve_id"])
    merged = nvd.merge(kev, on="cve_id", how="left", validate="one_to_one")
    merged["in_kev"] = merged["cve_id"].isin(kev_ids).astype("int8")
    elapsed = (merged["date_added"] - merged["published"]).dt.total_seconds() / 86400
    merged["days_to_kev"] = elapsed.where((merged["in_kev"] == 1) & elapsed.ge(0))
    if not merged["cve_id"].is_unique:
        raise ValueError("Analytical dataset contains duplicate cve_id values")
    if not set(merged["in_kev"].unique()).issubset({0, 1}):
        raise ValueError("in_kev contains values other than 0 and 1")
    if merged["days_to_kev"].dropna().lt(0).any():
        raise ValueError("days_to_kev contains negative values")
    return merged.sort_values(["published", "cve_id"]).reset_index(drop=True)


def missing_percent(frame: pd.DataFrame) -> dict[str, float]:
    return {
        column: round(float(frame[column].isna().mean() * 100), 2)
        for column in frame.columns
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-date", default="2025-01-01")
    parser.add_argument("--end-date", default="2025-03-31")
    parser.add_argument("--sample-size", type=int, default=1000)
    return parser.parse_args()


def run(args: argparse.Namespace) -> Path:
    slug = period_slug(args.start_date, args.end_date)
    nvd_path = ROOT / "data" / "raw" / "nvd" / f"nvd_cves_{slug}.json"
    kev_path = ROOT / "data" / "raw" / "cisa" / "kev_catalog.json"
    kev_metadata_path = kev_path.with_name("kev_catalog.metadata.json")
    nvd_payload = load_json(nvd_path)
    kev_payload = load_json(kev_path)
    kev_metadata = load_json(kev_metadata_path)

    nvd, nvd_duplicate_rows = normalize_nvd(nvd_payload)
    kev, kev_duplicate_rows = normalize_kev(kev_payload, kev_metadata)
    analytical = build_dataset(nvd, kev)

    interim_dir = ROOT / "data" / "interim"
    processed_dir = ROOT / "data" / "processed"
    sample_dir = ROOT / "data" / "sample"
    for directory in (interim_dir, processed_dir, sample_dir):
        directory.mkdir(parents=True, exist_ok=True)

    nvd.to_csv(interim_dir / f"nvd_normalized_{slug}.csv", index=False)
    kev.to_csv(interim_dir / "cisa_kev_normalized.csv", index=False)
    processed_path = processed_dir / f"vulnerabilities_{slug}.csv"
    analytical.to_csv(processed_path, index=False)

    sample_size = min(max(args.sample_size, 1), len(analytical))
    sample = analytical.sample(n=sample_size, random_state=42).sort_values(
        ["published", "cve_id"]
    )
    sample_path = sample_dir / f"analytical_sample_{slug}.csv"
    sample.to_csv(sample_path, index=False)

    raw_days = (analytical["date_added"] - analytical["published"]).dt.total_seconds() / 86400
    summary = {
        "period": {"start_date": args.start_date, "end_date": args.end_date},
        "nvd_raw_records": len(nvd_payload["vulnerabilities"]),
        "nvd_unique_records": len(nvd),
        "nvd_duplicate_rows_detected": nvd_duplicate_rows,
        "kev_catalog_records": len(kev_payload["vulnerabilities"]),
        "kev_unique_records": len(kev),
        "kev_duplicate_rows_detected": kev_duplicate_rows,
        "analytical_rows": len(analytical),
        "analytical_unique_cves": int(analytical["cve_id"].nunique()),
        "analytical_duplicate_rows": int(analytical.duplicated().sum()),
        "in_kev_count": int(analytical["in_kev"].sum()),
        "in_kev_percent": round(float(analytical["in_kev"].mean() * 100), 4),
        "days_to_kev_valid_count": int(analytical["days_to_kev"].notna().sum()),
        "negative_temporal_differences_excluded": int(raw_days.lt(0).sum()),
        "sample_rows": len(sample),
        "missing_percent": missing_percent(analytical),
        "note": "in_kev=0 means not found in the downloaded KEV catalog, not not exploited.",
    }
    (sample_dir / "build_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Saved analytical data to {processed_path.relative_to(ROOT)}")
    print(f"Saved review sample to {sample_path.relative_to(ROOT)}")
    return processed_path


def main() -> None:
    run(parse_args())


if __name__ == "__main__":
    main()
