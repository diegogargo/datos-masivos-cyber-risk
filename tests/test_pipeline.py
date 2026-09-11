import pandas as pd

from src.ingestion.nvd_ingestion import extract_cwe, select_cvss
from src.processing.build_sample_dataset import build_dataset


def test_select_cvss_prefers_v40():
    metrics = {
        "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1"}}],
        "cvssMetricV40": [{"type": "Primary", "cvssData": {"version": "4.0"}}],
    }
    assert select_cvss(metrics)["cvss_version"] == "4.0"


def test_extract_cwe_prefers_primary():
    weaknesses = [
        {"type": "Secondary", "description": [{"lang": "en", "value": "CWE-79"}]},
        {"type": "Primary", "description": [{"lang": "en", "value": "CWE-89"}]},
    ]
    assert extract_cwe(weaknesses) == "CWE-89"


def test_days_to_kev_ignores_negative_difference():
    nvd = pd.DataFrame({
        "cve_id": ["CVE-2025-1000", "CVE-2025-1001"],
        "published": pd.to_datetime(["2025-01-10", "2025-01-10"], utc=True),
    })
    kev = pd.DataFrame({
        "cve_id": ["CVE-2025-1000", "CVE-2025-1001"],
        "date_added": pd.to_datetime(["2025-01-15", "2025-01-01"], utc=True),
    })
    result = build_dataset(nvd, kev)
    values = result.set_index("cve_id")["days_to_kev"]
    assert values["CVE-2025-1000"] == 5
    assert pd.isna(values["CVE-2025-1001"])
