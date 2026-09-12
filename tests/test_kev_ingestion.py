import json
import re
from pathlib import Path


SAMPLE_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "sample"
    / "cisa_kev_sample.json"
)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def load_sample():
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


def test_cisa_kev_sample_has_valid_cve_ids():
    payload = load_sample()
    vulnerabilities = payload["vulnerabilities"]

    assert vulnerabilities
    assert all(
        CVE_PATTERN.fullmatch(item["cveID"])
        for item in vulnerabilities
    )


def test_cisa_kev_sample_count_is_consistent():
    payload = load_sample()

    assert payload["observed_count"] >= len(payload["vulnerabilities"])
