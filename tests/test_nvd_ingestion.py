from src.ingestion.nvd_ingestion import nvd_timestamp, period_slug


def test_nvd_timestamp_uses_start_of_day():
    assert nvd_timestamp("2025-01-01") == "2025-01-01T00:00:00.000"


def test_nvd_timestamp_uses_end_of_day():
    assert (
        nvd_timestamp("2025-03-31", end_of_day=True)
        == "2025-03-31T23:59:59.999"
    )


def test_period_slug_for_initial_sample():
    assert period_slug("2025-01-01", "2025-03-31") == "2025_q1"
