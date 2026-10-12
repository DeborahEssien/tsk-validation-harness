
#!/usr/bin/env python3
"""Automated tests for the controlled FAT16 validation experiment."""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hash_extractor import extract_hashes


PROJECT_DIR = Path(__file__).resolve().parents[1]
IMAGE = PROJECT_DIR / "controlled_test" / "controlled-test.dd"
GROUND_TRUTH = (
    PROJECT_DIR / "controlled_test" / "controlled_ground_truth.csv"
)


def test_extract_hashes_function_exists():
    assert callable(extract_hashes)


def test_extract_hashes_accepts_expected_arguments():
    import inspect

    parameters = list(inspect.signature(extract_hashes).parameters)
    assert parameters[:3] == ["image_path", "output_csv", "offset"]


def test_controlled_image_hashes_match_ground_truth(tmp_path):
    assert IMAGE.is_file(), "Controlled test image is missing"
    assert GROUND_TRUTH.is_file(), "Controlled ground truth is missing"

    output_csv = tmp_path / "tsk_hashes.csv"

    extract_hashes(
        image_path=str(IMAGE),
        output_csv=str(output_csv),
        offset=0,
    )

    assert output_csv.is_file()

    with GROUND_TRUTH.open(newline="", encoding="utf-8") as file:
        reference = {
            row["filename"]: row["sha256"].lower()
            for row in csv.DictReader(file)
        }

    with output_csv.open(newline="", encoding="utf-8") as file:
        extracted_rows = list(csv.DictReader(file))

    assert len(reference) == 8
    assert len(extracted_rows) == 8

    extracted = {}

    for row in extracted_rows:
        assert row["status"] == "OK"
        assert row["error"] == ""
        assert row["filename"] not in extracted
        assert "Volume Label Entry" not in row["filename"]

        extracted[row["filename"]] = row["sha256"].lower()

    assert set(extracted) == set(reference)
    assert extracted == reference
