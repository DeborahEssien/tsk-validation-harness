
#!/usr/bin/env python3
"""
TSK Validation Harness - Comparator

Compares extracted SHA-256 hashes with reference hashes.

Reports:
- MATCH
- MISMATCH
- MISSING_FROM_EXTRACTION
- NOT_IN_GROUND_TRUTH
- EXTRACTION_ERROR
- AMBIGUOUS_FILENAME

Filename-only comparison cannot reliably distinguish
files with identical names in different directories.
"""

import csv
import re
from collections import defaultdict


SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def load_csv(path):
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def is_valid_hash(value):
    return bool(SHA256_PATTERN.fullmatch((value or "").strip()))


def compare_hashes(tsk_csv, truth_csv, output_csv):
    extracted_rows = load_csv(tsk_csv)
    truth_rows = load_csv(truth_csv)

    extracted = defaultdict(list)
    ground_truth = defaultdict(list)

    for row in extracted_rows:
        filename = row.get("filename", "")
        if filename:
            extracted[filename].append(row)

    for row in truth_rows:
        filename = row.get("filename", "")
        if filename:
            ground_truth[filename].append(row)

    results = []
    counts = defaultdict(int)

    all_filenames = sorted(
        set(extracted) | set(ground_truth)
    )

    for filename in all_filenames:
        extracted_entries = extracted.get(filename, [])
        truth_entries = ground_truth.get(filename, [])

        extracted_hash = (
            extracted_entries[0].get("sha256", "")
            if extracted_entries else ""
        )

        truth_hash = (
            truth_entries[0].get("sha256", "")
            if truth_entries else ""
        )

        error_message = ""

        if len(extracted_entries) > 1 or len(truth_entries) > 1:
            status = "AMBIGUOUS_FILENAME"
            error_message = (
                "Duplicate filename; full paths required "
                "for reliable comparison"
            )

        elif not extracted_entries:
            status = "MISSING_FROM_EXTRACTION"

        elif not truth_entries:
            status = "NOT_IN_GROUND_TRUTH"

        else:
            extracted_row = extracted_entries[0]

            if extracted_row.get("status", "OK") == "ERROR":
                status = "EXTRACTION_ERROR"
                error_message = extracted_row.get("error", "")

            elif not is_valid_hash(extracted_hash):
                status = "EXTRACTION_ERROR"
                error_message = "Invalid or missing extracted SHA-256"

            elif not is_valid_hash(truth_hash):
                status = "INVALID_GROUND_TRUTH"
                error_message = "Invalid or missing reference SHA-256"

            elif extracted_hash.lower() == truth_hash.lower():
                status = "MATCH"

            else:
                status = "MISMATCH"

        counts[status] += 1

        results.append({
            "filename": filename,
            "tsk_hash": extracted_hash,
            "truth_hash": truth_hash,
            "match": (
                "YES" if status == "MATCH"
                else "NO" if status == "MISMATCH"
                else "N/A"
            ),
            "status": status,
            "error": error_message
        })

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "filename",
                "tsk_hash",
                "truth_hash",
                "match",
                "status",
                "error"
            ]
        )

        writer.writeheader()
        writer.writerows(results)

    matches = counts["MATCH"]
    mismatches = counts["MISMATCH"]
    comparable = matches + mismatches

    accuracy = (
        matches / comparable * 100
        if comparable else 0
    )

    print("\n" + "=" * 55)
    print("TSK HASH COMPARISON SUMMARY")
    print("=" * 55)

    for status in [
        "MATCH",
        "MISMATCH",
        "MISSING_FROM_EXTRACTION",
        "NOT_IN_GROUND_TRUTH",
        "EXTRACTION_ERROR",
        "INVALID_GROUND_TRUTH",
        "AMBIGUOUS_FILENAME"
    ]:
        print(f"{status}: {counts[status]}")

    print(f"\nComparable unique filenames: {comparable}")

    if comparable:
        print(f"Match rate among comparable files: {accuracy:.2f}%")
    else:
        print("Match rate: N/A (no comparable files)")

    print(f"Results saved to: {output_csv}")
    print("=" * 55)

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Compare extracted SHA-256 hashes with ground truth"
    )

    parser.add_argument("tsk_csv")
    parser.add_argument("truth_csv")
    parser.add_argument("output_csv")

    args = parser.parse_args()

    compare_hashes(
        args.tsk_csv,
        args.truth_csv,
        args.output_csv
    )
