
#!/usr/bin/env python3
"""
TSK Validation Harness - Forensic Validation Reporter

Generates a structured JSON report describing SHA-256
comparison results and the limitations of the assessment.

This report documents technical findings. It does not
establish legal admissibility or certify a forensic tool.
"""

import csv
import json
from datetime import datetime, timezone
from collections import Counter


def generate_report(
    comparison_csv,
    output_json="outputs/court_report.json"
):
    """Generate a forensic validation report from comparison results."""

    with open(
        comparison_csv,
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as f:
        results = list(csv.DictReader(f))

    counts = Counter(
        row.get("status", "UNKNOWN")
        for row in results
    )

    matches = counts["MATCH"]
    mismatches = counts["MISMATCH"]
    comparable = matches + mismatches

    match_rate = (
        round(matches / comparable * 100, 2)
        if comparable > 0
        else None
    )

    issues = {
        "mismatches": mismatches,
        "missing_from_extraction": counts["MISSING_FROM_EXTRACTION"],
        "not_in_ground_truth": counts["NOT_IN_GROUND_TRUTH"],
        "extraction_errors": counts["EXTRACTION_ERROR"],
        "invalid_ground_truth": counts["INVALID_GROUND_TRUTH"],
        "ambiguous_filenames": counts["AMBIGUOUS_FILENAME"],
        "unknown_statuses": counts["UNKNOWN"]
    }

    unresolved = sum(issues.values())

    if comparable == 0:
        assessment = "INSUFFICIENT_COMPARABLE_DATA"
    elif unresolved > 0:
        assessment = "REVIEW_REQUIRED"
    else:
        assessment = "NO_ISSUES_IN_COMPARABLE_SET"

    report = {
        "report_title": "TSK Hash Validation Assessment",

        "report_metadata": {
            "generated_at_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "report_type": "Technical Forensic Validation",
            "hash_algorithm": "SHA-256"
        },

        "validation_summary": {
            "total_filename_groups": len(results),
            "comparable_unique_filenames": comparable,
            "matches": matches,
            "mismatches": mismatches,
            "match_rate_percent": match_rate,
            "issues": issues,
            "assessment": assessment
        },

        "methodology": {
            "extraction_tool": "pytsk3 (The Sleuth Kit bindings)",
            "comparison_method": (
                "SHA-256 values are compared by filename "
                "where exactly one extracted entry and one "
                "ground-truth entry share that filename."
            ),
            "scope": (
                "The current extractor processes regular files "
                "in the filesystem root directory only."
            )
        },

        "limitations": [
            "This assessment does not validate every file on the disk.",
            "Filename-only comparison cannot reliably distinguish files with identical names in different directories.",
            "Missing files may be outside the extraction scope rather than evidence of extraction failure.",
            "The independence and provenance of the reference hashes must be established separately.",
            "The reported match rate applies only to comparable unique filenames.",
            "A successful hash comparison does not establish overall forensic tool reliability or legal admissibility."
        ],

        "legal_note": (
            "This report documents technical observations "
            "and is not a legal opinion or certification "
            "of evidentiary admissibility."
        ),

        "file_results": results
    }

    with open(
        output_json,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(report, f, indent=4)

    print("\n" + "=" * 55)
    print("FORENSIC VALIDATION REPORT")
    print("=" * 55)

    print(f"Comparable files: {comparable}")
    print(f"Matching hashes: {matches}")
    print(f"Mismatching hashes: {mismatches}")

    if match_rate is None:
        print("Match rate: N/A")
    else:
        print(f"Match rate: {match_rate:.2f}%")

    print(f"Other unresolved issues: {unresolved - mismatches}")
    print(f"Assessment: {assessment}")
    print(f"Report saved to: {output_json}")

    print("=" * 55)

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a forensic hash validation report"
    )

    parser.add_argument("comparison_csv")
    parser.add_argument(
        "output_json",
        nargs="?",
        default="outputs/court_report.json"
    )

    args = parser.parse_args()

    generate_report(
        args.comparison_csv,
        args.output_json
    )
