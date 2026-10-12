#!/usr/bin/env python3
"""
TSK Validation Harness - Demo Version

Coordinates forensic hash extraction, comparison against
reference hashes, and generation of a technical report.

This workflow assesses a limited set of filesystem files.
It does not certify the forensic tool or establish legal
admissibility.
"""

import argparse
import os
import sys
from pathlib import Path

from hash_extractor import extract_hashes
from comparator import compare_hashes
from court_reporter import generate_report


class TSKValidator:
    def __init__(
        self,
        image_path,
        ground_truth,
        offset=0,
        output_dir="outputs"
    ):
        self.image_path = Path(image_path)
        self.ground_truth = Path(ground_truth)
        self.offset = int(offset)
        self.output_dir = Path(output_dir)

    def run_all(self):
        if not self.image_path.is_file():
            raise FileNotFoundError(
                f"Forensic image not found: {self.image_path}"
            )

        if not self.ground_truth.is_file():
            raise FileNotFoundError(
                f"Ground-truth CSV not found: {self.ground_truth}"
            )

        if self.offset < 0:
            raise ValueError(
                "Filesystem offset cannot be negative"
            )

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        hashes_csv = self.output_dir / "tsk_hashes.csv"
        comparison_csv = (
            self.output_dir / "comparison_results.csv"
        )
        report_json = self.output_dir / "court_report.json"

        print("\n" + "=" * 60)
        print("TSK VALIDATION HARNESS - DEMO")
        print("=" * 60)
        print(f"Image: {self.image_path}")
        print(f"Ground truth: {self.ground_truth}")
        print(f"Filesystem offset: {self.offset} bytes")
        print(f"Output directory: {self.output_dir}")
        print("=" * 60)

        print("\n[1/3] EXTRACTING SHA-256 HASHES")

        extract_hashes(
            str(self.image_path),
            str(hashes_csv),
            self.offset
        )

        print("\n[2/3] COMPARING WITH GROUND TRUTH")

        compare_hashes(
            str(hashes_csv),
            str(self.ground_truth),
            str(comparison_csv)
        )

        print("\n[3/3] GENERATING FORENSIC REPORT")

        report = generate_report(
            str(comparison_csv),
            str(report_json)
        )

        summary = report["validation_summary"]

        print("\n" + "=" * 60)
        print("VALIDATION WORKFLOW COMPLETE")
        print("=" * 60)

        print(f"Assessment: {summary['assessment']}")
        print(
            "Comparable files: "
            f"{summary['comparable_unique_filenames']}"
        )
        print(f"Matches: {summary['matches']}")
        print(f"Mismatches: {summary['mismatches']}")

        rate = summary["match_rate_percent"]

        if rate is None:
            print("Match rate: N/A")
        else:
            print(f"Match rate: {rate:.2f}%")

        print("\nGenerated files:")
        print(f"  {hashes_csv}")
        print(f"  {comparison_csv}")
        print(f"  {report_json}")

        print("=" * 60)

        return report


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Validate extracted forensic file hashes "
            "against a reference dataset"
        )
    )

    parser.add_argument(
        "--image",
        default="controlled_test/controlled-test.dd",
        help="Path to forensic disk image"
    )

    parser.add_argument(
        "--ground-truth",
        default="controlled_test/controlled_ground_truth.csv",
        help="Path to reference hash CSV"
    )

    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Filesystem offset in bytes"
    )

    parser.add_argument(
        "--output-dir",
        default="outputs",
        help="Directory for generated reports"
    )

    args = parser.parse_args()

    try:
        validator = TSKValidator(
            image_path=args.image,
            ground_truth=args.ground_truth,
            offset=args.offset,
            output_dir=args.output_dir
        )

        validator.run_all()

    except Exception as exc:
        print(
            f"\n[ERROR] Validation workflow failed: {exc}",
            file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
