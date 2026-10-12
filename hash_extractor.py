#!/usr/bin/env python3
"""
TSK Validation Harness - Hash Extractor

Extracts SHA-256 hashes from root-level regular files
in a forensic disk image using pytsk3.

Features:
- Supports filesystem offsets in bytes
- Handles zero-byte files
- Reads large files in chunks
- Records extraction errors separately
- Excludes FAT volume-label entries
"""

import argparse
import csv
import hashlib
from pathlib import Path

import pytsk3


CHUNK_SIZE = 1024 * 1024


def calculate_hash(fs_info, inode_num):
    """Calculate SHA-256 using bounded reads."""

    file_obj = fs_info.open_meta(inode_num)
    file_size = file_obj.info.meta.size

    if file_size is None or file_size < 0:
        raise ValueError("Invalid or unavailable file size")

    hasher = hashlib.sha256()
    offset = 0

    while offset < file_size:
        bytes_to_read = min(
            CHUNK_SIZE,
            file_size - offset
        )

        content = file_obj.read_random(
            offset,
            bytes_to_read
        )

        if not content:
            raise IOError(
                f"Unexpected end of file at offset {offset}"
            )

        hasher.update(content)
        offset += len(content)

    return hasher.hexdigest()


def is_fat_volume_label(entry, fs_info):
    """
    Identify FAT volume-label entries.

    FAT directory entries use attribute bit 0x08
    to identify volume labels. pytsk3 exposes the
    entry name with a '(Volume Label Entry)' suffix
    for these entries.

    This function only applies the name check to
    FAT filesystems.
    """

    fs_type = fs_info.info.ftype

    fat_types = [
        pytsk3.TSK_FS_TYPE_FAT12,
        pytsk3.TSK_FS_TYPE_FAT16,
        pytsk3.TSK_FS_TYPE_FAT32,
    ]

    if fs_type not in fat_types:
        return False

    name = entry.info.name.name.decode(
        "utf-8",
        errors="replace"
    )

    return name.endswith("(Volume Label Entry)")


def extract_hashes(
    image_path="controlled_test/controlled-test.dd",
    output_csv="outputs/tsk_hashes.csv",
    offset=0
):
    """Extract root-level regular file hashes to CSV."""

    img = pytsk3.Img_Info(image_path)
    fs = pytsk3.FS_Info(img, offset=int(offset))

    print(f"\nAnalyzing: {image_path}")
    print(f"Filesystem offset: {offset} bytes")
    print("\nSHA-256 extraction results:\n")

    results = []
    skipped_labels = 0

    root = fs.open_dir(path="/")

    for entry in root:
        try:
            if not entry.info.name:
                continue

            filename = entry.info.name.name.decode(
                "utf-8",
                errors="replace"
            )

            if filename in (".", ".."):
                continue

            if not entry.info.meta:
                continue

            if is_fat_volume_label(entry, fs):
                print(
                    f"[SKIPPED] FAT volume label: {filename}"
                )
                skipped_labels += 1
                continue

            if (
                entry.info.meta.type
                != pytsk3.TSK_FS_META_TYPE_REG
            ):
                continue

            inode_num = entry.info.meta.addr

            try:
                file_hash = calculate_hash(
                    fs,
                    inode_num
                )

                print(
                    f"[OK] {filename}: {file_hash}"
                )

                results.append({
                    "filename": filename,
                    "sha256": file_hash,
                    "status": "OK",
                    "error": ""
                })

            except Exception as exc:
                print(
                    f"[ERROR] {filename}: {exc}"
                )

                results.append({
                    "filename": filename,
                    "sha256": "",
                    "status": "ERROR",
                    "error": str(exc)
                })

        except Exception as exc:
            print(
                f"[ERROR] Directory entry: {exc}"
            )
            raise

    output_path = Path(output_csv)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "filename",
                "sha256",
                "status",
                "error"
            ]
        )

        writer.writeheader()
        writer.writerows(results)

    successful = sum(
        row["status"] == "OK"
        for row in results
    )

    failed = sum(
        row["status"] == "ERROR"
        for row in results
    )

    print("\n" + "=" * 50)
    print("HASH EXTRACTION SUMMARY")
    print("=" * 50)
    print(f"Files processed: {len(results)}")
    print(f"Successful hashes: {successful}")
    print(f"Extraction errors: {failed}")
    print(f"FAT volume labels skipped: {skipped_labels}")
    print(f"Output saved to: {output_csv}")
    print("=" * 50)

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Extract SHA-256 hashes from a forensic image"
        )
    )

    parser.add_argument(
        "image",
        nargs="?",
        default="controlled_test/controlled-test.dd"
    )

    parser.add_argument(
        "output",
        nargs="?",
        default="outputs/tsk_hashes.csv"
    )

    parser.add_argument(
        "offset",
        nargs="?",
        type=int,
        default=0
    )

    args = parser.parse_args()

    extract_hashes(
        args.image,
        args.output,
        args.offset
    )
