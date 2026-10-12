# TSK Validation Harness

A Python-based demonstration harness for extracting SHA-256 hashes from files in forensic disk images, comparing them with reference hashes, and generating structured validation reports.

The project explores reproducible testing of digital-forensic workflows, with particular interest in how forensic practitioners can document test scope, results, and limitations. It is **not** a certification of The Sleuth Kit (TSK), a legal admissibility assessment, or a substitute for laboratory validation procedures.

## Features

- Reads forensic disk images using `pytsk3` (Python bindings for The Sleuth Kit).
- Supports a filesystem offset specified in **bytes**.
- Extracts and SHA-256-hashes **root-level regular files**, including zero-byte files.
- Reads file contents in bounded chunks and records extraction errors.
- Skips FAT volume-label entries in the controlled FAT16 test.
- Compares extracted hashes with a CSV reference dataset, reporting matches, mismatches, missing entries, extraction errors, and ambiguous filenames.
- Generates a JSON report summarizing comparable files and unresolved issues.

## Controlled validation experiment

The repository includes a **synthetic 20 MiB FAT16 disk image** containing eight known source files. Reference SHA-256 hashes were calculated directly from the source files using Python's `hashlib`, separately from the `pytsk3` extraction workflow.

The controlled experiment produced:

| Metric | Result |
| --- | ---: |
| Source evidence files | 8 |
| Successfully extracted and hashed | 8 |
| Matching SHA-256 hashes | 8 |
| Mismatches | 0 |
| Extraction errors | 0 |
| FAT volume-label entries skipped | 1 |
| Match rate among comparable unique filenames | 100% |
| Report assessment | `NO_ISSUES_IN_COMPARABLE_SET` |

The empty file was included and correctly produced the standard SHA-256 digest for zero bytes. These results demonstrate agreement **for this controlled set only**; they do not establish performance across other disk images, filesystems, deleted files, or nested directories.

The image fingerprint is recorded in `controlled_test/disk_image_sha256.txt`. The successful example reports are in `controlled_test/validation_results_v2/`.

## Repository structure

```text
tsk-validation-harness/
├── README.md
├── LICENSE
├── requirements.txt
├── validator.py
├── hash_extractor.py
├── comparator.py
├── court_reporter.py
├── .gitignore
├── controlled_test/
│   ├── controlled-test.dd
│   ├── controlled_ground_truth.csv
│   ├── disk_image_sha256.txt
│   ├── source_files/
│   └── validation_results_v2/
└── tests/
    └── test_hash_extractor.py
```

## Installation

The experiment was run on **Kali Linux** using Python 3.13 and `pytsk3`. A compatible Python environment and the dependencies in `requirements.txt` are required; `pytsk3` installation may require system build dependencies depending on the platform.

```bash
# Clone the repository
 git clone https://github.com/DeborahEssien/tsk-validation-harness.git
 cd tsk-validation-harness

# Create and activate a virtual environment
 python3 -m venv venv
 source venv/bin/activate

# Install Python dependencies
 python -m pip install -r requirements.txt
```

If necessary on Kali/Debian, install The Sleuth Kit with `sudo apt install sleuthkit`. The application accesses the image through `pytsk3`; it does not require invoking TSK command-line tools during the normal validation workflow.

## Reproduce the controlled validation

From the repository root, run:

```bash
python validator.py \
  --image controlled_test/controlled-test.dd \
  --ground-truth controlled_test/controlled_ground_truth.csv \
  --offset 0 \
  --output-dir outputs
```

This generates:

- `outputs/tsk_hashes.csv` — extracted SHA-256 hashes and extraction status.
- `outputs/comparison_results.csv` — file-by-file comparison outcomes.
- `outputs/court_report.json` — structured technical validation summary (despite its historical filename, **not** a legal opinion or court certification).

To verify the disk image has the recorded fingerprint:

```bash
sha256sum -c controlled_test/disk_image_sha256.txt
```

To run the automated tests:

```bash
python -m pytest tests/test_hash_extractor.py -v
```

The controlled-image test checks that eight extracted entries have successful status, exclude the FAT volume label, and match the supplied reference hashes. The test requires the included disk image.

## Using another image

Supply the image path, appropriate reference CSV, and **byte offset** to the filesystem:

```bash
python validator.py \
  --image /path/to/image.dd \
  --ground-truth /path/to/reference.csv \
  --offset 0 \
  --output-dir outputs
```

Reference CSV columns are `filename,sha256`. Files with the same basename in different directories can be ambiguous: the current extractor does not traverse directories recursively or use full paths as comparison keys.

## Scope and limitations

- **Root directory only:** nested files are not included in the extraction set.
- **Filesystem coverage:** the reproducible controlled test uses FAT16; broader filesystem support is not established by this experiment.
- **Filename-based comparison:** duplicate filenames are flagged as ambiguous rather than silently treated as unique.
- **Limited evidence scope:** deleted files, alternate data streams, unallocated space, and other forensic artifacts are not comprehensively validated.
- **Reference provenance:** reference hashes are calculated from known synthetic source files; they are independent of TSK extraction but use the same SHA-256 algorithm.
- **Interpretation:** a 100% match rate here applies only to eight comparable files and must not be interpreted as a general tool-accuracy figure or a statement of legal admissibility.

## Future work

Potential extensions include recursive path-aware extraction, additional filesystem test images, deliberately altered reference-hash negative controls, and expanded automated tests for error handling and ambiguous names.

## License

MIT License. See `LICENSE`.

## Author

- Deborah Essien

## Background resources

- [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/)
- [NIST Computer Forensic Reference Data Sets (CFReDS)](https://cfreds.nist.gov/) — background resource; **not** the source of the controlled test's reference hashes.
## Additional Forensic Testing — M57 Jean Dataset

The TSK Validation Harness can also be evaluated using external forensic disk images, including the **M57 Jean dataset**, a forensic research dataset associated with Digital Corpora and the NIST CFReDS collection.

**Dataset resources:**
- [NIST Computer Forensic Reference Data Sets (CFReDS)](https://cfreds.nist.gov/)
- [Digital Corpora](https://digitalcorpora.org/)

The M57 Jean disk image is not distributed with this repository and must be obtained separately.

### Running the Validator on M57 Jean

After obtaining the disk image and preparing a suitable ground-truth CSV containing independently established SHA-256 hashes, run:

```bash
python validator.py --image m57-jean.dd --ground-truth m57_ground_truth.csv --offset 32256
```

Replace the filenames and offset with the correct values for your image. The example offset is not applicable to every disk image.

The validator coordinates three components:

1. **Hash Extractor** — Extracts file contents and calculates SHA-256 hashes using The Sleuth Kit.
2. **Comparator** — Compares extracted hashes against the supplied ground truth.
3. **Court Reporter** — Generates a structured JSON report summarizing the comparison results.

**Validation scope:** The included controlled FAT16 experiment produced 8 matching SHA-256 hashes out of 8 tested files. This result does not establish the harness's accuracy on M57 Jean or other forensic datasets. External datasets require separate testing and appropriate reference hashes.
