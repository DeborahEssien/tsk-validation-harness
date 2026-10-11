# TSK Validation Harness

This is a Python-based validation tool for The Sleuth Kit (TSK) that helps small law enforcement agencies demonstrate tool reliability for evidence admissibility in Canadian courts.

## Overview

This tool validates TSK file hashes against the NIST CFReDS M57-Jean ground truth dataset, producing a court-ready JSON report. It addresses the challenge faced by resource-constrained Canadian law enforcement agencies who use open-source forensic tools but must still meet evidentiary standards under *R. v. Mohan* (1994) and *R. v. Bingley* (2017).

## Features

- Extracts file hashes from disk images using TSK (`fls`, `icat`, `istat`)
- Compares extracted hashes against NIST ground truth
- Generates JSON report with:
  - File-by-file match/mismatch status
  - Accuracy percentage
  - Plain-language court summary
- Sanity test injection for mismatch detection verification
- Processing: <10 minutes/10GB on standard hardware

## Repository Structure

```
tsk-validation-harness/
├── README.md
├── LICENSE
├── requirements.txt
├── validator.py                 # Main validation tool
├── hash_extractor.py            # Extracts SHA-256 hashes
├── comparator.py                # Compares hashes vs ground truth
├── court_reporter.py            # Generates JSON court report
├── compare_m57.py               # M57-specific comparison script
├── hash_extractor_m57_subset.py # M57 subset extraction
├── ground_truth.csv             # Ground truth for test image
├── ground_truth_correct.csv     # Corrected ground truth
├── m57_ground_truth.csv         # Ground truth for M57-Jean
├── my-test.dd                   # Test disk image
├── tsk_hashes.txt               # Example output
├── tsk_hashes_m57.txt           # M57 extraction output
├── validation_report.json       # Example court report
└── tests/                       # Automated tests
```

## Installation

### Prerequisites

- Python 3.11+
- The Sleuth Kit (TSK) 4.12+

### Step 1: Install TSK

**Kali Linux:**
```bash
sudo apt-get install sleuthkit
```

**Ubuntu/Debian:**
```bash
sudo apt-get install sleuthkit
```

**macOS:**
```bash
brew install sleuthkit
```

**Windows:**
Download from https://www.sleuthkit.org/sleuthkit/download.php

### Step 2: Clone and Set Up

```bash
git clone https://github.com/DeborahEssien/tsk-validation-harness
cd tsk-validation-harness
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## How to Run

### Option A: Using Validator (Recommended)

```bash
python validator.py --image my-test.dd --ground-truth ground_truth.csv
```

### Option B: Run Step by Step

```bash
# Step 1: Extract hashes
python hash_extractor.py my-test.dd outputs/tsk_hashes.csv

# Step 2: Compare against ground truth
python comparator.py outputs/tsk_hashes.csv ground_truth.csv outputs/comparison_results.csv

# Step 3: Generate court report
python court_reporter.py outputs/comparison_results.csv outputs/court_report.json
```

### Option C: Run on M57-Jean (with offset)

```bash
python validator.py --image m57-jean.dd --ground-truth m57_ground_truth.csv --offset 32256
```

## Expected Output

```json
{
  "summary": {
    "total_files_compared": 8,
    "matches": 8,
    "mismatches": 0,
    "accuracy_percent": 100.0
  },
  "court_summary": {
    "statement": "TSK demonstrated 100.00% accuracy on 8 files.",
    "recommendation": "Tool is reliable for forensic use"
  }
}
```

## Running Tests

```bash
pytest tests/ -v
```

## License

MIT License

## Authors
- Deborah Essien (1408505)

## References

- Casey, E., Nelson, A. & Hyde, J. (2019). Digital Investigation, 31, 100873.
- Hargreaves, C., Nelson, A., & Casey, E. (2024). Forensic Science International: Digital Investigation, 48(Suppl.) 301723.
- NIST (2023). Computer Forensic Reference Data Sets (CFReDS). https://cfreds.nist.gov/
