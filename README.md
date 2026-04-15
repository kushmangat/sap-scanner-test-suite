# SAP Scanner Test Suite

EICAR-based test file generator for validating SAP Scanner behavior in Trend Micro Deep Security and Vision One Server & Workload Protection.

## What It Tests

| Section | Scenario |
|---|---|
| Baseline | Standard 68-byte EICAR file |
| MIME Mismatch | EICAR disguised as .jpg, .bmp, .gif, .png, .pdf, .doc, .docx, .xml, .csv + spoofed JPEG magic bytes |
| Archive Extraction | Single ZIP, MIME mismatch inside ZIP, multi-file ZIP, nested ZIP, `.sar` rename, EICAR mixed with benign files |
| File Size Boundaries | 68B, ~1MB, ~10MB, ~32MB, 10MB ZIP — tests scan limit threshold behavior |
| File Classification | CSV <4KB, CSV >4KB (regression for misclassification bug), SWIFT `.fin`, JSP, XML |
| Edge Cases | Triple-nested ZIP, empty file, null-padded EICAR, split EICAR across files |

## Usage

```bash
chmod +x sap_scanner_test_suite.sh
./sap_scanner_test_suite.sh
```

Output lands in `./sap_scanner_tests/` organized by scenario:

```
sap_scanner_tests/
├── eicar.com                  # baseline
├── eicar.txt
├── mime_mismatch/             # extension ≠ MIME type
├── archives/                  # ZIP, SAR, nested
├── file_size/                 # boundary tests
├── classification/            # CSV, SWIFT, JSP, XML
└── nested/                    # edge cases
```

## Notes

- The EICAR test file is a safe, standardized antivirus test string — not real malware.
- Intended for use in isolated test environments only.
- Delete test files after use.
- Maps to known SAP Scanner issues documented in Deep Security 10.0 and Vision One SWP release notes (Jan 2025 – Mar 2026).
