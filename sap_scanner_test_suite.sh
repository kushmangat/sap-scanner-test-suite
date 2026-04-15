#!/bin/bash
# =============================================================================
# SAP Scanner Test Suite
# Tests EICAR-based scenarios mapped to known SAP Scanner behaviors
# Covers: MIME mismatch, archive extraction, file size limits, CSV/binary
#         classification, nested archives, and large file handling
# =============================================================================

EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
OUTPUT_DIR="./sap_scanner_tests"
RESULTS=()
PASS=0
FAIL=0
SKIP=0

# --- Helpers -----------------------------------------------------------------

pass() { echo "  [PASS] $1"; RESULTS+=("PASS  | $1"); ((PASS++)); }
fail() { echo "  [FAIL] $1"; RESULTS+=("FAIL  | $1"); ((FAIL++)); }
skip() { echo "  [SKIP] $1"; RESULTS+=("SKIP  | $1"); ((SKIP++)); }
section() { echo; echo ">> $1"; echo "   $(printf '%.0s-' {1..60})"; }

verify_file() {
    local file="$1"
    local min_size="${2:-1}"
    if [[ -f "$file" && $(wc -c < "$file") -ge $min_size ]]; then
        pass "Created: $(basename "$file") ($(wc -c < "$file") bytes)"
    else
        fail "Failed to create: $(basename "$file")"
    fi
}

# --- Setup -------------------------------------------------------------------

echo "============================================================"
echo "  SAP Scanner Test Suite"
echo "  Output directory: $OUTPUT_DIR"
echo "============================================================"

mkdir -p "$OUTPUT_DIR"/{mime_mismatch,archives,file_size,classification,nested}

# =============================================================================
# 1. BASELINE — Standard EICAR File
# =============================================================================
section "1. Baseline EICAR File"

printf '%s' "$EICAR" > "$OUTPUT_DIR/eicar.com"
ACTUAL_SIZE=$(wc -c < "$OUTPUT_DIR/eicar.com")
if [[ $ACTUAL_SIZE -eq 68 ]]; then
    pass "eicar.com — 68 bytes (standard)"
else
    fail "eicar.com — unexpected size: $ACTUAL_SIZE bytes (expected 68)"
fi

# Also create a .txt variant for basic detection
printf '%s' "$EICAR" > "$OUTPUT_DIR/eicar.txt"
verify_file "$OUTPUT_DIR/eicar.txt" 68

# =============================================================================
# 2. MIME TYPE MISMATCH TESTS
# Scenario: file extension doesn't match actual MIME type
# Expected: SAP Scanner should flag with "Rule Violation" error
# Note: Enable SCANBESTEFFORT for graphics types (jpg, bmp, gif)
# =============================================================================
section "2. MIME Type Mismatch Tests"

MIME_TYPES=(jpg bmp gif png pdf doc docx xml csv)
for ext in "${MIME_TYPES[@]}"; do
    OUT="$OUTPUT_DIR/mime_mismatch/eicar_disguised.$ext"
    printf '%s' "$EICAR" > "$OUT"
    verify_file "$OUT" 68
done

# Binary header spoofing — prepend JPEG magic bytes before EICAR content
printf '\xFF\xD8\xFF\xE0' > "$OUTPUT_DIR/mime_mismatch/eicar_fake_jpeg_header.jpg"
printf '%s' "$EICAR" >> "$OUTPUT_DIR/mime_mismatch/eicar_fake_jpeg_header.jpg"
verify_file "$OUTPUT_DIR/mime_mismatch/eicar_fake_jpeg_header.jpg" 72

# Executable disguised as image
printf '%s' "$EICAR" > "$OUTPUT_DIR/mime_mismatch/eicar_exec_as_image.jpg"
verify_file "$OUTPUT_DIR/mime_mismatch/eicar_exec_as_image.jpg" 68

# =============================================================================
# 3. ARCHIVE EXTRACTION TESTS
# ZIP behavior: block MIME won't trigger immediately; large ZIPs delay results
# SAR behavior: if extracted > scan limit → skipped; if smaller → completes
# =============================================================================
section "3. Archive Extraction Tests"

# 3a. EICAR in a single ZIP
printf '%s' "$EICAR" > "$OUTPUT_DIR/eicar.com"
zip -j "$OUTPUT_DIR/archives/eicar_single.zip" "$OUTPUT_DIR/eicar.com" > /dev/null 2>&1
verify_file "$OUTPUT_DIR/archives/eicar_single.zip" 1

# 3b. EICAR with wrong extension inside ZIP (MIME mismatch inside archive)
cp "$OUTPUT_DIR/eicar.com" "$OUTPUT_DIR/eicar_inside.jpg"
zip -j "$OUTPUT_DIR/archives/eicar_mismatch_inside.zip" "$OUTPUT_DIR/eicar_inside.jpg" > /dev/null 2>&1
rm -f "$OUTPUT_DIR/eicar_inside.jpg"
verify_file "$OUTPUT_DIR/archives/eicar_mismatch_inside.zip" 1

# 3c. Multiple EICAR files in one ZIP
cp "$OUTPUT_DIR/eicar.com" "$OUTPUT_DIR/eicar1.com"
cp "$OUTPUT_DIR/eicar.com" "$OUTPUT_DIR/eicar2.com"
cp "$OUTPUT_DIR/eicar.com" "$OUTPUT_DIR/eicar3.com"
zip -j "$OUTPUT_DIR/archives/eicar_multi.zip" \
    "$OUTPUT_DIR/eicar1.com" \
    "$OUTPUT_DIR/eicar2.com" \
    "$OUTPUT_DIR/eicar3.com" > /dev/null 2>&1
rm -f "$OUTPUT_DIR"/eicar{1,2,3}.com
verify_file "$OUTPUT_DIR/archives/eicar_multi.zip" 1

# 3d. Nested ZIP (ZIP inside ZIP)
zip -j "$OUTPUT_DIR/archives/inner.zip" "$OUTPUT_DIR/eicar.com" > /dev/null 2>&1
zip -j "$OUTPUT_DIR/archives/eicar_nested.zip" "$OUTPUT_DIR/archives/inner.zip" > /dev/null 2>&1
verify_file "$OUTPUT_DIR/archives/eicar_nested.zip" 1

# 3e. SAR-style archive (ZIP renamed to .sar — simulates SAP archive format)
cp "$OUTPUT_DIR/archives/eicar_single.zip" "$OUTPUT_DIR/archives/eicar_single.sar"
verify_file "$OUTPUT_DIR/archives/eicar_single.sar" 1

# 3f. EICAR mixed with benign files in ZIP
echo "This is a benign file" > "$OUTPUT_DIR/benign.txt"
zip -j "$OUTPUT_DIR/archives/eicar_mixed.zip" \
    "$OUTPUT_DIR/eicar.com" \
    "$OUTPUT_DIR/benign.txt" > /dev/null 2>&1
rm -f "$OUTPUT_DIR/benign.txt"
verify_file "$OUTPUT_DIR/archives/eicar_mixed.zip" 1

# =============================================================================
# 4. FILE SIZE BOUNDARY TESTS
# Scenario: test behavior at scan size limits (skip vs block)
# Known issue: returns "Skip file" instead of proper size-exceeded error
# =============================================================================
section "4. File Size Boundary Tests"

# 4a. Small file (well under any limit) — should always scan
printf '%s' "$EICAR" > "$OUTPUT_DIR/file_size/eicar_small.com"
verify_file "$OUTPUT_DIR/file_size/eicar_small.com" 68

# 4b. EICAR padded to ~1MB (tests mid-range scanning)
printf '%s' "$EICAR" > "$OUTPUT_DIR/file_size/eicar_1mb.com"
dd if=/dev/zero bs=1024 count=1024 >> "$OUTPUT_DIR/file_size/eicar_1mb.com" 2>/dev/null
verify_file "$OUTPUT_DIR/file_size/eicar_1mb.com" 1048576

# 4c. EICAR padded to ~10MB (tests near-default scan limits)
printf '%s' "$EICAR" > "$OUTPUT_DIR/file_size/eicar_10mb.com"
dd if=/dev/zero bs=1024 count=10240 >> "$OUTPUT_DIR/file_size/eicar_10mb.com" 2>/dev/null
verify_file "$OUTPUT_DIR/file_size/eicar_10mb.com" 10485760

# 4d. EICAR padded to ~32MB (tests upper-range limit behavior — often default DSM cap)
printf '%s' "$EICAR" > "$OUTPUT_DIR/file_size/eicar_32mb.com"
dd if=/dev/zero bs=1024 count=32768 >> "$OUTPUT_DIR/file_size/eicar_32mb.com" 2>/dev/null
verify_file "$OUTPUT_DIR/file_size/eicar_32mb.com" 33554432

# 4e. Large ZIP containing oversized EICAR (tests SAR scan-skip behavior)
zip -j "$OUTPUT_DIR/archives/eicar_10mb.zip" "$OUTPUT_DIR/file_size/eicar_10mb.com" > /dev/null 2>&1
verify_file "$OUTPUT_DIR/archives/eicar_10mb.zip" 1

# =============================================================================
# 5. FILE CLASSIFICATION TESTS
# Based on fixed bugs:
#   - CSV files >4KB were misclassified (now fixed)
#   - SWIFT messages misclassified as binary if dataset too large (now fixed)
# =============================================================================
section "5. File Classification Tests"

# 5a. CSV file < 4KB with EICAR (under regression threshold)
{
    echo "filename,size,threat"
    printf '%s' "$EICAR"
} > "$OUTPUT_DIR/classification/eicar_small.csv"
verify_file "$OUTPUT_DIR/classification/eicar_small.csv" 1

# 5b. CSV file > 4KB with EICAR (regression test for misclassification bug)
{
    echo "id,filename,size,type,hash,status,notes"
    # Pad to exceed 4KB threshold
    for i in $(seq 1 80); do
        printf '%d,testfile_%d.exe,1024,malware,deadbeef%08x,detected,SAP scanner test row %d\n' \
               "$i" "$i" "$i" "$i"
    done
    printf '%s' "$EICAR"
} > "$OUTPUT_DIR/classification/eicar_large.csv"
verify_file "$OUTPUT_DIR/classification/eicar_large.csv" 4096

# 5c. SWIFT-like message file (regression for binary misclassification)
{
    printf '{1:F01BANKUS33AXXX0000000000}{2:I103BANKGB2LXXXXN}'
    printf '{3:{108:MT103}}{4:\n'
    printf ':20:REFERENCE12345\n'
    printf ':23B:CRED\n'
    printf ':32A:260415USD1000,00\n'
    printf ':50K:SENDER NAME\n1234 SENDER ST\n'
    printf ':59:RECEIVER NAME\n5678 RECEIVER AVE\n'
    printf ':70:PAYMENT DETAILS\n'
    printf ':71A:SHA\n'
    printf '%s' '-}{5:{MAC:00000000}{CHK:000000000000}}'
    # Append EICAR to simulate malicious payload in SWIFT message
    printf '\n%s' "$EICAR"
} > "$OUTPUT_DIR/classification/swift_with_eicar.fin"
verify_file "$OUTPUT_DIR/classification/swift_with_eicar.fin" 1

# 5d. JSP file with EICAR (documented as improved format detection)
{
    echo '<%@ page language="java" %>'
    echo '<html><body>'
    printf '%s' "$EICAR"
    echo '</body></html>'
} > "$OUTPUT_DIR/classification/eicar_payload.jsp"
verify_file "$OUTPUT_DIR/classification/eicar_payload.jsp" 1

# 5e. XML file with EICAR embedded
{
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<root>'
    echo "  <payload>$(printf '%s' "$EICAR")</payload>"
    echo '</root>'
} > "$OUTPUT_DIR/classification/eicar_embedded.xml"
verify_file "$OUTPUT_DIR/classification/eicar_embedded.xml" 1

# =============================================================================
# 6. NESTED / EDGE CASE TESTS
# =============================================================================
section "6. Nested and Edge Case Tests"

# 6a. EICAR inside a ZIP inside a ZIP inside a ZIP (triple nested)
zip -j "$OUTPUT_DIR/nested/level1.zip" "$OUTPUT_DIR/eicar.com" > /dev/null 2>&1
zip -j "$OUTPUT_DIR/nested/level2.zip" "$OUTPUT_DIR/nested/level1.zip" > /dev/null 2>&1
zip -j "$OUTPUT_DIR/nested/level3.zip" "$OUTPUT_DIR/nested/level2.zip" > /dev/null 2>&1
verify_file "$OUTPUT_DIR/nested/level3.zip" 1

# 6b. Zero-byte file (edge case — scan behavior on empty files)
touch "$OUTPUT_DIR/nested/empty_file.com"
if [[ -f "$OUTPUT_DIR/nested/empty_file.com" ]]; then
    pass "Created: empty_file.com (0 bytes)"
else
    fail "Failed to create: empty_file.com"
fi

# 6c. EICAR with null bytes appended (tests binary parsing)
printf '%s' "$EICAR" > "$OUTPUT_DIR/nested/eicar_null_padded.com"
printf '\x00\x00\x00\x00\x00\x00\x00\x00' >> "$OUTPUT_DIR/nested/eicar_null_padded.com"
verify_file "$OUTPUT_DIR/nested/eicar_null_padded.com" 76

# 6d. EICAR string split across two files in same ZIP (tests partial detection)
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$' > "$OUTPUT_DIR/nested/eicar_part1.txt"
printf 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$OUTPUT_DIR/nested/eicar_part2.txt"
zip -j "$OUTPUT_DIR/nested/eicar_split.zip" \
    "$OUTPUT_DIR/nested/eicar_part1.txt" \
    "$OUTPUT_DIR/nested/eicar_part2.txt" > /dev/null 2>&1
verify_file "$OUTPUT_DIR/nested/eicar_split.zip" 1

# =============================================================================
# SUMMARY REPORT
# =============================================================================

echo
echo "============================================================"
echo "  TEST SUITE COMPLETE"
echo "============================================================"
printf "  Total: %d  |  Pass: %d  |  Fail: %d  |  Skip: %d\n" \
    $((PASS + FAIL + SKIP)) $PASS $FAIL $SKIP
echo
echo "  Results:"
for r in "${RESULTS[@]}"; do
    echo "    $r"
done

echo
echo "  Output directory: $OUTPUT_DIR"
echo
echo "  Test Files by Scenario:"
echo "    Baseline:          $OUTPUT_DIR/eicar.com, eicar.txt"
echo "    MIME Mismatch:     $OUTPUT_DIR/mime_mismatch/"
echo "    Archives:          $OUTPUT_DIR/archives/"
echo "    File Size:         $OUTPUT_DIR/file_size/"
echo "    Classification:    $OUTPUT_DIR/classification/"
echo "    Nested/Edge:       $OUTPUT_DIR/nested/"
echo
echo "  NOTE: These files are intended for use with SAP Scanner"
echo "  testing ONLY. Keep test files isolated from production"
echo "  environments. Delete after testing."
echo "============================================================"
