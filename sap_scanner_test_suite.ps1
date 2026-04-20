#Requires -Version 5.1
# =============================================================================
# SAP Scanner Test Suite (PowerShell)
# Tests EICAR-based scenarios mapped to known SAP Scanner behaviors
# Covers: MIME mismatch, archive extraction, file size limits, CSV/binary
#         classification, nested archives, and large file handling
# =============================================================================

Add-Type -AssemblyName System.IO.Compression.FileSystem

# Use single quotes to prevent PowerShell from interpreting $ as variable sigil
$EICAR      = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$OUTPUT_DIR = '.\sap_scanner_tests'
$Results    = [System.Collections.Generic.List[string]]::new()
$PassCount  = 0
$FailCount  = 0
$SkipCount  = 0

# --- Helpers -----------------------------------------------------------------

function Write-Pass  { param($Msg) Write-Host "  [PASS] $Msg" -ForegroundColor Green;  $script:Results.Add("PASS  | $Msg"); $script:PassCount++ }
function Write-Fail  { param($Msg) Write-Host "  [FAIL] $Msg" -ForegroundColor Red;    $script:Results.Add("FAIL  | $Msg"); $script:FailCount++ }
function Write-Skip  { param($Msg) Write-Host "  [SKIP] $Msg" -ForegroundColor Yellow; $script:Results.Add("SKIP  | $Msg"); $script:SkipCount++ }
function Write-Section { param($Title) Write-Host "`n>> $Title`n   $('-' * 60)" }

# Write bytes to a file (no trailing newline — equivalent to printf '%s')
function Write-Bytes {
    param([string]$Path, [byte[]]$Bytes, [switch]$Append)
    if ($Append) {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Dispose()
    } else {
        [System.IO.File]::WriteAllBytes($Path, $Bytes)
    }
}

# Write EICAR string as ASCII bytes (no newline)
function Write-Eicar {
    param([string]$Path, [switch]$Append)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($EICAR)
    Write-Bytes -Path $Path -Bytes $bytes -Append:$Append
}

# Verify a file exists and meets minimum byte size
function Confirm-File {
    param([string]$Path, [int]$MinSize = 1)
    $name = [System.IO.Path]::GetFileName($Path)
    if ((Test-Path $Path) -and (Get-Item $Path).Length -ge $MinSize) {
        Write-Pass "Created: $name ($((Get-Item $Path).Length) bytes)"
    } else {
        Write-Fail "Failed to create: $name"
    }
}

# Create a ZIP archive from one or more source files (flat — no directory paths, like zip -j)
function New-ZipArchive {
    param([string]$ZipPath, [string[]]$SourceFiles)
    Remove-Item $ZipPath -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    foreach ($file in $SourceFiles) {
        $entryName = [System.IO.Path]::GetFileName($file)
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file, $entryName) | Out-Null
    }
    $zip.Dispose()
}

# Append N zero bytes to an existing file (equivalent to dd if=/dev/zero)
function Add-ZeroPadding {
    param([string]$Path, [long]$ByteCount)
    $zeros  = [byte[]]::new($ByteCount)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append)
    $stream.Write($zeros, 0, $zeros.Length)
    $stream.Dispose()
}

# --- Setup -------------------------------------------------------------------

Write-Host '============================================================'
Write-Host '  SAP Scanner Test Suite'
Write-Host "  Output directory: $OUTPUT_DIR"
Write-Host '============================================================'

@('mime_mismatch','archives','file_size','classification','nested') | ForEach-Object {
    New-Item -ItemType Directory -Path "$OUTPUT_DIR\$_" -Force | Out-Null
}

# =============================================================================
# 1. BASELINE — Standard EICAR File
# =============================================================================
Write-Section '1. Baseline EICAR File'

Write-Eicar -Path "$OUTPUT_DIR\eicar.com"
$actualSize = (Get-Item "$OUTPUT_DIR\eicar.com").Length
if ($actualSize -eq 68) {
    Write-Pass 'eicar.com — 68 bytes (standard)'
} else {
    Write-Fail "eicar.com — unexpected size: $actualSize bytes (expected 68)"
}

Write-Eicar -Path "$OUTPUT_DIR\eicar.txt"
Confirm-File -Path "$OUTPUT_DIR\eicar.txt" -MinSize 68

# =============================================================================
# 2. MIME TYPE MISMATCH TESTS
# Scenario: file extension doesn't match actual MIME type
# Expected: SAP Scanner should flag with "Rule Violation" error
# Note: Enable SCANBESTEFFORT for graphics types (jpg, bmp, gif)
# =============================================================================
Write-Section '2. MIME Type Mismatch Tests'

foreach ($ext in @('jpg','bmp','gif','png','pdf','doc','docx','xml','csv')) {
    $out = "$OUTPUT_DIR\mime_mismatch\eicar_disguised.$ext"
    Write-Eicar -Path $out
    Confirm-File -Path $out -MinSize 68
}

# Binary header spoofing — prepend JPEG magic bytes before EICAR content
$jpegMagic = [byte[]]@(0xFF, 0xD8, 0xFF, 0xE0)
Write-Bytes -Path "$OUTPUT_DIR\mime_mismatch\eicar_fake_jpeg_header.jpg" -Bytes $jpegMagic
Write-Eicar -Path "$OUTPUT_DIR\mime_mismatch\eicar_fake_jpeg_header.jpg" -Append
Confirm-File -Path "$OUTPUT_DIR\mime_mismatch\eicar_fake_jpeg_header.jpg" -MinSize 72

# Executable disguised as image
Write-Eicar -Path "$OUTPUT_DIR\mime_mismatch\eicar_exec_as_image.jpg"
Confirm-File -Path "$OUTPUT_DIR\mime_mismatch\eicar_exec_as_image.jpg" -MinSize 68

# =============================================================================
# 3. ARCHIVE EXTRACTION TESTS
# ZIP behavior: block MIME won't trigger immediately; large ZIPs delay results
# SAR behavior: if extracted > scan limit → skipped; if smaller → completes
# =============================================================================
Write-Section '3. Archive Extraction Tests'

# 3a. EICAR in a single ZIP
New-ZipArchive -ZipPath "$OUTPUT_DIR\archives\eicar_single.zip" -SourceFiles @("$OUTPUT_DIR\eicar.com")
Confirm-File -Path "$OUTPUT_DIR\archives\eicar_single.zip"

# 3b. EICAR with wrong extension inside ZIP (MIME mismatch inside archive)
Copy-Item "$OUTPUT_DIR\eicar.com" "$OUTPUT_DIR\eicar_inside.jpg"
New-ZipArchive -ZipPath "$OUTPUT_DIR\archives\eicar_mismatch_inside.zip" -SourceFiles @("$OUTPUT_DIR\eicar_inside.jpg")
Remove-Item "$OUTPUT_DIR\eicar_inside.jpg"
Confirm-File -Path "$OUTPUT_DIR\archives\eicar_mismatch_inside.zip"

# 3c. Multiple EICAR files in one ZIP
Copy-Item "$OUTPUT_DIR\eicar.com" "$OUTPUT_DIR\eicar1.com"
Copy-Item "$OUTPUT_DIR\eicar.com" "$OUTPUT_DIR\eicar2.com"
Copy-Item "$OUTPUT_DIR\eicar.com" "$OUTPUT_DIR\eicar3.com"
New-ZipArchive -ZipPath "$OUTPUT_DIR\archives\eicar_multi.zip" -SourceFiles @(
    "$OUTPUT_DIR\eicar1.com",
    "$OUTPUT_DIR\eicar2.com",
    "$OUTPUT_DIR\eicar3.com"
)
Remove-Item "$OUTPUT_DIR\eicar1.com","$OUTPUT_DIR\eicar2.com","$OUTPUT_DIR\eicar3.com"
Confirm-File -Path "$OUTPUT_DIR\archives\eicar_multi.zip"

# 3d. Nested ZIP (ZIP inside ZIP)
New-ZipArchive -ZipPath "$OUTPUT_DIR\archives\inner.zip" -SourceFiles @("$OUTPUT_DIR\eicar.com")
New-ZipArchive -ZipPath "$OUTPUT_DIR\archives\eicar_nested.zip" -SourceFiles @("$OUTPUT_DIR\archives\inner.zip")
Confirm-File -Path "$OUTPUT_DIR\archives\eicar_nested.zip"

# 3e. SAR-style archive (ZIP renamed to .sar — simulates SAP archive format)
Copy-Item "$OUTPUT_DIR\archives\eicar_single.zip" "$OUTPUT_DIR\archives\eicar_single.sar"
Confirm-File -Path "$OUTPUT_DIR\archives\eicar_single.sar"

# 3f. EICAR mixed with benign files in ZIP
$benignPath = "$OUTPUT_DIR\benign.txt"
[System.IO.File]::WriteAllText($benignPath, "This is a benign file`n", [System.Text.Encoding]::ASCII)
New-ZipArchive -ZipPath "$OUTPUT_DIR\archives\eicar_mixed.zip" -SourceFiles @(
    "$OUTPUT_DIR\eicar.com",
    $benignPath
)
Remove-Item $benignPath
Confirm-File -Path "$OUTPUT_DIR\archives\eicar_mixed.zip"

# =============================================================================
# 4. FILE SIZE BOUNDARY TESTS
# Scenario: test behavior at scan size limits (skip vs block)
# Known issue: returns "Skip file" instead of proper size-exceeded error
# =============================================================================
Write-Section '4. File Size Boundary Tests'

# 4a. Small file (well under any limit) — should always scan
Write-Eicar -Path "$OUTPUT_DIR\file_size\eicar_small.com"
Confirm-File -Path "$OUTPUT_DIR\file_size\eicar_small.com" -MinSize 68

# 4b. EICAR padded to ~1MB
Write-Eicar -Path "$OUTPUT_DIR\file_size\eicar_1mb.com"
Add-ZeroPadding -Path "$OUTPUT_DIR\file_size\eicar_1mb.com" -ByteCount 1MB
Confirm-File -Path "$OUTPUT_DIR\file_size\eicar_1mb.com" -MinSize 1MB

# 4c. EICAR padded to ~10MB
Write-Eicar -Path "$OUTPUT_DIR\file_size\eicar_10mb.com"
Add-ZeroPadding -Path "$OUTPUT_DIR\file_size\eicar_10mb.com" -ByteCount 10MB
Confirm-File -Path "$OUTPUT_DIR\file_size\eicar_10mb.com" -MinSize 10MB

# 4d. EICAR padded to ~32MB (tests upper-range limit — often default DSM cap)
Write-Eicar -Path "$OUTPUT_DIR\file_size\eicar_32mb.com"
Add-ZeroPadding -Path "$OUTPUT_DIR\file_size\eicar_32mb.com" -ByteCount 32MB
Confirm-File -Path "$OUTPUT_DIR\file_size\eicar_32mb.com" -MinSize 32MB

# 4e. Large ZIP containing oversized EICAR (tests SAR scan-skip behavior)
New-ZipArchive -ZipPath "$OUTPUT_DIR\archives\eicar_10mb.zip" -SourceFiles @("$OUTPUT_DIR\file_size\eicar_10mb.com")
Confirm-File -Path "$OUTPUT_DIR\archives\eicar_10mb.zip"

# =============================================================================
# 5. FILE CLASSIFICATION TESTS
# Based on fixed bugs:
#   - CSV files >4KB were misclassified (now fixed)
#   - SWIFT messages misclassified as binary if dataset too large (now fixed)
# =============================================================================
Write-Section '5. File Classification Tests'

# 5a. CSV file < 4KB with EICAR (under regression threshold)
$csv = [System.Text.StringBuilder]::new()
[void]$csv.AppendLine('filename,size,threat')
[void]$csv.Append($EICAR)
[System.IO.File]::WriteAllText("$OUTPUT_DIR\classification\eicar_small.csv",
    $csv.ToString(), [System.Text.Encoding]::ASCII)
Confirm-File -Path "$OUTPUT_DIR\classification\eicar_small.csv"

# 5b. CSV file > 4KB with EICAR (regression test for misclassification bug)
$csv = [System.Text.StringBuilder]::new()
[void]$csv.AppendLine('id,filename,size,type,hash,status,notes')
1..80 | ForEach-Object {
    [void]$csv.AppendLine("$_,testfile_$_.exe,1024,malware,deadbeef$("{0:x8}" -f $_),detected,SAP scanner test row $_")
}
[void]$csv.Append($EICAR)
[System.IO.File]::WriteAllText("$OUTPUT_DIR\classification\eicar_large.csv",
    $csv.ToString(), [System.Text.Encoding]::ASCII)
Confirm-File -Path "$OUTPUT_DIR\classification\eicar_large.csv" -MinSize 4096

# 5c. SWIFT-like message file (regression for binary misclassification)
# Single-quoted here-string avoids interpolation of $ and { characters
$swiftBody = @'
{1:F01BANKUS33AXXX0000000000}{2:I103BANKGB2LXXXXN}{3:{108:MT103}}{4:
:20:REFERENCE12345
:23B:CRED
:32A:260415USD1000,00
:50K:SENDER NAME
1234 SENDER ST
:59:RECEIVER NAME
5678 RECEIVER AVE
:70:PAYMENT DETAILS
:71A:SHA
-}{5:{MAC:00000000}{CHK:000000000000}}
'@
[System.IO.File]::WriteAllText("$OUTPUT_DIR\classification\swift_with_eicar.fin",
    ($swiftBody + $EICAR), [System.Text.Encoding]::ASCII)
Confirm-File -Path "$OUTPUT_DIR\classification\swift_with_eicar.fin"

# 5d. JSP file with EICAR (documented as improved format detection)
$jsp = "<%@ page language=`"java`" %>`n<html><body>`n" + $EICAR + "`n</body></html>`n"
[System.IO.File]::WriteAllText("$OUTPUT_DIR\classification\eicar_payload.jsp",
    $jsp, [System.Text.Encoding]::ASCII)
Confirm-File -Path "$OUTPUT_DIR\classification\eicar_payload.jsp"

# 5e. XML file with EICAR embedded
$xml = "<?xml version=`"1.0`" encoding=`"UTF-8`"?>`n<root>`n  <payload>$EICAR</payload>`n</root>`n"
[System.IO.File]::WriteAllText("$OUTPUT_DIR\classification\eicar_embedded.xml",
    $xml, [System.Text.Encoding]::ASCII)
Confirm-File -Path "$OUTPUT_DIR\classification\eicar_embedded.xml"

# =============================================================================
# 6. NESTED / EDGE CASE TESTS
# =============================================================================
Write-Section '6. Nested and Edge Case Tests'

# 6a. Triple nested ZIP (ZIP inside ZIP inside ZIP)
New-ZipArchive -ZipPath "$OUTPUT_DIR\nested\level1.zip" -SourceFiles @("$OUTPUT_DIR\eicar.com")
New-ZipArchive -ZipPath "$OUTPUT_DIR\nested\level2.zip" -SourceFiles @("$OUTPUT_DIR\nested\level1.zip")
New-ZipArchive -ZipPath "$OUTPUT_DIR\nested\level3.zip" -SourceFiles @("$OUTPUT_DIR\nested\level2.zip")
Confirm-File -Path "$OUTPUT_DIR\nested\level3.zip"

# 6b. Zero-byte file (edge case — scan behavior on empty files)
$emptyPath = "$OUTPUT_DIR\nested\empty_file.com"
[System.IO.File]::WriteAllBytes($emptyPath, [byte[]]@())
if (Test-Path $emptyPath) {
    Write-Pass 'Created: empty_file.com (0 bytes)'
} else {
    Write-Fail 'Failed to create: empty_file.com'
}

# 6c. EICAR with null bytes appended (tests binary parsing)
Write-Eicar -Path "$OUTPUT_DIR\nested\eicar_null_padded.com"
Write-Bytes -Path "$OUTPUT_DIR\nested\eicar_null_padded.com" -Bytes ([byte[]]@(0,0,0,0,0,0,0,0)) -Append
Confirm-File -Path "$OUTPUT_DIR\nested\eicar_null_padded.com" -MinSize 76

# 6d. EICAR string split across two files in same ZIP (tests partial detection)
[System.IO.File]::WriteAllText("$OUTPUT_DIR\nested\eicar_part1.txt",
    'X5O!P%@AP[4\PZX54(P^)7CC)7}$', [System.Text.Encoding]::ASCII)
[System.IO.File]::WriteAllText("$OUTPUT_DIR\nested\eicar_part2.txt",
    'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', [System.Text.Encoding]::ASCII)
New-ZipArchive -ZipPath "$OUTPUT_DIR\nested\eicar_split.zip" -SourceFiles @(
    "$OUTPUT_DIR\nested\eicar_part1.txt",
    "$OUTPUT_DIR\nested\eicar_part2.txt"
)
Confirm-File -Path "$OUTPUT_DIR\nested\eicar_split.zip"

# =============================================================================
# SUMMARY REPORT
# =============================================================================

$total = $PassCount + $FailCount + $SkipCount

Write-Host ''
Write-Host '============================================================'
Write-Host '  TEST SUITE COMPLETE'
Write-Host '============================================================'
Write-Host "  Total: $total  |  Pass: $PassCount  |  Fail: $FailCount  |  Skip: $SkipCount"
Write-Host ''
Write-Host '  Results:'
foreach ($r in $Results) { Write-Host "    $r" }

Write-Host ''
Write-Host "  Output directory: $OUTPUT_DIR"
Write-Host ''
Write-Host '  Test Files by Scenario:'
Write-Host "    Baseline:          $OUTPUT_DIR\eicar.com, eicar.txt"
Write-Host "    MIME Mismatch:     $OUTPUT_DIR\mime_mismatch\"
Write-Host "    Archives:          $OUTPUT_DIR\archives\"
Write-Host "    File Size:         $OUTPUT_DIR\file_size\"
Write-Host "    Classification:    $OUTPUT_DIR\classification\"
Write-Host "    Nested/Edge:       $OUTPUT_DIR\nested\"
Write-Host ''
Write-Host '  NOTE: These files are intended for use with SAP Scanner'
Write-Host '  testing ONLY. Keep test files isolated from production'
Write-Host '  environments. Delete after testing.'
Write-Host '============================================================'
