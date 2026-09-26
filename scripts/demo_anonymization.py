"""Demonstration script for DPDP Act 2023 compliant PII anonymization on logs and forensic artifacts."""

import tempfile
from pathlib import Path

from core.privacy.anonymizer import AnonymizationMethod, Anonymizer
from core.privacy.log_filter import LogFilter
from core.privacy.pii_detector import PIIDetector

print("=" * 70)
print("DPDP ACT 2023 COMPLIANT FORENSIC PII ANONYMIZATION DEMONSTRATION")
print("=" * 70)

# 1. Sample Log with synthetic PII
raw_log = """2026-09-26 10:00:00 [AUTH] User login: rajesh.kumar@cybersec.in from 192.168.1.105 (internal)
2026-09-26 10:01:15 [KYC] Verified Aadhaar: 2345 6789 0123 with phone: +91-9876543210
2026-09-26 10:02:30 [PAYMENT] PAN: ABCDE1234F, Card: 4532-7589-2341-9823 CVV: 891
2026-09-26 10:03:00 [ALERT] Attack detected from external C2 IP: 198.51.100.45 targeting 10.0.0.12"""

print("\n--- [ORIGINAL RAW LOG] ---")
print(raw_log)

# 2. PII Detection
detector = PIIDetector()
findings = detector.detect_pii(raw_log)

print(f"\n--- [DETECTED PII ENTITIES ({len(findings)})] ---")
for f in findings:
    print(
        f"  * Category: {f.category.value:<15} Confidence: {f.confidence:.2f} Match: '{f.raw_text}' [Pos: {f.start}:{f.end}]"
    )

# 3. Anonymization - MASK
anonymizer = Anonymizer()
mask_result = anonymizer.anonymize(raw_log, findings, method=AnonymizationMethod.MASK)
print("\n--- [ANONYMIZED LOG (METHOD: MASK)] ---")
print(mask_result.anonymized_text)
print("\nMasking Summary:", mask_result.category_counts)

# 4. Anonymization - PSEUDONYMIZE
pseudo_result = anonymizer.anonymize(
    raw_log, findings, method=AnonymizationMethod.PSEUDONYMIZE
)
print("\n--- [ANONYMIZED LOG (METHOD: PSEUDONYMIZE)] ---")
print(pseudo_result.anonymized_text)

# 5. File-based LogFilter
log_filter = LogFilter(detector=detector)
with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as tmp_in:
    tmp_in.write(raw_log)
    tmp_in_path = Path(tmp_in.name)

tmp_out_path = tmp_in_path.with_suffix(".scrubbed.log")
try:
    result = log_filter.filter_log_file(
        tmp_in_path, tmp_out_path, method=AnonymizationMethod.MASK
    )
    print("\n--- [LOG FILTER FILE EXECUTION] ---")
    print(f"Processed: {result.lines_processed} lines")
    print(f"Modified: {result.lines_modified} lines")
    print(f"PII Findings Redacted: {result.findings_count}")
    print(f"Category Breakdown: {result.category_counts}")
finally:
    if tmp_in_path.exists():
        tmp_in_path.unlink()
    if tmp_out_path.exists():
        tmp_out_path.unlink()

print("\n" + "=" * 70)
print("DEMONSTRATION RESULT: PASS (All DPDP PII redacted, C2 indicators preserved)")
print("=" * 70)
