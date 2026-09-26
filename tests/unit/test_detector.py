"""Unit tests for forensic file type detection engine."""

import io
from pathlib import Path
from unittest.mock import patch

import pytest

from core.ingestion.detector import DetectedType, detect_file_type
from core.ingestion.exceptions import UnsupportedFileTypeError
from scripts.seed_sample_artifacts import (
    generate_sample_apk,
    generate_sample_certificates,
    generate_sample_json,
    generate_sample_log,
    generate_sample_pcap,
    generate_sample_pe,
)


def test_detect_pcap() -> None:
    """Verifies libpcap binary detection."""
    pcap_bytes = generate_sample_pcap()
    result = detect_file_type(pcap_bytes, filename_hint="capture.pcap")
    assert result.file_type == DetectedType.PCAP
    assert result.mime_type in ("application/vnd.tcpdump.pcap", "application/x-pcapng")
    assert result.confidence == 1.0


def test_detect_json() -> None:
    """Verifies JSON record detection."""
    json_str = generate_sample_json()
    result = detect_file_type(json_str.encode("utf-8"), filename_hint="cve.json")
    assert result.file_type == DetectedType.JSON
    assert result.mime_type == "application/json"
    assert result.confidence >= 0.9


def test_detect_json_array() -> None:
    """Verifies JSON array detection."""
    json_arr = b'[{"id": "CVE-1"}, {"id": "CVE-2"}]'
    result = detect_file_type(json_arr, filename_hint="list.json")
    assert result.file_type == DetectedType.JSON
    assert result.details.get("json_root") == "array"


def test_detect_pe() -> None:
    """Verifies PE executable detection."""
    pe_bytes = generate_sample_pe()
    result = detect_file_type(pe_bytes, filename_hint="sample.exe")
    assert result.file_type == DetectedType.PE
    assert result.confidence >= 0.85


def test_detect_elf() -> None:
    """Verifies ELF binary detection."""
    elf_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
    result = detect_file_type(elf_bytes, filename_hint="malware.elf")
    assert result.file_type == DetectedType.ELF
    assert result.confidence == 1.0


def test_detect_apk() -> None:
    """Verifies APK archive detection."""
    apk_bytes = generate_sample_apk()
    result = detect_file_type(apk_bytes, filename_hint="app.apk")
    assert result.file_type == DetectedType.APK
    assert result.confidence >= 0.95


def test_detect_pdf() -> None:
    """Verifies PDF document detection."""
    pdf_bytes = b"%PDF-1.7\n%Fake PDF content for test\n%%EOF"
    result = detect_file_type(pdf_bytes, filename_hint="report.pdf")
    assert result.file_type == DetectedType.PDF
    assert result.confidence == 1.0


def test_detect_certificates() -> None:
    """Verifies X.509 certificate detection in PEM and DER formats."""
    pem_str, der_bytes = generate_sample_certificates()

    # PEM
    res_pem = detect_file_type(pem_str.encode("utf-8"), filename_hint="cert.pem")
    assert res_pem.file_type == DetectedType.CERT_PEM
    assert res_pem.confidence == 1.0

    # DER
    res_der = detect_file_type(der_bytes, filename_hint="cert.der")
    assert res_der.file_type == DetectedType.CERT_DER
    assert res_der.confidence >= 0.9


def test_detect_plain_text_log() -> None:
    """Verifies plain text and log detection."""
    log_text = generate_sample_log()
    result = detect_file_type(log_text.encode("utf-8"), filename_hint="access.log")
    assert result.file_type == DetectedType.PLAIN_TEXT
    assert result.confidence >= 0.85


def test_detect_file_path_input(tmp_path: Path) -> None:
    """Verifies detection when given a file path."""
    tmp_file = tmp_path / "test.json"
    tmp_file.write_text('{"status": "ok"}', encoding="utf-8")
    result = detect_file_type(tmp_file)
    assert result.file_type == DetectedType.JSON


def test_detect_stream_input() -> None:
    """Verifies detection from seekable binary stream."""
    stream = io.BytesIO(b"%PDF-1.4\n...")
    result = detect_file_type(stream, filename_hint="test.pdf")
    assert result.file_type == DetectedType.PDF
    # Stream position should be restored
    assert stream.tell() == 0


def test_detect_empty_raises() -> None:
    """Verifies empty content raises UnsupportedFileTypeError."""
    with pytest.raises(UnsupportedFileTypeError):
        detect_file_type(b"")


def test_detect_unknown_binary() -> None:
    """Verifies unclassifiable binary falls back to UNKNOWN with 0 confidence."""
    rand_bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 10
    result = detect_file_type(rand_bytes, filename_hint="unknown.bin")
    assert result.file_type == DetectedType.UNKNOWN
    assert result.confidence == 0.0


def test_detect_magic_fallbacks() -> None:
    """Verifies magic library fallback branches for PDF, PCAP, Text, JSON."""
    blob = b"\x00\x01\x02\x03" * 8

    with (
        patch("core.ingestion.detector.HAS_MAGIC", True),
        patch("magic.from_buffer", return_value="application/pdf"),
    ):
        res = detect_file_type(blob)
        assert res.file_type == DetectedType.PDF

    with (
        patch("core.ingestion.detector.HAS_MAGIC", True),
        patch("magic.from_buffer", return_value="application/vnd.tcpdump.pcap"),
    ):
        res = detect_file_type(blob)
        assert res.file_type == DetectedType.PCAP

    with (
        patch("core.ingestion.detector.HAS_MAGIC", True),
        patch("magic.from_buffer", return_value="text/plain"),
    ):
        res = detect_file_type(blob)
        assert res.file_type == DetectedType.PLAIN_TEXT

    with (
        patch("core.ingestion.detector.HAS_MAGIC", True),
        patch("magic.from_buffer", return_value="application/json"),
    ):
        res = detect_file_type(blob)
        assert res.file_type == DetectedType.JSON


def test_detect_pcapng_magic_bytes() -> None:
    """Verifies PCAP-NG magic byte signature."""
    pcapng_bytes = b"\x0a\x0d\x0d\x0a" + b"\x00" * 32
    res = detect_file_type(pcapng_bytes)
    assert res.file_type == DetectedType.PCAP
    assert res.details.get("format") == "pcapng"


def test_detect_elf_32bit() -> None:
    """Verifies 32-bit ELF binary detection."""
    elf32_bytes = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 32
    res = detect_file_type(elf32_bytes)
    assert res.file_type == DetectedType.ELF
    assert res.details.get("architecture") == "32-bit"


def test_detect_corrupt_zip_fallback() -> None:
    """Verifies corrupted zip header falls back gracefully."""
    corrupt_zip = b"PK\x03\x04" + b"\xff" * 20
    res = detect_file_type(corrupt_zip)
    assert res.file_type in (DetectedType.PE, DetectedType.UNKNOWN)
