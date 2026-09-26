"""Unit tests for PCAP and Log forensic privacy filters."""

from pathlib import Path

from core.privacy.anonymizer import AnonymizationMethod
from core.privacy.log_filter import LogFilter
from core.privacy.pcap_filter import PCAPFilter
from scripts.seed_sample_artifacts import generate_sample_log, generate_sample_pcap


def test_filter_log_text() -> None:
    """Verifies log file filtering masks all synthetic PII across multiple lines."""
    log_text = generate_sample_log()
    log_filter = LogFilter()

    result = log_filter.filter_log_text(log_text, method=AnonymizationMethod.MASK)
    assert result.lines_processed == 4
    assert result.lines_modified >= 3
    assert result.findings_count >= 4
    assert "vikram.sharma@domain.in" not in result.anonymized_content
    assert "3456 7890 1234" not in result.anonymized_content
    assert "ABCDE1234F" not in result.anonymized_content


def test_filter_log_file(tmp_path: Path) -> None:
    """Verifies filtering log content from a file."""
    log_file = tmp_path / "raw.log"
    out_file = tmp_path / "clean.log"
    log_file.write_text(generate_sample_log(), encoding="utf-8")

    log_filter = LogFilter()
    result = log_filter.filter_log_file(
        log_file, out_file, method=AnonymizationMethod.MASK
    )

    assert result.lines_processed == 4
    assert out_file.exists()
    assert "vikram.sharma@domain.in" not in out_file.read_text(encoding="utf-8")


def test_filter_pcap_bytes() -> None:
    """Verifies PCAP filter processes packet payloads and alters SHA256 while preserving headers."""
    raw_pcap = generate_sample_pcap()
    pcap_filter = PCAPFilter()

    result = pcap_filter.filter_pcap_bytes(raw_pcap, method=AnonymizationMethod.MASK)
    assert result.packets_processed >= 1
    assert result.findings_count >= 1
    assert result.original_sha256 != result.filtered_sha256
    assert b"victim_alice@example.com" not in result.anonymized_bytes
    # Global PCAP magic is preserved
    assert result.anonymized_bytes[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")


def test_filter_pcap_short_buffer() -> None:
    """Verifies short buffer (<24 bytes) returns unchanged."""
    short = b"\x00" * 10
    pcap_filter = PCAPFilter()
    result = pcap_filter.filter_pcap_bytes(short)
    assert result.anonymized_bytes == short
    assert result.packets_processed == 0


def test_filter_pcap_raw_stream_fallback() -> None:
    """Verifies non-standard capture stream falls back to string replacement."""
    raw_stream = b"Random binary prefix -- user=alice@example.com -- suffix"
    pcap_filter = PCAPFilter()
    result = pcap_filter.filter_pcap_bytes(raw_stream, method=AnonymizationMethod.MASK)
    assert result.findings_count >= 1
    assert b"alice@example.com" not in result.anonymized_bytes


def test_filter_pcap_file(tmp_path: Path) -> None:
    """Verifies filtering PCAP file from disk."""
    pcap_file = tmp_path / "raw.pcap"
    out_file = tmp_path / "clean.pcap"
    pcap_file.write_bytes(generate_sample_pcap())

    pcap_filter = PCAPFilter()
    result = pcap_filter.filter_pcap_file(pcap_file, out_file)
    assert out_file.exists()
    assert result.packets_processed >= 1
