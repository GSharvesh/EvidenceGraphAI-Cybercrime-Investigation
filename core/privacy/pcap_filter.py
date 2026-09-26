"""Forensic network capture (PCAP) anonymization filter for DPDP compliance."""

import hashlib
import io
import struct
from pathlib import Path

from pydantic import BaseModel, Field

from core.logging.logger import get_logger
from core.privacy.anonymizer import AnonymizationMethod, Anonymizer
from core.privacy.pii_detector import PIIDetector

logger = get_logger("core.privacy.pcap_filter")


class FilteredPCAPResult(BaseModel):
    """Result of PCAP network capture anonymization processing."""

    anonymized_bytes: bytes
    original_sha256: str
    filtered_sha256: str
    packets_processed: int
    packets_modified: int
    findings_count: int
    category_counts: dict[str, int] = Field(default_factory=dict)
    method_used: AnonymizationMethod


class PCAPFilter:
    """Processes libpcap network captures to mask PII payloads while preserving framing and forensic headers."""

    def __init__(
        self,
        detector: PIIDetector | None = None,
        anonymizer: Anonymizer | None = None,
    ) -> None:
        self.detector = detector or PIIDetector()
        self.anonymizer = anonymizer or Anonymizer()

    def filter_pcap_bytes(
        self,
        raw_pcap: bytes,
        method: AnonymizationMethod = AnonymizationMethod.MASK,
    ) -> FilteredPCAPResult:
        """Parses libpcap byte buffer, anonymizes payload text, and reconstructs valid PCAP.

        Args:
            raw_pcap: Input PCAP byte stream.
            method: Anonymization method to apply.

        Returns:
            FilteredPCAPResult with filtered PCAP bytes and audit statistics.
        """
        original_sha = hashlib.sha256(raw_pcap).hexdigest()
        if len(raw_pcap) < 24:
            # Not a full PCAP, return unchanged
            return FilteredPCAPResult(
                anonymized_bytes=raw_pcap,
                original_sha256=original_sha,
                filtered_sha256=original_sha,
                packets_processed=0,
                packets_modified=0,
                findings_count=0,
                category_counts={},
                method_used=method,
            )

        magic = raw_pcap[:4]
        is_pcap = magic in (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        )
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"

        if not is_pcap:
            # Fallback for PCAPNG or raw streams: string pattern replacement
            try:
                text = raw_pcap.decode("latin1")
                findings = self.detector.detect_pii(text, artifact_type="PCAP")
                if findings:
                    res = self.anonymizer.anonymize(text, findings, method=method)
                    out_bytes = res.anonymized_text.encode("latin1")
                    return FilteredPCAPResult(
                        anonymized_bytes=out_bytes,
                        original_sha256=original_sha,
                        filtered_sha256=hashlib.sha256(out_bytes).hexdigest(),
                        packets_processed=1,
                        packets_modified=1,
                        findings_count=res.findings_count,
                        category_counts=res.category_counts,
                        method_used=method,
                    )
            except Exception as exc:
                logger.warning("PCAP byte scanning fallback failed", error=str(exc))

            return FilteredPCAPResult(
                anonymized_bytes=raw_pcap,
                original_sha256=original_sha,
                filtered_sha256=original_sha,
                packets_processed=0,
                packets_modified=0,
                findings_count=0,
                category_counts={},
                method_used=method,
            )

        # Standard libpcap global header
        global_header = raw_pcap[:24]
        out_stream = io.BytesIO()
        out_stream.write(global_header)

        offset = 24
        packets_processed = 0
        packets_modified = 0
        total_findings = 0
        aggregate_counts: dict[str, int] = {}

        while offset + 16 <= len(raw_pcap):
            pkt_hdr = raw_pcap[offset : offset + 16]
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f"{endian}IIII", pkt_hdr
            )
            offset += 16

            if offset + incl_len > len(raw_pcap):
                # Truncated trailing packet
                break

            packet_data = raw_pcap[offset : offset + incl_len]
            offset += incl_len
            packets_processed += 1

            # Extract ASCII strings within packet payload for PII inspection
            try:
                pkt_text = packet_data.decode("latin1")
                findings = self.detector.detect_pii(pkt_text, artifact_type="PCAP")
                if findings:
                    anon_res = self.anonymizer.anonymize(
                        pkt_text, findings, method=method
                    )
                    new_pkt_data = anon_res.anonymized_text.encode("latin1")
                    new_incl_len = len(new_pkt_data)
                    new_orig_len = max(
                        orig_len + (new_incl_len - incl_len), new_incl_len
                    )

                    # Write updated header
                    new_hdr = struct.pack(
                        f"{endian}IIII", ts_sec, ts_usec, new_incl_len, new_orig_len
                    )
                    out_stream.write(new_hdr)
                    out_stream.write(new_pkt_data)

                    packets_modified += 1
                    total_findings += anon_res.findings_count
                    for cat, cnt in anon_res.category_counts.items():
                        aggregate_counts[cat] = aggregate_counts.get(cat, 0) + cnt
                else:
                    out_stream.write(pkt_hdr)
                    out_stream.write(packet_data)
            except Exception:
                out_stream.write(pkt_hdr)
                out_stream.write(packet_data)

        anonymized_pcap_bytes = out_stream.getvalue()
        return FilteredPCAPResult(
            anonymized_bytes=anonymized_pcap_bytes,
            original_sha256=original_sha,
            filtered_sha256=hashlib.sha256(anonymized_pcap_bytes).hexdigest(),
            packets_processed=packets_processed,
            packets_modified=packets_modified,
            findings_count=total_findings,
            category_counts=aggregate_counts,
            method_used=method,
        )

    def filter_pcap_file(
        self,
        file_path: Path | str,
        output_path: Path | str | None = None,
        method: AnonymizationMethod = AnonymizationMethod.MASK,
    ) -> FilteredPCAPResult:
        """Reads PCAP file, anonymizes PII, and optionally writes result to disk."""
        path = Path(file_path)
        raw_bytes = path.read_bytes()
        res = self.filter_pcap_bytes(raw_bytes, method=method)

        if output_path:
            out = Path(output_path)
            out.write_bytes(res.anonymized_bytes)

        return res
