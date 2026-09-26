"""Forensic file type detection engine using magic bytes, signatures, and format validation."""

import io
import json
import struct
import zipfile
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO

from pydantic import BaseModel, Field

from core.ingestion.exceptions import UnsupportedFileTypeError
from core.logging.logger import get_logger

logger = get_logger("core.ingestion.detector")

# Optional python-magic import
try:
    import magic

    HAS_MAGIC = True
except Exception:
    HAS_MAGIC = False


class DetectedType(str, Enum):
    """Enumeration of supported forensic artifact types."""

    PCAP = "PCAP"
    JSON = "JSON"
    PE = "PE"
    ELF = "ELF"
    APK = "APK"
    PLAIN_TEXT = "PLAIN_TEXT"
    PDF = "PDF"
    CERT_PEM = "CERT_PEM"
    CERT_DER = "CERT_DER"
    UNKNOWN = "UNKNOWN"


class FileTypeDetectionResult(BaseModel):
    """Structured result of file type detection."""

    file_type: DetectedType
    mime_type: str
    extension: str
    confidence: float = Field(ge=0.0, le=1.0)
    details: dict[str, Any] = Field(default_factory=dict)


def _detect_magic_bytes(
    header: bytes, filename_hint: str | None = None
) -> FileTypeDetectionResult | None:
    """Inspects raw leading bytes for unambiguous binary and text signatures."""
    if len(header) == 0:
        return None

    # 1. PCAP / PCAPNG
    # Standard libpcap: 0xd4c3b2a1 (microsecond) or 0xa1b2c3d4 (swapped), 0x4d3cb2a1 (nanosecond) or 0xa1b23c4d
    if header.startswith(
        (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        )
    ):
        return FileTypeDetectionResult(
            file_type=DetectedType.PCAP,
            mime_type="application/vnd.tcpdump.pcap",
            extension=".pcap",
            confidence=1.0,
            details={
                "format": "libpcap",
                "endianness": (
                    "little" if header.startswith((b"\xd4", b"\x4d")) else "big"
                ),
            },
        )
    # PCAP-NG: 0x0a0d0d0a (\n\r\r\n)
    if header.startswith(b"\x0a\x0d\x0d\x0a"):
        return FileTypeDetectionResult(
            file_type=DetectedType.PCAP,
            mime_type="application/x-pcapng",
            extension=".pcapng",
            confidence=1.0,
            details={"format": "pcapng"},
        )

    # 2. ELF (Executable and Linkable Format)
    if header.startswith(b"\x7fELF"):
        bit_arch = "64-bit" if len(header) > 4 and header[4] == 2 else "32-bit"
        return FileTypeDetectionResult(
            file_type=DetectedType.ELF,
            mime_type="application/x-executable",
            extension=".elf",
            confidence=1.0,
            details={"architecture": bit_arch},
        )

    # 3. PE (Portable Executable - Windows EXE/DLL)
    if header.startswith(b"MZ"):
        # Check PE header pointer at offset 0x3C
        is_pe = False
        if len(header) >= 0x40:
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            if (
                len(header) >= pe_offset + 4
                and header[pe_offset : pe_offset + 4] == b"PE\x00\x00"
            ):
                is_pe = True
        return FileTypeDetectionResult(
            file_type=DetectedType.PE,
            mime_type="application/x-dosexec",
            extension=".exe",
            confidence=1.0 if is_pe else 0.85,
            details={"mz_header": True, "pe_signature": is_pe},
        )

    # 4. PDF (Portable Document Format)
    if header.startswith(b"%PDF-"):
        version = header[5:8].decode("ascii", errors="ignore")
        return FileTypeDetectionResult(
            file_type=DetectedType.PDF,
            mime_type="application/pdf",
            extension=".pdf",
            confidence=1.0,
            details={"pdf_version": version},
        )

    # 5. PEM Certificate
    pem_signatures = [
        b"-----BEGIN CERTIFICATE-----",
        b"-----BEGIN X509 CERTIFICATE-----",
        b"-----BEGIN TRUSTED CERTIFICATE-----",
    ]
    if any(sig in header for sig in pem_signatures):
        return FileTypeDetectionResult(
            file_type=DetectedType.CERT_PEM,
            mime_type="application/x-pem-file",
            extension=".pem",
            confidence=1.0,
            details={"pem_type": "X509_CERTIFICATE"},
        )

    # 6. DER Certificate (ASN.1 Sequence 0x30 0x82...)
    if header.startswith(b"\x30\x82") or header.startswith(b"\x30\x83"):
        hint = (filename_hint or "").lower()
        if hint.endswith((".der", ".crt", ".cer")):
            return FileTypeDetectionResult(
                file_type=DetectedType.CERT_DER,
                mime_type="application/x-x509-ca-cert",
                extension=".der",
                confidence=0.95,
                details={"asn1_tag": "SEQUENCE"},
            )

    # 7. APK / ZIP container (PK\x03\x04)
    if header.startswith(b"PK\x03\x04"):
        hint = (filename_hint or "").lower()
        if hint.endswith(".apk"):
            return FileTypeDetectionResult(
                file_type=DetectedType.APK,
                mime_type="application/vnd.android.package-archive",
                extension=".apk",
                confidence=0.95,
                details={"zip_container": True},
            )

    return None


def detect_file_type(
    data_or_stream_or_path: bytes | BinaryIO | Path | str,
    filename_hint: str | None = None,
) -> FileTypeDetectionResult:
    """Detects forensic file type from content and optional filename.

    Args:
        data_or_stream_or_path: Bytes content, open binary stream, or file path.
        filename_hint: Optional filename to assist disambiguation.

    Returns:
        FileTypeDetectionResult with detected type, MIME type, and confidence.

    Raises:
        UnsupportedFileTypeError: If file is completely unrecognized or empty.
    """
    raw_bytes: bytes
    if isinstance(data_or_stream_or_path, str | Path):
        path = Path(data_or_stream_or_path)
        filename_hint = filename_hint or path.name
        with open(path, "rb") as f:
            raw_bytes = f.read(4096)
    elif isinstance(data_or_stream_or_path, bytes):
        raw_bytes = data_or_stream_or_path
    else:
        # Stream
        pos = data_or_stream_or_path.tell()
        raw_bytes = data_or_stream_or_path.read(4096)
        data_or_stream_or_path.seek(pos)

    if not raw_bytes:
        raise UnsupportedFileTypeError("Cannot detect type of empty content")

    # Step 1: Magic byte signatures
    result = _detect_magic_bytes(raw_bytes, filename_hint=filename_hint)
    if result:
        # Extra verification for APK if full buffer is available
        if result.file_type == DetectedType.APK or (
            raw_bytes.startswith(b"PK\x03\x04")
            and (filename_hint or "").endswith(".apk")
        ):
            try:
                # Check if it contains AndroidManifest.xml
                zf_stream = io.BytesIO(
                    raw_bytes
                    if isinstance(data_or_stream_or_path, bytes)
                    else (
                        Path(data_or_stream_or_path).read_bytes()
                        if isinstance(data_or_stream_or_path, str | Path)
                        else raw_bytes
                    )
                )
                with zipfile.ZipFile(zf_stream, "r") as zf:
                    if "AndroidManifest.xml" in zf.namelist():
                        return FileTypeDetectionResult(
                            file_type=DetectedType.APK,
                            mime_type="application/vnd.android.package-archive",
                            extension=".apk",
                            confidence=1.0,
                            details={"has_manifest": True},
                        )
            except Exception:
                pass
        return result

    # Step 2: JSON detection
    try:
        text = raw_bytes.decode("utf-8").strip()
        if (text.startswith("{") and text.endswith("}")) or (
            text.startswith("[") and text.endswith("]")
        ):
            json.loads(text)
            return FileTypeDetectionResult(
                file_type=DetectedType.JSON,
                mime_type="application/json",
                extension=".json",
                confidence=0.98,
                details={"json_root": "object" if text.startswith("{") else "array"},
            )
    except Exception:
        pass

    # Step 3: Plain text / Log detection
    try:
        decoded = raw_bytes.decode("utf-8")
        # Check for non-printable control characters
        non_printable = [
            c for c in decoded if ord(c) < 32 and c not in ("\t", "\n", "\r")
        ]
        if not non_printable and len(decoded.strip()) > 0:
            hint = (filename_hint or "").lower()
            return FileTypeDetectionResult(
                file_type=DetectedType.PLAIN_TEXT,
                mime_type="text/plain",
                extension=".log" if hint.endswith(".log") else ".txt",
                confidence=0.90,
                details={"encoding": "utf-8", "line_count": decoded.count("\n") + 1},
            )
    except Exception:
        pass

    # Step 4: Python-magic library fallback if available
    if HAS_MAGIC:
        try:
            mime = magic.from_buffer(raw_bytes, mime=True)
            if "json" in mime:
                return FileTypeDetectionResult(
                    file_type=DetectedType.JSON,
                    mime_type="application/json",
                    extension=".json",
                    confidence=0.85,
                )
            if "text" in mime:
                return FileTypeDetectionResult(
                    file_type=DetectedType.PLAIN_TEXT,
                    mime_type="text/plain",
                    extension=".txt",
                    confidence=0.85,
                )
            if "pdf" in mime:
                return FileTypeDetectionResult(
                    file_type=DetectedType.PDF,
                    mime_type="application/pdf",
                    extension=".pdf",
                    confidence=0.9,
                )
            if "pcap" in mime or "tcpdump" in mime:
                return FileTypeDetectionResult(
                    file_type=DetectedType.PCAP,
                    mime_type="application/vnd.tcpdump.pcap",
                    extension=".pcap",
                    confidence=0.9,
                )
        except Exception:
            pass

    return FileTypeDetectionResult(
        file_type=DetectedType.UNKNOWN,
        mime_type="application/octet-stream",
        extension=".bin",
        confidence=0.0,
        details={"unrecognized": True},
    )
