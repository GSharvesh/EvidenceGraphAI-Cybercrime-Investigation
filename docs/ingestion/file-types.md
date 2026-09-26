# Forensic File Type Detection & Validation

## 1. Supported Artifact Formats

EvidenceGraphAI Phase 2 supports the following primary forensic artifact formats:

| Detected Type | Typical Extension | Primary MIME Type | Magic Byte Signature / Validation Pattern |
| :--- | :--- | :--- | :--- |
| `PCAP` | `.pcap`, `.pcapng` | `application/vnd.tcpdump.pcap` | `\xd4\xc3\xb2\xa1` (libpcap LE), `\xa1\xb2\xc3\xd4` (BE), `\x0a\x0d\x0d\x0a` (pcap-ng) |
| `JSON` | `.json` | `application/json` | Text starting with `{` or `[`, verified with strict JSON parser |
| `PE` | `.exe`, `.dll`, `.sys` | `application/x-dosexec` | Offset `0x00`: `MZ`, offset `0x3C`: pointer to `PE\x00\x00` header |
| `ELF` | `.elf`, `.so` | `application/x-executable` | Offset `0x00`: `\x7fELF` (32-bit/64-bit Linux binary) |
| `APK` | `.apk` | `application/vnd.android.package-archive` | ZIP header `PK\x03\x04` containing `AndroidManifest.xml` |
| `PLAIN_TEXT` | `.log`, `.txt` | `text/plain` | UTF-8/ASCII text without binary null bytes or unprintable control codes |
| `PDF` | `.pdf` | `application/pdf` | Offset `0x00`: `%PDF-` |
| `CERT_PEM` | `.pem`, `.crt` | `application/x-pem-file` | Text containing `-----BEGIN CERTIFICATE-----` or `-----BEGIN X509` |
| `CERT_DER` | `.der`, `.cer` | `application/x-x509-ca-cert` | ASN.1 DER Sequence starting with `\x30\x82` or `\x30\x83` |

---

## 2. Detection Algorithm

Detection is executed in [`core.ingestion.detector`](file:///d:/EvidenceGraphAI/core/ingestion/detector.py) through a multi-tiered inspection pipeline:

1. **Magic Signature Inspection:** Evaluates the initial 4KB buffer for exact binary magic headers.
2. **Container Inspection:** For ZIP files, inspects internal directory entries to disambiguate Android APKs from generic archives.
3. **Structured Content Validation:** Attempts JSON syntax parsing on text payloads to categorize threat intelligence / vulnerability feeds.
4. **Text Cleanliness Check:** Validates that plain text logs contain valid UTF-8 and no binary null bytes or unprintable control sequences.
5. **Magic Library Fallback:** Invokes `python-magic` MIME detection for boundary cases.
6. **Rejection:** Unrecognized binaries return `DetectedType.UNKNOWN` with 0.0 confidence, which is rejected by default by the ingestion validator.
