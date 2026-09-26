#!/usr/bin/env python3
"""Generates safe, synthetic forensic sample artifacts for testing and developer workflows.

Generates:
- sample_capture.pcap (synthesized libpcap network packet capture)
- sample_cve_nvd.json (vulnerability intelligence record)
- sample_binary.exe (safe dummy PE header)
- sample_app.apk (safe dummy Android package)
- sample_forensic.log (forensic access log with synthetic DPDP PII)
- sample_cert.pem and sample_cert.der (self-signed X.509 certificates)
"""

import datetime
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from core.logging.logger import configure_logging, get_logger

configure_logging(log_level="INFO", is_json=False)
logger = get_logger("scripts.seed_sample_artifacts")


def generate_sample_pcap() -> bytes:
    """Generates valid libpcap binary stream with a dummy HTTP packet."""
    # Global header (24 bytes): magic, v_major=2, v_minor=4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # Ethernet (14) + IP (20) + TCP (20) + Payload
    payload = b"GET /login?user=victim_alice@example.com&aadhaar=234567890123 HTTP/1.1\r\nHost: c2.example.com\r\n\r\n"
    # Ethernet header: dst MAC (6), src MAC (6), type=0x0800 (IPv4)
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    # Dummy IPv4 header (20 bytes)
    ip_hdr = b"\x45\x00\x00\x54\x00\x01\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x32\xc6\x33\x64\x0a"
    # Dummy TCP header (20 bytes)
    tcp_hdr = b"\x1f\x90\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x18\x20\x00\x00\x00\x00\x00"

    packet = eth_hdr + ip_hdr + tcp_hdr + payload
    pkt_len = len(packet)

    # Packet header: ts_sec, ts_usec, incl_len, orig_len
    ts_sec = int(datetime.datetime.now(datetime.UTC).timestamp())
    pkt_hdr = struct.pack("<IIII", ts_sec, 0, pkt_len, pkt_len)

    return global_hdr + pkt_hdr + packet


def generate_sample_json() -> str:
    """Generates synthetic NVD CVE vulnerability JSON."""
    data = {
        "cve": {
            "id": "CVE-2024-99999",
            "sourceIdentifier": "cve@evidencegraphai.io",
            "published": "2024-01-15T10:00:00.000",
            "lastModified": "2024-01-15T12:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Synthetic Remote Code Execution vulnerability in sample target service for demonstration purposes.",
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                    }
                ]
            },
        }
    }
    return json.dumps(data, indent=2)


def generate_sample_pe() -> bytes:
    """Generates a dummy PE executable header structure (non-executable placeholder)."""
    # 0x00: MZ
    # 0x3C: pointer to PE signature (let's set offset to 0x80)
    dos_header = bytearray(128)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x40)  # PE offset at 64
    pe_sig = b"PE\x00\x00"
    coff_header = b"\x4c\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01"
    return bytes(dos_header[:0x40]) + pe_sig + coff_header + (b"\x00" * 128)


def generate_sample_apk() -> bytes:
    """Generates synthetic APK archive containing dummy AndroidManifest.xml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        manifest_xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="com.example.synthetic.forensic.app">\n'
            '    <application android:label="ForensicSampleApp">\n'
            "    </application>\n"
            "</manifest>"
        )
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", b"DEX\n035\x00DummyDexBytes")
    return buf.getvalue()


def generate_sample_log() -> str:
    """Generates synthetic server access log with DPDP Act PII fields."""
    return (
        "2024-02-10T09:12:01.442Z [INFO] User session started for user=vikram.sharma@domain.in from ip=192.168.1.105\n"
        "2024-02-10T09:12:15.110Z [AUTH] Verification completed for Aadhaar=3456 7890 1234, PAN=ABCDE1234F\n"
        "2024-02-10T09:12:44.892Z [ALERT] Outbound transfer initiated with phone=+91 9876543210 to destination C2 198.51.100.25:443\n"
        "2024-02-10T09:13:02.100Z [INFO] Card authorization checked: 4111111111111111 status=APPROVED\n"
    )


def generate_sample_certificates() -> tuple[str, bytes]:
    """Generates self-signed X.509 certificate in PEM (string) and DER (bytes) format."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "EvidenceGraphAI Forensic Lab"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, "forensic-evidence.test"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        )
        .sign(key, hashes.SHA256())
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    der_cert = cert.public_bytes(serialization.Encoding.DER)
    return pem_cert, der_cert


def seed_artifacts(
    output_dir: Path | str = "scratch/sample_artifacts",
) -> dict[str, str]:
    """Writes all sample artifacts to the specified output directory."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    logger.info("Generating sample artifacts in directory", path=str(out_path))

    artifacts: dict[str, str] = {}

    # 1. PCAP
    pcap_file = out_path / "sample_capture.pcap"
    pcap_file.write_bytes(generate_sample_pcap())
    artifacts["PCAP"] = str(pcap_file)

    # 2. JSON
    json_file = out_path / "sample_cve_nvd.json"
    json_file.write_text(generate_sample_json(), encoding="utf-8")
    artifacts["JSON"] = str(json_file)

    # 3. PE
    pe_file = out_path / "sample_binary.exe"
    pe_file.write_bytes(generate_sample_pe())
    artifacts["PE"] = str(pe_file)

    # 4. APK
    apk_file = out_path / "sample_app.apk"
    apk_file.write_bytes(generate_sample_apk())
    artifacts["APK"] = str(apk_file)

    # 5. Log with PII
    log_file = out_path / "sample_forensic.log"
    log_file.write_text(generate_sample_log(), encoding="utf-8")
    artifacts["LOG"] = str(log_file)

    # 6. Certificates
    pem_str, der_bytes = generate_sample_certificates()
    pem_file = out_path / "sample_cert.pem"
    pem_file.write_text(pem_str, encoding="utf-8")
    artifacts["CERT_PEM"] = str(pem_file)

    der_file = out_path / "sample_cert.der"
    der_file.write_bytes(der_bytes)
    artifacts["CERT_DER"] = str(der_file)

    logger.info("Successfully seeded all sample artifacts", count=len(artifacts))
    return artifacts


if __name__ == "__main__":
    seed_artifacts()
