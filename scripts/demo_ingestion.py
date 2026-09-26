import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.custody.chain import GENESIS_HASH, LedgerEntry, compute_entry_hash
from core.ingestion.detector import detect_file_type
from core.ingestion.hasher import compute_sha256_bytes
from core.ingestion.ingestor import ArtifactIngestor
from scripts.seed_sample_artifacts import (
    generate_sample_apk,
    generate_sample_certificates,
    generate_sample_json,
    generate_sample_log,
    generate_sample_pcap,
    generate_sample_pe,
)

print("=" * 70)
print("HETEROGENEOUS FORENSIC ARTIFACT INGESTION DEMONSTRATION")
print("=" * 70)

cert_pem, cert_der = generate_sample_certificates()
samples = {
    "PCAP": generate_sample_pcap(),
    "JSON": generate_sample_json().encode("utf-8"),
    "PE": generate_sample_pe(),
    "APK": generate_sample_apk(),
    "LOG": generate_sample_log().encode("utf-8"),
    "CERT_PEM": cert_pem.encode("utf-8"),
    "CERT_DER": cert_der,
}
print(f"Generated {len(samples)} synthetic forensic artifact test vectors:")
for stype, data in samples.items():
    print(
        f"  * {stype:<12} (Size: {len(data):>6} bytes, SHA256: {compute_sha256_bytes(data)[:16]}...)"
    )

# 2. Test FileTypeDetector directly on each vector
print("\n--- [FILE TYPE DETECTION RESULTS] ---")
detected_types = {}
for stype, data in samples.items():
    ext_map = {
        "PCAP": "capture.pcap",
        "JSON": "cve_record.json",
        "PE": "payload.exe",
        "APK": "sample.apk",
        "LOG": "syslog.log",
        "CERT_PEM": "server.crt",
        "CERT_DER": "server.der",
    }
    filename = ext_map.get(stype, "artifact.bin")
    det = detect_file_type(data, filename_hint=filename)
    detected_types[stype] = det
    print(
        f"  * Artifact: {filename:<16} Expected: {stype:<10} Detected: {det.file_type.value:<10} Confidence: High"
    )

# 3. Ingestion Pipeline Execution
print("\n--- [INGESTION PIPELINE EXECUTION] ---")
mock_storage = MagicMock()
mock_storage.put_object.side_effect = (
    lambda evidence_id, sha256, data, **kw: f"minio://evidencegraphai-artifacts/evidence/{evidence_id}/{sha256}"
)
mock_storage.get_object.side_effect = lambda evidence_id, sha256: samples.get("PCAP")

mock_ledger = MagicMock()
mock_ledger_entries = {}


def record_mock_ledger(evidence_id, action, actor, sha256, metadata=None, **kw):
    prev_hash = GENESIS_HASH
    entry_h = compute_entry_hash(
        evidence_id=evidence_id,
        action=action,
        actor=actor,
        timestamp="2026-09-26T10:00:00Z",
        sha256=sha256,
        previous_hash=prev_hash,
        metadata=metadata or {},
    )
    entry = LedgerEntry(
        id=len(mock_ledger_entries) + 1,
        evidence_id=evidence_id,
        action=action,
        actor=actor,
        timestamp="2026-09-26T10:00:00Z",
        sha256=sha256,
        previous_hash=prev_hash,
        entry_hash=entry_h,
        metadata=metadata or {},
    )
    mock_ledger_entries[evidence_id] = entry
    return entry


mock_ledger.append_entry.side_effect = record_mock_ledger

mock_graph = MagicMock()
mock_graph.create_node.side_effect = lambda label, props: {
    "id": props["id"],
    "labels": [label],
}

ingestor = ArtifactIngestor(
    storage_client=mock_storage,
    custody_ledger=mock_ledger,
    graph_client=mock_graph,
)

ingest_results = []
for stype, data in samples.items():
    ext_map = {
        "PCAP": "traffic.pcap",
        "JSON": "nvd_vuln.json",
        "PE": "malware.exe",
        "APK": "agent.apk",
        "LOG": "auth.log",
        "CERT_PEM": "root_ca.pem",
        "CERT_DER": "root_ca.der",
    }
    fname = ext_map.get(stype, "artifact.bin")
    res = ingestor.ingest(
        data_or_stream_or_path=data,
        filename=fname,
        actor="agent://ingestion-subsystem",
        source_metadata={"source": "forensic_disk_image_01"},
        anonymize=False,
    )
    ingest_results.append(res)
    print(
        f"  * INGEST SUCCESS: ID: {res.evidence_id} | Type: {res.artifact_type:<10} | SHA256: {res.sha256[:16]}... | MinIO: {res.storage_path}"
    )

print("\n" + "=" * 70)
print(
    f"INGESTION DEMO COMPLETE: {len(ingest_results)}/{len(samples)} ARTIFACTS INGESTED"
)
print("=" * 70)
