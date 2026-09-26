"""Frontend Ingestion Portal verification script."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

response = client.get("/dev/ingestion-portal")

print("=" * 70)
print("FORENSIC INGEST CONSOLE (/dev/ingestion-portal) VERIFICATION")
print("=" * 70)
print(f"HTTP Status Code: {response.status_code}")
print(f"Content-Type: {response.headers.get('content-type')}")
print(f"Payload Size: {len(response.content)} bytes")

# Check key UI features
content = response.text
checks = [
    ("Security Banner", "Developer Tool \u2014 Not for production use"),
    ("Drag-and-Drop Zone", "dropzone"),
    ("Live SHA256 Streamer", "live-sha256-display"),
    ("Chain Timeline", "timeline-container"),
    ("Section 65B Manifest Button", "Generate Section 65B Evidence Manifest"),
    ("DPDP Anonymization Switch", "DPDP Act 2023 Anonymization"),
    ("Cytoscape.js Mini Graph", "cytoscape"),
]

print("\n--- [COMPONENT VERIFICATION CHECKLIST] ---")
all_passed = True
for name, marker in checks:
    present = marker in content
    status = "PRESENT" if present else "MISSING"
    print(f"  * {name:<30}: [{status}]")
    if not present:
        all_passed = False

print("\n" + "=" * 70)
print(
    f"FRONTEND VERIFICATION RESULT: {'PASS (All UI components verified)' if all_passed else 'FAIL'}"
)
print("=" * 70)
