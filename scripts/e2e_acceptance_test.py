#!/usr/bin/env python3
"""Final Clean End-to-End Acceptance Test for Evidence Integrity Workflow.

Executes all 13 verification points against the running API and databases:
1. Fresh artifact ingestion succeeds.
2. The raw actor 'integration-test' is preserved in the custody ledger.
3. Neo4j receives a normalized source_agent: 'integration_test'.
4. No ERROR custody entry is created for the fresh ingestion.
5. Evidence SHA-256 verification returns MATCH.
6. Generate a fresh manifest containing that evidence.
7. Manifest is persisted and can be retrieved by manifest_id.
8. Verify the untouched manifest (is_valid = true, signature_algorithm = HMAC-SHA256).
9. Create a copy of the manifest and modify generator_identity only.
10. Verify the modified manifest (is_valid = false).
11. Confirm original manifest still verifies successfully.
12. Confirm ledger integrity remains valid.
13. Report exact evidence_id, manifest_id, ledger actions, and verification results.
"""

import copy
import json
import sys
import time
from typing import Any

import httpx

from core.db.postgres import PostgresClient
from core.graph.client import GraphClient

BASE_URL = "http://127.0.0.1:8000"


def run_acceptance_test() -> dict[str, Any]:
    print("=" * 80)
    print(" EVIDENCE INTEGRITY WORKFLOW - CLEAN END-TO-END ACCEPTANCE TEST")
    print("=" * 80)

    results = {}

    # 0. Health check
    print("\n[PRE-CHECK] Verifying service health...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.get("/health")
        assert (
            r.status_code == 200
        ), f"API health check failed: {r.status_code} {r.text}"
        health_data = r.json()
        print(f"  Health Status: {health_data['status']}")
        print(f"  Services: {health_data['services']}")
        assert health_data["status"] == "healthy"
        for svc, state in health_data["services"].items():
            assert state == "healthy", f"Service {svc} is {state}"

    raw_actor = "integration-test"
    expected_normalized_agent = "integration_test"
    test_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    artifact_filename = f"e2e_evidence_{int(time.time())}.log"
    artifact_content = f"""[FORENSIC LOG RECORD]
Timestamp: {test_timestamp}
Source Host: host-victim-01.internal
Event: Unauthorized SMB pipe connection detected from 192.168.1.105
Actor: {raw_actor}
Process: spoolsv.exe (PID: 1428)
Integrity Verification Artifact: E2E-ACCEPTANCE-TEST-{time.time()}
""".encode()

    # 1. Fresh artifact ingestion succeeds
    print("\n[STEP 1] Fresh artifact ingestion...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        files = {"file": (artifact_filename, artifact_content, "text/plain")}
        data = {"actor": raw_actor, "anonymize": "false"}
        r = client.post("/ingest", files=files, data=data)
        assert r.status_code == 201, f"Ingestion failed: {r.status_code} {r.text}"
        ingest_res = r.json()

    evidence_id = ingest_res["evidence_id"]
    evidence_sha256 = ingest_res["sha256"]
    node_id = ingest_res["node_id"]
    ledger_entry_id = ingest_res["ledger_entry_id"]

    print("  [PASS] Fresh artifact ingested successfully:")
    print(f"         Evidence ID: {evidence_id}")
    print(f"         SHA-256: {evidence_sha256}")
    print(f"         Node ID: {node_id}")
    print(f"         Ledger Entry ID: {ledger_entry_id}")
    results["step1"] = {
        "pass": True,
        "evidence_id": evidence_id,
        "sha256": evidence_sha256,
    }

    # 2. Raw actor "integration-test" is preserved in custody ledger
    print("\n[STEP 2] Verifying raw actor in custody ledger...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.get(f"/ledger?evidence_id={evidence_id}")
        assert r.status_code == 200, f"Ledger fetch failed: {r.status_code} {r.text}"
        ledger_data = r.json()

    entries = ledger_data.get("entries", [])
    ingest_entry = next((e for e in entries if e["action"] == "INGEST"), None)
    assert ingest_entry is not None, "INGEST ledger entry not found"
    assert (
        ingest_entry["actor"] == raw_actor
    ), f"Actor mismatch: expected '{raw_actor}', got '{ingest_entry['actor']}'"

    print("  [PASS] Raw actor preserved in custody ledger:")
    print(f"         Entry ID: {ingest_entry['id']}")
    print(f"         Action: {ingest_entry['action']}")
    print(f"         Actor: '{ingest_entry['actor']}' (exact match)")
    print(f"         Entry Hash: {ingest_entry['entry_hash']}")
    results["step2"] = {"pass": True, "actor": ingest_entry["actor"]}

    # 3. Neo4j receives normalized source_agent: "integration_test"
    print("\n[STEP 3] Verifying Neo4j normalized source_agent...")
    graph_client = GraphClient()
    cypher_query = "MATCH (n:EvidenceArtifact {id: $evidence_id}) RETURN n.id AS id, n.source_agent AS source_agent, n.hash_sha256 AS hash_sha256, n.artifact_type AS artifact_type"
    graph_records = graph_client.query(cypher_query, {"evidence_id": evidence_id})
    assert len(graph_records) == 1, f"Expected 1 Neo4j node, got {len(graph_records)}"
    neo4j_node = graph_records[0]
    assert (
        neo4j_node["source_agent"] == expected_normalized_agent
    ), f"Neo4j source_agent mismatch: expected '{expected_normalized_agent}', got '{neo4j_node['source_agent']}'"
    assert (
        neo4j_node["hash_sha256"] == evidence_sha256
    ), f"Neo4j hash mismatch: expected '{evidence_sha256}', got '{neo4j_node['hash_sha256']}'"

    print("  [PASS] Neo4j EvidenceArtifact node verified:")
    print(f"         Node ID: {neo4j_node['id']}")
    print(
        f"         source_agent: '{neo4j_node['source_agent']}' (normalized from '{raw_actor}')"
    )
    print(f"         hash_sha256: {neo4j_node['hash_sha256']}")
    results["step3"] = {"pass": True, "source_agent": neo4j_node["source_agent"]}

    # 4. No ERROR custody entry is created for the fresh ingestion
    print("\n[STEP 4] Checking for absence of ERROR custody entries...")
    error_entries = [e for e in entries if e["action"] == "ERROR"]
    assert (
        len(error_entries) == 0
    ), f"Found unexpected ERROR entries for fresh evidence: {error_entries}"

    # Also check directly in DB
    db = PostgresClient()
    db_errors = db.fetch_all(
        "SELECT * FROM custody_ledger WHERE evidence_id = %s AND action = 'ERROR'",
        (evidence_id,),
    )
    assert len(db_errors) == 0, f"Database has ERROR entries: {db_errors}"

    print(f"  [PASS] Zero ERROR custody entries exist for evidence '{evidence_id}'.")
    results["step4"] = {"pass": True, "error_count": 0}

    # 5. Evidence SHA-256 verification returns MATCH
    print("\n[STEP 5] Cryptographic SHA-256 verification against MinIO and Ledger...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.get(f"/evidence/{evidence_id}/verify?actor={raw_actor}")
        assert (
            r.status_code == 200
        ), f"Verification request failed: {r.status_code} {r.text}"
        verify_res = r.json()

    assert (
        verify_res["status"] == "MATCH"
    ), f"Verification status is not MATCH: {verify_res['status']}"
    assert verify_res["match"] is True, "Verification match is False"
    assert verify_res["stored_sha256"] == evidence_sha256, "Stored SHA256 mismatch"
    assert (
        verify_res["recomputed_sha256"] == evidence_sha256
    ), "Recomputed SHA256 mismatch"

    print("  [PASS] Evidence SHA-256 verification returns MATCH:")
    print(f"         Status: {verify_res['status']}")
    print(f"         Match: {verify_res['match']}")
    print(f"         Stored SHA-256:     {verify_res['stored_sha256']}")
    print(f"         Recomputed SHA-256: {verify_res['recomputed_sha256']}")
    print(f"         Verification Ledger Entry ID: {verify_res.get('ledger_entry_id')}")
    results["step5"] = {
        "pass": True,
        "status": verify_res["status"],
        "match": verify_res["match"],
    }

    # 6. Generate a fresh manifest containing that evidence
    print("\n[STEP 6] Generating fresh Section 65B Evidence Manifest...")
    generator_identity = "Forensic Laboratory - Unit 7"
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        payload = {
            "evidence_ids": [evidence_id],
            "generator_identity": generator_identity,
            "actor": raw_actor,
        }
        r = client.post("/manifests", json=payload)
        assert (
            r.status_code == 201
        ), f"Manifest creation failed: {r.status_code} {r.text}"
        fresh_manifest = r.json()

    manifest_id = fresh_manifest["manifest_id"]
    signature_algorithm = fresh_manifest["signature_algorithm"]
    digital_signature = fresh_manifest["digital_signature"]
    evidence_items = fresh_manifest["evidence_items"]
    chain_of_custody = fresh_manifest["chain_of_custody"]

    assert manifest_id.startswith("MANIFEST-"), f"Unexpected manifest ID: {manifest_id}"
    assert (
        signature_algorithm == "HMAC-SHA256"
    ), f"Unexpected signature algorithm: {signature_algorithm}"
    assert bool(digital_signature), "Digital signature is empty"
    assert (
        len(evidence_items) == 1
    ), f"Expected 1 evidence item in manifest, got {len(evidence_items)}"

    # Check chain_entry_count consistency
    item_summary = evidence_items[0]
    expected_chain_count_at_gen = 2  # INGEST + VERIFY
    assert (
        item_summary["chain_entry_count"] == expected_chain_count_at_gen
    ), f"Manifest chain_entry_count mismatch: expected {expected_chain_count_at_gen}, got {item_summary['chain_entry_count']}"
    assert (
        len(chain_of_custody) == expected_chain_count_at_gen
    ), f"Manifest chain_of_custody entries mismatch: expected {expected_chain_count_at_gen}, got {len(chain_of_custody)}"

    print("  [PASS] Section 65B Evidence Manifest generated successfully:")
    print(f"         Manifest ID: {manifest_id}")
    print(f"         Generator Identity: {fresh_manifest['generator_identity']}")
    print(f"         Signature Algorithm: {signature_algorithm}")
    print(f"         Digital Signature: {digital_signature[:32]}...")
    print(f"         Evidence Items Count: {fresh_manifest['evidence_count']}")
    print(
        f"         Item chain_entry_count: {item_summary['chain_entry_count']} (consistent with INGEST + VERIFY chain)"
    )
    print(f"         Embedded Chain Entries: {[e['action'] for e in chain_of_custody]}")
    results["step6"] = {
        "pass": True,
        "manifest_id": manifest_id,
        "signature_algorithm": signature_algorithm,
        "digital_signature": digital_signature,
        "chain_entry_count": item_summary["chain_entry_count"],
    }

    # 7. Manifest is persisted and can be retrieved by manifest_id
    print("\n[STEP 7] Retrieving persisted manifest from MinIO by manifest_id...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.get(f"/manifests/{manifest_id}")
        assert (
            r.status_code == 200
        ), f"Manifest retrieval failed: {r.status_code} {r.text}"
        retrieved_manifest = r.json()

    assert retrieved_manifest["manifest_id"] == manifest_id
    assert retrieved_manifest["digital_signature"] == digital_signature
    assert retrieved_manifest["generator_identity"] == generator_identity
    assert retrieved_manifest["signature_algorithm"] == signature_algorithm

    print("  [PASS] Manifest persisted and successfully retrieved by manifest_id:")
    print(f"         Storage URI: {retrieved_manifest.get('storage_uri')}")
    print("         Matches generated manifest: TRUE")
    results["step7"] = {"pass": True, "manifest_id": manifest_id}

    # 8. Verify the untouched manifest: is_valid = true, signature_algorithm = HMAC-SHA256
    print("\n[STEP 8] Verifying untouched manifest signature...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.post("/manifests/verify", json=fresh_manifest)
        assert r.status_code == 200, f"Verify request failed: {r.status_code} {r.text}"
        verify_untouched = r.json()

    assert (
        verify_untouched["is_valid"] is True
    ), f"Untouched manifest verification failed: {verify_untouched}"
    assert verify_untouched["signature_algorithm"] == "HMAC-SHA256"
    assert verify_untouched["manifest_id"] == manifest_id

    print("  [PASS] Untouched manifest verification succeeded:")
    print(f"         is_valid: {verify_untouched['is_valid']}")
    print(f"         signature_algorithm: {verify_untouched['signature_algorithm']}")
    print(f"         message: '{verify_untouched['message']}'")
    results["step8"] = {"pass": True, "is_valid": verify_untouched["is_valid"]}

    # 9. Create a copy of the manifest and modify generator_identity only
    print(
        "\n[STEP 9] Creating tampered copy of manifest (modifying generator_identity only)..."
    )
    tampered_manifest = copy.deepcopy(fresh_manifest)
    original_gen_identity = tampered_manifest["generator_identity"]
    tampered_manifest["generator_identity"] = (
        "Unauthorized Attacker / Impersonated Officer"
    )
    print(f"  Original generator_identity: '{original_gen_identity}'")
    print(f"  Modified generator_identity: '{tampered_manifest['generator_identity']}'")
    results["step9"] = {
        "pass": True,
        "tampered_generator_identity": tampered_manifest["generator_identity"],
    }

    # 10. Verify the modified manifest: is_valid = false
    print("\n[STEP 10] Verifying modified/tampered manifest signature...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.post("/manifests/verify", json=tampered_manifest)
        assert (
            r.status_code == 200
        ), f"Verify tampered request failed: {r.status_code} {r.text}"
        verify_tampered = r.json()

    assert (
        verify_tampered["is_valid"] is False
    ), f"Tampered manifest unexpectedly passed verification! {verify_tampered}"
    print(
        "  [PASS] Tampered generator_identity manifest verification correctly rejected:"
    )
    print(f"         is_valid: {verify_tampered['is_valid']}")
    print(f"         message: '{verify_tampered['message']}'")
    results["step10"] = {"pass": True, "is_valid": verify_tampered["is_valid"]}

    # 10b. Verify that tampering with legal_framework or legal_declaration also fails verification
    print(
        "\n[STEP 10b] Verifying tampered legal_framework and legal_declaration rejection..."
    )
    tampered_framework = copy.deepcopy(fresh_manifest)
    tampered_framework["legal_framework"] = "Unauthorized Altered Statute 2026"
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.post("/manifests/verify", json=tampered_framework)
        assert r.status_code == 200
        assert (
            r.json()["is_valid"] is False
        ), "Tampered legal_framework unexpectedly passed verification!"

    tampered_declaration = copy.deepcopy(fresh_manifest)
    tampered_declaration["legal_declaration"] = (
        "Fraudulent non-statutory declaration text."
    )
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.post("/manifests/verify", json=tampered_declaration)
        assert r.status_code == 200
        assert (
            r.json()["is_valid"] is False
        ), "Tampered legal_declaration unexpectedly passed verification!"
    print(
        "  [PASS] Tampered legal_framework and legal_declaration signatures rejected correctly."
    )

    # 10c. Generate and verify BSA 2023 Manifest
    print(
        "\n[STEP 10c] Generating and verifying BSA 2023 Section 63 Evidence Manifest..."
    )
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        bsa_payload = {
            "evidence_ids": [evidence_id],
            "generator_identity": "Cyber Forensic Cell - New Delhi",
            "actor": raw_actor,
            "legal_framework": "Section 63 Bharatiya Sakshya Adhiniyam, 2023 / BNSS 2023",
        }
        r_bsa = client.post("/manifests", json=bsa_payload)
        assert r_bsa.status_code == 201, f"BSA manifest creation failed: {r_bsa.text}"
        bsa_manifest = r_bsa.json()
        assert (
            "SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023"
            in bsa_manifest["legal_declaration"]
        )

        r_bsa_verify = client.post("/manifests/verify", json=bsa_manifest)
        assert r_bsa_verify.status_code == 200
        assert (
            r_bsa_verify.json()["is_valid"] is True
        ), "BSA manifest verification failed!"
    print("  [PASS] BSA 2023 Section 63 Manifest generated and verified successfully.")
    print(f"         Manifest ID: {bsa_manifest['manifest_id']}")
    print(f"         Legal Framework: {bsa_manifest['legal_framework']}")

    # 10d. Generate and verify Ed25519 Asymmetric Manifest
    print(
        "\n[STEP 10d] Generating and verifying Ed25519 Asymmetric Evidence Manifest..."
    )
    from core.custody.manifest import generate_ed25519_keypair

    ed_priv_hex, ed_pub_hex = generate_ed25519_keypair()
    _, wrong_ed_pub_hex = generate_ed25519_keypair()

    from core.custody.manifest import ManifestGenerator

    gen_ed = ManifestGenerator()
    ed_manifest_obj = gen_ed.generate_manifest(
        evidence_ids=[evidence_id],
        generator_identity="High Court Forensic Expert",
        actor=raw_actor,
        legal_framework="Section 63 Bharatiya Sakshya Adhiniyam, 2023 / BNSS 2023",
        signature_algorithm="Ed25519",
        signing_key=ed_priv_hex,
    )
    ed_manifest_dict = ed_manifest_obj.model_dump()
    assert ed_manifest_dict["signature_algorithm"] == "Ed25519"
    assert len(ed_manifest_dict["digital_signature"]) == 128

    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        # Verify valid Ed25519 manifest with public key
        r_ed_verify = client.post(
            f"/manifests/verify?public_key={ed_pub_hex}", json=ed_manifest_dict
        )
        assert r_ed_verify.status_code == 200
        assert (
            r_ed_verify.json()["is_valid"] is True
        ), "Ed25519 manifest verification failed!"

        # Verify failure with wrong public key
        r_ed_wrong_key = client.post(
            f"/manifests/verify?public_key={wrong_ed_pub_hex}",
            json=ed_manifest_dict,
        )
        assert r_ed_wrong_key.status_code == 200
        assert (
            r_ed_wrong_key.json()["is_valid"] is False
        ), "Ed25519 manifest with wrong key unexpectedly passed!"

        # Verify failure when payload is tampered
        ed_tampered = copy.deepcopy(ed_manifest_dict)
        ed_tampered["generator_identity"] = "Unauthorized Third Party"
        r_ed_tampered = client.post(
            f"/manifests/verify?public_key={ed_pub_hex}", json=ed_tampered
        )
        assert r_ed_tampered.status_code == 200
        assert (
            r_ed_tampered.json()["is_valid"] is False
        ), "Tampered Ed25519 manifest unexpectedly passed!"

    print("  [PASS] Ed25519 Asymmetric Manifest generated and verified successfully.")
    print(f"         Manifest ID: {ed_manifest_dict['manifest_id']}")
    print(f"         Signature Algorithm: {ed_manifest_dict['signature_algorithm']}")
    print(
        f"         Ed25519 Signature: {ed_manifest_dict['digital_signature'][:32]}..."
    )
    print("         Valid public key verification: PASS")
    print("         Wrong public key rejection: PASS")
    print("         Tampered payload rejection: PASS")

    # 11. Confirm original manifest still verifies successfully
    print("\n[STEP 11] Re-confirming original manifest verifies successfully...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.post("/manifests/verify", json=fresh_manifest)
        assert (
            r.status_code == 200
        ), f"Verify original re-check failed: {r.status_code} {r.text}"
        verify_original_recheck = r.json()

    assert (
        verify_original_recheck["is_valid"] is True
    ), f"Original manifest verification failed on re-check: {verify_original_recheck}"
    print("  [PASS] Original manifest re-verification confirmed:")
    print(f"         is_valid: {verify_original_recheck['is_valid']}")
    results["step11"] = {"pass": True, "is_valid": verify_original_recheck["is_valid"]}

    # 12. Confirm ledger integrity remains valid
    print("\n[STEP 12] Verifying entire custody ledger hash chain integrity...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.get("/ledger/verify")
        assert r.status_code == 200, f"Ledger verify failed: {r.status_code} {r.text}"
        ledger_verify = r.json()

    assert (
        ledger_verify["is_valid"] is True
    ), f"Ledger integrity verification failed: {ledger_verify}"
    print("  [PASS] Full custody ledger integrity verified:")
    print(f"         is_valid: {ledger_verify['is_valid']}")
    print(f"         total_entries: {ledger_verify['total_entries']}")
    print(f"         message: '{ledger_verify['message']}'")
    results["step12"] = {
        "pass": True,
        "is_valid": ledger_verify["is_valid"],
        "total_entries": ledger_verify["total_entries"],
    }

    # 13. Report exact evidence_id, manifest_id, relevant ledger actions, and verification results
    print("\n[STEP 13] Collecting full custody trail and report data...")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = client.get(f"/ledger?evidence_id={evidence_id}")
        assert r.status_code == 200
        final_ledger_entries = r.json().get("entries", [])

    print("\n" + "=" * 80)
    print(" COMPLETE CUSTODY TRAIL FOR FRESH EVIDENCE ARTIFACT")
    print("=" * 80)
    for idx, e in enumerate(final_ledger_entries, 1):
        print(f"Entry #{idx} [ID: {e['id']}]")
        print(f"  Action:        {e['action']}")
        print(f"  Actor:         {e['actor']}")
        print(f"  Timestamp:     {e['timestamp']}")
        print(f"  SHA-256:       {e['sha256']}")
        print(f"  Previous Hash: {e['previous_hash']}")
        print(f"  Entry Hash:    {e['entry_hash']}")
        if e.get("signature"):
            print(f"  Signature:     {e['signature'][:32]}...")
        print(f"  Metadata:      {json.dumps(e['metadata'], indent=2)}")
        print("-" * 60)

    # Historical entries preservation check
    all_ledger_entries = db.fetch_all(
        "SELECT action, COUNT(*) as cnt FROM custody_ledger GROUP BY action"
    )
    print("\nGlobal Ledger Action Breakdown:")
    for row in all_ledger_entries:
        print(f"  {row['action']}: {row['cnt']}")

    print("\n" + "=" * 80)
    print(" ACCEPTANCE SUMMARY")
    print("=" * 80)
    all_passed = all(step.get("pass", False) for step in results.values())
    status_str = "PASS" if all_passed else "FAIL"
    print(f"Final Acceptance Status: {status_str}")
    print(f"Evidence ID: {evidence_id}")
    print(f"Manifest ID: {manifest_id}")
    print(
        f"Fresh Evidence Chain Actions: {[e['action'] for e in final_ledger_entries]}"
    )
    print("=" * 80)

    return {
        "status": status_str,
        "evidence_id": evidence_id,
        "evidence_sha256": evidence_sha256,
        "manifest_id": manifest_id,
        "digital_signature": digital_signature,
        "raw_actor": raw_actor,
        "normalized_agent": expected_normalized_agent,
        "fresh_ledger_entries": final_ledger_entries,
        "ledger_verify": ledger_verify,
        "all_passed": all_passed,
    }


if __name__ == "__main__":
    out = run_acceptance_test()
    if not out["all_passed"]:
        sys.exit(1)
