# Cryptographic Hash Chain Specification

## 1. Mathematical Model

The custody ledger employs sequential cryptographic hash chaining to guarantee tamper evidence. Each block/entry encapsulates the hash of the preceding entry in the sequence, producing an unbroken Merkle-like chain.

```mermaid
graph LR
    subgraph Block 1 (Genesis)
        B1_P["previous_hash: 0000...0000"]
        B1_D["Payload: {evidence_id, action, actor, ...}"]
        B1_H["entry_hash: H1 = SHA256(B1_P + B1_D)"]
    end

    subgraph Block 2
        B2_P["previous_hash: H1"]
        B2_D["Payload: {evidence_id, action, actor, ...}"]
        B2_H["entry_hash: H2 = SHA256(B2_P + B2_D)"]
    end

    subgraph Block 3
        B3_P["previous_hash: H2"]
        B3_D["Payload: {evidence_id, action, actor, ...}"]
        B3_H["entry_hash: H3 = SHA256(B3_P + B3_D)"]
    end

    B1_H --> B2_P
    B2_H --> B3_P
```

---

## 2. Canonical Serialization & Hash Computation

To guarantee identical digest computation across disparate architectures and runtimes:

1. **Genesis Rule:** If no previous ledger entry exists, `previous_hash` is initialized to 64 ASCII zeros (`0000000000000000000000000000000000000000000000000000000000000000`).
2. **Canonical JSON Encoding:**
   - Keys are sorted alphabetically (`sort_keys=True`).
   - Compact separators with zero whitespace (`separators=(',', ':')`).
   - UTF-8 byte encoding.
3. **Payload Structure:**
   ```json
   {
     "action": "INGEST",
     "actor": "investigator-01",
     "evidence_id": "EV-3eb51b76-4a93-4c5e-bd71-f34f9a02a2c7",
     "metadata": {"original_filename": "capture.pcap"},
     "previous_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "sha256": "b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a8c",
     "timestamp": "2026-09-26T10:00:00.000000+00:00"
   }
   ```
4. **Digest Calculation:**
   $$\text{entry\_hash} = \text{SHA256}(\text{canonical\_json\_bytes})$$

---

## 3. Verification Algorithm

Verification iterates through the entire ledger sequence ordered by `id ASC`:
1. **Link Continuity:** Confirms `entry[i].previous_hash == entry[i-1].entry_hash`. If mismatch, returns `CONTINUITY_BREAK`.
2. **Payload Integrity:** Recomputes $\text{SHA256}(\text{canonical\_payload})$ and confirms equality with stored `entry_hash`. If mismatch, returns `HASH_MISMATCH`.
