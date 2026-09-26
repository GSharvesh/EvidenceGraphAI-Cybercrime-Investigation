# ADR 0011: Deterministic Cryptographic Hash Chaining Algorithm

## Status
Accepted

## Context
To prove that no ledger records have been inserted, modified, or deleted after the fact, the system must compute a cryptographic chain where each entry's hash encapsulates the hash of the preceding entry. We needed a strictly deterministic serialization and hashing algorithm.

## Decision
We implemented canonical JSON serialization:
1. Lexicographical key sorting (`sort_keys=True`).
2. Compact separators without extraneous whitespace (`separators=(',', ':')`).
3. SHA256 hashing over UTF-8 encoded canonical byte streams.
4. Each entry's hash computation takes:
   $$\text{entry\_hash} = \text{SHA256}(\text{canonical}(\text{evidence\_id}, \text{action}, \text{actor}, \text{timestamp}, \text{sha256}, \text{previous\_hash}, \text{metadata}))$$
5. The genesis record sets `previous_hash = "0" * 64`.

## Consequences
- **Positive:** 100% deterministic, platform-independent, verifiable by external auditors without proprietary tools.
- **Negative:** Schema changes to metadata fields require canonical dictionary normalization.
