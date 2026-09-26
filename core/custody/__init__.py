"""Forensic chain of custody subsystem for EvidenceGraphAI."""

from core.custody.chain import (
    GENESIS_HASH,
    ChainVerificationResult,
    LedgerEntry,
    canonical_serialize,
    compute_entry_hash,
    verify_chain,
)
from core.custody.exceptions import (
    ArtifactVerificationError,
    ChainIntegrityError,
    CustodyError,
    CustodyLedgerError,
    ManifestGenerationError,
    ManifestVerificationError,
    TamperDetectedError,
)
from core.custody.ledger import CustodyLedger
from core.custody.manifest import (
    EvidenceItemSummary,
    EvidenceManifest,
    ManifestGenerator,
)
from core.custody.verifier import (
    ArtifactVerifier,
    VerificationResult,
    VerificationStatus,
)

__all__ = [
    "CustodyLedger",
    "LedgerEntry",
    "ChainVerificationResult",
    "ArtifactVerifier",
    "VerificationResult",
    "VerificationStatus",
    "ManifestGenerator",
    "EvidenceManifest",
    "EvidenceItemSummary",
    "GENESIS_HASH",
    "canonical_serialize",
    "compute_entry_hash",
    "verify_chain",
    "CustodyError",
    "CustodyLedgerError",
    "ChainIntegrityError",
    "TamperDetectedError",
    "ArtifactVerificationError",
    "ManifestGenerationError",
    "ManifestVerificationError",
]
