"""Custody, ledger, and hash chain domain exceptions for EvidenceGraphAI."""


class CustodyError(Exception):
    """Base exception for all chain-of-custody domain errors."""

    pass


class CustodyLedgerError(CustodyError):
    """Raised when an error occurs while querying or appending to the custody ledger."""

    pass


class ChainIntegrityError(CustodyError):
    """Raised when the hash chain integrity verification fails."""

    pass


class TamperDetectedError(CustodyError):
    """Raised when an artifact hash mismatch or ledger tampering is detected."""

    pass


class ArtifactVerificationError(CustodyError):
    """Raised when artifact verification fails."""

    pass


class ManifestGenerationError(CustodyError):
    """Raised when generating an Evidence Manifest fails."""

    pass


class ManifestVerificationError(CustodyError):
    """Raised when verifying an Evidence Manifest signature or content fails."""

    pass
