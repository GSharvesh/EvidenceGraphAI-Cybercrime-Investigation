"""Custom exceptions for the Threat Reconstruction Agent."""


class ThreatReconstructionError(Exception):
    """Base exception for Threat Reconstruction Agent errors."""


class BlueprintGenerationError(ThreatReconstructionError):
    """Raised when blueprint generation fails for a given CVE."""


class BlueprintNotFoundError(ThreatReconstructionError):
    """Raised when a requested blueprint ID does not exist."""


class CVENotAnalyzedError(ThreatReconstructionError):
    """Raised when a CVE node does not exist in the graph (must be analyzed first)."""
