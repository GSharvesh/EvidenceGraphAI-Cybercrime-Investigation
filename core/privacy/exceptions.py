"""Privacy and DPDP Act 2023 compliance domain exceptions for EvidenceGraphAI."""


class PrivacyError(Exception):
    """Base exception for all privacy and anonymization errors."""

    pass


class PIIDetectionError(PrivacyError):
    """Raised when an error occurs during PII scanning."""

    pass


class AnonymizationError(PrivacyError):
    """Raised when an error occurs while transforming or masking data."""

    pass
