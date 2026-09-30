"""Custom exceptions for the ATT&CK Mapper."""


class ATTACKMapperError(Exception):
    """Base exception for ATT&CK Mapper errors."""


class MappingRuleError(ATTACKMapperError):
    """Raised when a mapping rule is malformed."""


class MappingError(ATTACKMapperError):
    """Raised when evidence-to-technique mapping fails."""
