"""Forensic log file anonymization filter for DPDP compliance."""

from pathlib import Path

from pydantic import BaseModel, Field

from core.privacy.anonymizer import AnonymizationMethod, Anonymizer
from core.privacy.pii_detector import PIIDetector


class FilteredLogResult(BaseModel):
    """Result of log file anonymization processing."""

    anonymized_content: str
    lines_processed: int
    lines_modified: int
    findings_count: int
    category_counts: dict[str, int] = Field(default_factory=dict)
    method_used: AnonymizationMethod


class LogFilter:
    """Line-by-line log processor that detects and anonymizes PII."""

    def __init__(
        self,
        detector: PIIDetector | None = None,
        anonymizer: Anonymizer | None = None,
    ) -> None:
        self.detector = detector or PIIDetector()
        self.anonymizer = anonymizer or Anonymizer()

    def filter_log_text(
        self,
        log_text: str,
        method: AnonymizationMethod = AnonymizationMethod.MASK,
    ) -> FilteredLogResult:
        """Processes raw log text and returns anonymized content and statistics.

        Args:
            log_text: Raw multi-line log string.
            method: Anonymization method to apply.

        Returns:
            FilteredLogResult.
        """
        lines = log_text.splitlines(keepends=True)
        anonymized_lines: list[str] = []
        lines_modified = 0
        total_findings = 0
        aggregate_counts: dict[str, int] = {}

        for line in lines:
            findings = self.detector.detect_pii(line, artifact_type="LOG")
            if findings:
                res = self.anonymizer.anonymize(line, findings, method=method)
                anonymized_lines.append(res.anonymized_text)
                lines_modified += 1
                total_findings += res.findings_count
                for cat, count in res.category_counts.items():
                    aggregate_counts[cat] = aggregate_counts.get(cat, 0) + count
            else:
                anonymized_lines.append(line)

        return FilteredLogResult(
            anonymized_content="".join(anonymized_lines),
            lines_processed=len(lines),
            lines_modified=lines_modified,
            findings_count=total_findings,
            category_counts=aggregate_counts,
            method_used=method,
        )

    def filter_log_file(
        self,
        file_path: Path | str,
        output_path: Path | str | None = None,
        method: AnonymizationMethod = AnonymizationMethod.MASK,
    ) -> FilteredLogResult:
        """Reads a log file from disk, anonymizes PII, and optionally writes output."""
        path = Path(file_path)
        content = path.read_text(encoding="utf-8", errors="replace")
        result = self.filter_log_text(content, method=method)

        if output_path:
            out = Path(output_path)
            out.write_text(result.anonymized_content, encoding="utf-8")

        return result
