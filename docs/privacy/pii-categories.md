# PII Categories & Detection Rules

## 1. Supported Entity Categories

[`PIIDetector`](file:///d:/EvidenceGraphAI/core/privacy/pii_detector.py) identifies the following primary PII categories:

| Category | Description | Validation & Regex Specification |
| :--- | :--- | :--- |
| `AADHAAR` | Indian 12-digit Unique Identification Number | `\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b` validated via Verhoeff checksum algorithm |
| `PAN` | Permanent Account Number (Indian Income Tax) | `\b[A-Z]{5}[0-9]{4}[A-Z]\b` (5 letters, 4 digits, 1 letter) |
| `PASSPORT` | Indian Passport Identifier | `\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b` |
| `PHONE` | Indian Mobile Phone Numbers | `(?:\+91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}\b` |
| `EMAIL` | Electronic Mail Addresses | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b` |
| `CREDIT_CARD` | Payment Cards (Visa, MasterCard, Amex, RuPay) | Standard BIN lengths validated via Luhn formula |
| `PRIVATE_IP` | Internal / Local Endpoint IP Addresses | RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) |

---

## 2. Confidence Scoring

Each detected finding receives a confidence score from `0.0` to `1.0`:
- **Algorithmic Validation (1.0):** Checksum-verified Aadhaar (Verhoeff) and Credit Card (Luhn).
- **Exact Format Matches (0.95 - 0.99):** Standard emails, PAN records, and private IP patterns.
- **Heuristic Matches (0.85 - 0.90):** Unformatted numbers or partial phone matches.
