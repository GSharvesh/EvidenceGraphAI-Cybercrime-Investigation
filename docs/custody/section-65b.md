# Indian Evidence Act Section 65B & BNSS Compliance Mapping

## 1. Legal Requirements for Electronic Evidence

Under **Section 65B of the Indian Evidence Act, 1872** (and the corresponding electronic evidence provisions under Bharatiya Sakshya Adhiniyam, 2023 / BNSS), electronic records produced by computer systems are admissible in judicial proceedings provided specific statutory conditions are certified.

---

## 2. Statutory Conditions & EvidenceGraphAI Mapping

| Statutory Requirement | Legal Condition | EvidenceGraphAI Implementation |
| :--- | :--- | :--- |
| **Section 65B(2)(a)** | Computer produced the output during period of regular lawful use. | Automated system logging with authenticated actor tracking in immutable ledger. |
| **Section 65B(2)(b)** | Information fed into computer in ordinary course of regular activities. | REST ingestion pipeline logs every artifact at first contact with correlation IDs. |
| **Section 65B(2)(c)** | Computer was operating properly throughout the relevant period. | System health checks, Prometheus observability, and continuous verification records. |
| **Section 65B(2)(d)** | Output accurately reproduces original information. | Bit-level SHA256 hashing at first contact and on-demand cryptographic verification. |
| **Section 65B(4)** | Certificate identifying electronic record signed by person responsible. | Manifest generator attaches cryptographic digital signature and Section 65B declaration. |

---

## 3. Cryptographic Integrity & Legal Admissibility

By maintaining an unbroken cryptographic hash chain from the moment an artifact enters the system through each transformation and export step, EvidenceGraphAI establishes mathematical integrity, chain of custody continuity, and cryptographic non-repudiation of electronic records.

> [!IMPORTANT]
> **Legal Admissibility Distinction**: Cryptographic validity confirms that electronic records are unaltered and accurately tracked. Statutory legal admissibility in court remains a legal determination governed by judicial discretion and procedural compliance under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (or Section 65B of the Indian Evidence Act, 1872) read with Section 105 of the Bharatiya Nagarik Suraksha Sanhita, 2023. Cryptographic integrity supports and facilitates statutory compliance, but does not substitute for judicial process.
