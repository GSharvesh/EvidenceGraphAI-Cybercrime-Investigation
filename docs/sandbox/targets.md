# Sandbox Vulnerable Targets

## Catalog of Targets

The Phase 3 sandbox environment maintains a collection of controlled, intentionally vulnerable target containers:

| Service Name | Description | Key Vulnerability / CVE | Port |
|---|---|---|---|
| `log4j-vulnerable` | Custom Java HTTP service built with Apache Log4j 2.14.1 | CVE-2021-44228 (Log4Shell JNDI RCE) | 8080 |
| `dvwa` | Damn Vulnerable Web Application | SQLi, XSS, Command Injection, File Inclusion | 80 |
| `juice-shop` | OWASP Juice Shop Node.js / Angular application | Modern web vulnerabilities, JWT tampering, injection | 3000 |
| `metasploitable` | Multi-service Linux distribution with legacy services | Multiple unauthenticated network services | Various |

## Disclaimer & Security Policy

All vulnerable targets exist solely for local defensive threat reconstruction, forensic signature derivation, and automated detection rule verification. They must **never** be exposed to public networks or bound to host interfaces.
