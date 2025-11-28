# crypton-certificate

X.509 Certificate and Attribute Certificate handling for Haskell

[![BSD](http://b.repl.ca/v1/license-BSD-blue.png)](http://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](http://b.repl.ca/v1/language-haskell-lightgrey.png)](http://haskell.org)

## Overview

This repository provides comprehensive X.509 certificate handling capabilities for Haskell, including support for:

- **X.509 Public Key Certificates** (RFC 5280)
- **X.509 Attribute Certificates** (RFC 5755)
- **TCG Platform Certificates** (IWG Platform Certificate Profile v1.1)
- **Delta Platform Certificates** for hardware component updates

This is a fork of [crypton-certificate](https://github.com/kazu-yamamoto/crypton-certificate) with extended support for Attribute Certificates and TCG Platform Certificates.

## Packages

### Core X.509 Packages

| Package | Description |
|---------|-------------|
| **crypton-x509** | Core X.509 certificate types, reader and writer |
| **crypton-x509-store** | X.509 certificate collection and storage |
| **crypton-x509-system** | System certificate store access (macOS, Windows, Unix) |
| **crypton-x509-validation** | X.509 certificate chain validation |
| **crypton-x509-util** | Debugging and query utilities |

### Attribute Certificate Packages

| Package | Description |
|---------|-------------|
| **crypton-x509-ac-validation** | RFC 5755 Attribute Certificate and TCG Platform Certificate validation |

### TCG Platform Certificate Packages

| Package | Description |
|---------|-------------|
| **tcg-platform-cert** | TCG Platform Certificate types and OID definitions per IWG v1.1 |
| **tcg-platform-cert-validation** | Validation functions for TCG Platform Certificates |
| **tcg-platform-cert-util** | Command-line utility for inspecting and validating platform certificates |

## Building

```bash
# Using Stack
stack build

# Run tests
stack test

# Build documentation
stack haddock
```

## TCG Platform Certificate Utility

The `tcg-platform-cert-util` package provides a command-line tool for working with TCG Platform Certificates:

```bash
# Show certificate details
stack exec tcg-platform-cert-util -- show <certificate.pem>

# List platform components
stack exec tcg-platform-cert-util -- components <certificate.pem>

# Validate certificate
stack exec tcg-platform-cert-util -- validate <certificate.pem> --issuer <issuer.pem>
```

## Specifications

This implementation follows these specifications. Reference documents are available in the `spec/` directory.

### IETF RFCs

| Document | Description |
|----------|-------------|
| `rfc5280.txt` | Internet X.509 PKI Certificate and CRL Profile |
| `rfc5755.txt` | An Internet Attribute Certificate Profile for Authorization |

### ITU-T X.509 Standards

| Document | Description |
|----------|-------------|
| `T-REC-X.509-201910-I!!PDF-E.pdf` | ITU-T X.509 (10/2019) - PKI and PMI framework |
| `T-REC-X.509-202110-I!Cor1!PDF-E.pdf` | X.509 Corrigendum 1 (10/2021) |
| `T-REC-X.509-202310-I!Cor2!PDF-E.pdf` | X.509 Corrigendum 2 (10/2023) |
| `T-REC-X.509-202410-I!Amd1!PDF-E.pdf` | X.509 Amendment 1 (10/2024) |

### TCG (Trusted Computing Group) Specifications

| Document | Description |
|----------|-------------|
| `IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf` | Platform Certificate Profile v1.1 Revision 19 |
| `TCG-Platform-Certificate-Profile-Version-2.0-Revision-39.pdf` | Platform Certificate Profile v2.0 Revision 39 |
| `TCG_Component_Class_Registry_v1.0_rev14_pub.pdf` | Component Class Registry v1.0 Revision 14 |

### Test Vectors

| Document | Description |
|----------|-------------|
| `PKITS_v1_0_0.pdf` | NIST PKI Test Suite (PKITS) v1.0.0 |

## License

BSD-3-Clause

## Authors

- Vincent Hanquez (original crypton-certificate)
- Kazu Yamamoto (crypton-certificate maintainer)
- Toru Tomita (TCG Platform Certificate extensions)
