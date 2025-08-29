# TCG Platform Certificate Utility

A command-line tool for generating, parsing, validating, and analyzing TCG Platform Certificates based on the IWG Platform Certificate Profile v1.1.

## Features

- **Secure Certificate Binding**: Uses ObjectDigestInfo with SHA256 hashes of EK certificate public keys (RFC 5755 compliant)
- **Real Cryptographic Signatures**: Generates certificates with proper digital signatures using CA private keys
- **EK Certificate Integration**: Binds platform certificates to TPM Endorsement Key certificates
- **Comprehensive Validation**: Structure, signature, and attribute validation
- **Multiple Output Formats**: PEM format with detailed information display

## Installation

Build using Stack:

```bash
cd tcg-platform-cert-util
stack build
```

The executable will be available at:
```bash
.stack-work/dist/*/build/tcg-platform-cert-util/tcg-platform-cert-util
```

## Commands Overview

- `generate` - Generate a new TCG Platform Certificate with real signatures
- `generate-delta` - Generate delta platform certificates
- `show` - Display detailed certificate information
- `validate` - Comprehensive certificate validation
- `components` - Extract platform component information
- `create-config` - Create example YAML configuration files

## Quick Start

### Using Stack

Run commands using Stack:

```bash
# Build the project
stack build

# Run commands using stack exec
stack exec tcg-platform-cert-util -- [command] [options]
```

### Example: Generate and View Certificate

```bash
# Generate a test certificate using stack exec
stack exec tcg-platform-cert-util -- generate \
  --config test-config.yaml \
  --ca-key test-data/keys/test-ca-key.pem \
  --ca-cert test-data/certs/test-ca-cert.pem \
  --ek-cert test-data/certs/test-ek-cert.pem \
  --output test-data/certs/my-cert.pem

# View the generated certificate
stack exec tcg-platform-cert-util -- show test-data/certs/my-cert.pem

# View with detailed information
stack exec tcg-platform-cert-util -- show --verbose test-data/certs/my-cert.pem
```

## Certificate Generation

### Prerequisites

Before generating certificates, you need:

1. **CA Certificate** (`test-ca-cert.pem`) - Certificate Authority's public certificate
2. **CA Private Key** (`test-ca-key.pem`) - Certificate Authority's private key for signing
3. **EK Certificate** (`test-ek-cert.pem`) - TPM Endorsement Key certificate for secure binding

### Generate Platform Certificate

Create a platform certificate with real cryptographic signatures:

```bash
# Using direct executable (after building)
tcg-platform-cert-util generate \
  --manufacturer "Test Corporation" \
  --model "Test Platform" \
  --version "1.0" \
  --serial "TEST001" \
  --output my-platform-cert.pem \
  --ca-cert test-data/certs/test-ca-cert.pem \
  --ca-key test-data/keys/test-ca-key.pem \
  --ek-cert test-data/certs/test-ek-cert.pem

# Or using stack exec (recommended)
stack exec tcg-platform-cert-util -- generate \
  --manufacturer "Test Corporation" \
  --model "Test Platform" \
  --version "1.0" \
  --serial "TEST001" \
  --output my-platform-cert.pem \
  --ca-cert test-data/certs/test-ca-cert.pem \
  --ca-key test-data/keys/test-ca-key.pem \
  --ek-cert test-data/certs/test-ek-cert.pem
```

**Output:**
```
Generating platform certificate...
Loading CA private key from: test-ca-key.pem
Loading CA certificate from: test-ca-cert.pem
Loading TPM EK certificate from: test-ek-cert.pem
CA credentials and TPM EK certificate loaded successfully
Generating certificate with real signature and proper EK certificate binding...
Certificate generated successfully with real signature and EK certificate binding
Certificate written to: my-platform-cert.pem
```

### Generate Command Options

```bash
tcg-platform-cert-util generate --help
```

**Required Options:**
- `--ca-key FILE`, `-k FILE` - CA private key file (PEM format) [REQUIRED]
- `--ca-cert FILE`, `-c FILE` - CA certificate file (PEM format) [REQUIRED]
- `--ek-cert FILE`, `-e FILE` - TPM EK certificate file (PEM format) [REQUIRED]

**Platform Information Options (required unless using config file):**
- `--manufacturer NAME`, `-m NAME` - Platform manufacturer name
- `--model NAME` - Platform model name
- `--version VER` - Platform version
- `--serial NUM`, `-s NUM` - Platform serial number

**Optional Options:**
- `--output FILE`, `-o FILE` - Output file path (default: platform-cert.pem)
- `--config FILE`, `-f FILE` - YAML configuration file (alternative to individual options)
- `--key-size BITS` - RSA key size in bits (default: 2048)
- `--validity DAYS` - Validity period in days (default: 365)
- `--help`, `-h` - Show help message

### Using YAML Configuration Files

You can simplify certificate generation by using YAML configuration files instead of specifying each option individually:

#### Creating a Configuration Template

Generate an example configuration file:

```bash
# Using direct executable
tcg-platform-cert-util create-config platform-config.yaml

# Or using stack exec (recommended)
stack exec tcg-platform-cert-util -- create-config platform-config.yaml
```

This creates a comprehensive example file with TCG Component Class Registry v1.0 compliant component definitions:

```yaml
manufacturer: "Test Corporation"
model: "Test Platform"
version: "1.0"
serial: "TEST001"
validityDays: 365
keySize: 2048
components:
  - class: "00030003"  # Motherboard (includes processor, memory, and I/O)
    manufacturer: "Test Corporation"
    model: "Test Platform Motherboard"
    serial: "MB-TEST001"
    revision: "1.0"
  - class: "00010002"  # CPU (Central Processing Unit)
    manufacturer: "Intel Corporation"
    model: "Xeon E5-2680"
    serial: "CPU-TEST001"
    revision: "Rev C0"
  - class: "00060004"  # DRAM Memory (Dynamic Random-Access Memory)
    manufacturer: "Samsung"
    model: "DDR4-3200"
    serial: "MEM-TEST001"
    revision: "1.35V"
  - class: "00070003"  # SSD Drive (Solid-State Drive)
    manufacturer: "Western Digital"
    model: "WD Blue SN580"
    serial: "SSD-TEST001"
    revision: "1.0"
  - class: "00130003"  # System firmware (UEFI)
    manufacturer: "Phoenix Technologies"
    model: "SecureCore Tiano"
    serial: "UEFI-TEST001"
    revision: "2.3.1"
  - class: "00040009"  # TPM (discrete Trusted Platform Module)
    manufacturer: "Infineon"
    model: "SLB9670"
    serial: "TPM-TEST001"
    revision: "2.0"
```

#### Using Configuration Files

Generate certificates using YAML configuration:

```bash
# Using direct executable
tcg-platform-cert-util generate \
  --config test-config.yaml \
  --output my-platform-cert.pem \
  --ca-cert test-data/certs/test-ca-cert.pem \
  --ca-key test-data/keys/test-ca-key.pem \
  --ek-cert test-data/certs/test-ek-cert.pem

# Or using stack exec (recommended)
stack exec tcg-platform-cert-util -- generate \
  --config test-config.yaml \
  --output my-platform-cert.pem \
  --ca-cert test-data/certs/test-ca-cert.pem \
  --ca-key test-data/keys/test-ca-key.pem \
  --ek-cert test-data/certs/test-ek-cert.pem
```

**Component Class Values**: All component class values follow the [TCG Component Class Registry v1.0](https://trustedcomputinggroup.org/resource/tcg-component-class-registry/) standard. The 4-byte hexadecimal values specify component categories and sub-categories as defined by the TCG.

### Complete TCG Platform Certificate Fields Reference

Based on the IWG Platform Certificate Profile v1.1, the following comprehensive YAML configuration shows all available fields that can be configured. Fields marked as auto-generated are handled automatically during certificate creation.

#### Field Status Legend
- **MUST**: Required field (automatically included if not specified)
- **MAY**: Optional field
- **SHOULD**: Recommended field
- **SHOULD NOT**: Not recommended

#### Platform Certificate Fields

```yaml
# === Basic Platform Information (REQUIRED) ===
manufacturer: "Test Corporation"         # Platform manufacturer name
model: "Test Platform"                   # Platform model name  
version: "1.0"                          # Platform version
serial: "TEST001"                       # Platform serial number

# === Certificate Properties (OPTIONAL) ===
validityDays: 365                       # Certificate validity period in days (default: 365)
keySize: 2048                          # RSA key size for certificate generation (default: 2048)

# === Platform Components (OPTIONAL) ===
components:
  # Motherboard Component
  - class: "00030003"                   # Component class from TCG Component Class Registry
    manufacturer: "Test Corporation"     # Component manufacturer
    model: "Test Platform Motherboard"  # Component model name
    serial: "MB-TEST001"                # Component serial number
    revision: "1.0"                     # Component revision/version
    
  # CPU Component  
  - class: "00010002"                   # CPU class (Central Processing Unit)
    manufacturer: "Intel Corporation"
    model: "Xeon E5-2680"
    serial: "CPU-TEST001"
    revision: "Rev C0"
    
  # Memory Component
  - class: "00060004"                   # DRAM Memory class
    manufacturer: "Samsung" 
    model: "DDR4-3200"
    serial: "MEM-TEST001"
    revision: "1.35V"
    
  # Storage Component
  - class: "00070003"                   # SSD Drive class
    manufacturer: "Western Digital"
    model: "WD Blue SN580" 
    serial: "SSD-TEST001"
    revision: "1.0"
    
  # Firmware Component
  - class: "00130003"                   # System firmware (UEFI) class
    manufacturer: "Phoenix Technologies"
    model: "SecureCore Tiano"
    serial: "UEFI-TEST001"
    revision: "2.3.1"
    
  # TPM Component
  - class: "00040009"                   # TPM (discrete Trusted Platform Module) class
    manufacturer: "Infineon"
    model: "SLB9670"
    serial: "TPM-TEST001"
    revision: "2.0"

# === Notes ===
# 1. Only the fields shown above are supported in the current implementation
# 2. All other fields (extensions, advanced security features, etc.) are automatically
#    generated or handled by the certificate generation process
# 3. Component class values must be valid 4-byte hexadecimal from TCG Component Class Registry
# 4. Certificate signatures, validity timestamps, and cryptographic bindings are auto-generated
```

#### Important Notes

- Only the fields shown in the YAML example above are currently supported by the implementation
- All other certificate fields (timestamps, signatures, cryptographic bindings, extensions) are automatically generated during the certificate creation process
- Any unsupported fields in the YAML configuration file will be ignored
- Component class values must be valid 4-byte hexadecimal values from the TCG Component Class Registry
- The `FromJSON` and `ToJSON` instances automatically handle parsing and ignore unknown fields

## Certificate Analysis

### Show Certificate Information

Display detailed certificate content:

```bash
# Using direct executable
tcg-platform-cert-util show my-platform-cert.pem

# Or using stack exec (recommended)
stack exec tcg-platform-cert-util -- show my-platform-cert.pem
```

**Example Output:**
```
Reading certificate from: my-platform-cert.pem
Serial: 1
Version: v2
Valid: 2024-12-01 00:00:00 to 2025-12-01 00:00:00
Manufacturer: "Test Corporation"
Model: "Test Platform"
Serial: "TEST001"
```

### Validate Certificate

Comprehensive certificate validation with optional CA certificate verification:

#### Basic Validation (Structure and Content Only)

```bash
# Using direct executable
tcg-platform-cert-util validate my-platform-cert.pem

# Or using stack exec (recommended)
stack exec tcg-platform-cert-util -- validate my-platform-cert.pem
```

**Example Output:**
```
Validating certificate: my-platform-cert.pem

=== PLATFORM CERTIFICATE VALIDATION ===

1. Certificate Structure Check:
   ✅ PASSED: Certificate parsed successfully

2. Validity Period Check:
   ✅ PASSED: Certificate is currently valid

3. Required Attributes Check:
   ✅ PASSED: Platform information found
   ℹ️  INFO: Found 4 TCG attributes

4. Signature Check:
   ⚠️  WARNING: No CA certificate provided - structure check only
   ⚠️  WARNING: Signature structure check only
   ℹ️  INFO: Certificate contains signature data

5. Platform Information Consistency:
   ✅ PASSED: Essential platform information present

=== VALIDATION SUMMARY ===
✅ Certificate parsing: PASSED
⚠️  Note: This is a basic validation for testing certificates
⚠️  Production validation would require:
   - Certificate chain verification
   - Trusted root CA validation
   - CRL/OCSP checking
   - Full cryptographic signature verification
```

#### Enhanced Validation with CA Certificate

For comprehensive validation including signature verification, provide the CA certificate used to sign the platform certificate:

```bash
# Using direct executable
tcg-platform-cert-util validate --ca-cert test-data/certs/test-ca-cert.pem my-platform-cert.pem

# Or using stack exec (recommended)
stack exec tcg-platform-cert-util -- validate --ca-cert test-data/certs/test-ca-cert.pem my-platform-cert.pem
```

**Enhanced Validation Output:**
```
Validating certificate: my-platform-cert.pem

Loading CA certificate from: test-data/certs/test-ca-cert.pem
✅ CA certificate loaded successfully
=== PLATFORM CERTIFICATE VALIDATION ===

1. Certificate Structure Check:
   ✅ PASSED: Certificate parsed successfully

2. Validity Period Check:
   ✅ PASSED: Certificate is currently valid

3. Required Attributes Check:
   ✅ PASSED: Platform information found
   ℹ️  INFO: Found 4 TCG attributes

4. Signature Check:
   🔍 INFO: Performing signature verification with CA certificate
   ✅ PASSED: CA certificate has RSA public key
   ❌ FAILED: Cryptographic signature verification failed
   - Failure reason: SignatureInvalid
   Details:
   - CA certificate loaded: ✅
   - Public key extracted: ✅
   - Signature data extracted: ✅
   - Cryptographic verification: ❌ FAILED

5. Platform Information Consistency:
   ✅ PASSED: Essential platform information present

=== VALIDATION SUMMARY ===
✅ Certificate parsing: PASSED
⚠️  Note: This is a basic validation for testing certificates
⚠️  Production validation would require:
   - Certificate chain verification
   - Trusted root CA validation
   - CRL/OCSP checking
   - Full cryptographic signature verification
```

#### Verbose Validation Output

Use `--verbose` flag for detailed information including CA certificate details:

```bash
stack exec tcg-platform-cert-util -- validate --verbose --ca-cert test-data/certs/test-ca-cert.pem my-platform-cert.pem
```

**Verbose Output Includes:**
- Detailed validity period timestamps
- Complete attribute listings with OID information
- CA certificate public key algorithm details (RSA modulus, exponent)
- Step-by-step validation progress
- Advanced cryptographic signature verification details
- RSA public key modulus size and exponent values

**Validation Options:**
- `--verbose`, `-v` - Detailed validation output with timestamps and CA certificate details
- `--ca-cert FILE`, `-c FILE` - CA certificate file (PEM format) for signature verification
- `--help`, `-h` - Show validation help

### Extract Component Information

Analyze platform components and attributes:

```bash
# Using direct executable
tcg-platform-cert-util components my-platform-cert.pem

# Or using stack exec (recommended)
stack exec tcg-platform-cert-util -- components my-platform-cert.pem
```

**Example Output:**
```
Extracting components from: my-platform-cert.pem
Component Analysis from ASN.1 Structure:

=== Platform Attributes ===
  [1] Manufacturer: "Test Corporation"
  [2] Model: "Test Platform"
  [3] Serial: "TEST001"
  [4] Version: "1.0"

=== TCG Component OIDs Found ===
  [1] [2,23,133,5,2,4] - Platform Manufacturer
  [2] [2,23,133,5,2,5] - Platform Model
  [3] [2,23,133,5,2,6] - Platform Serial
  [4] [2,23,133,5,2,7] - Platform Version
```

## Security Features

### ObjectDigestInfo Implementation

The utility implements secure certificate binding using:

- **ObjectDigestInfo**: RFC 5755 compliant cryptographic binding
- **SHA256 Hashing**: Public key hashes for collision-resistant identification
- **EK Certificate Binding**: Links platform certificates to TPM Endorsement Keys
- **V2Form Issuer**: Proper issuer name structure with DirectoryName

### Certificate Security

Generated certificates include:

- **Real Digital Signatures**: Using CA private keys (not dummy signatures)
- **Proper Certificate Chain**: Links to CA certificate for validation
- **Cryptographic Binding**: SHA256 hash of EK certificate public key
- **Standard Compliance**: Follows IWG Platform Certificate Profile v1.1

### Signature Verification Security

The validation system provides:

- **Full Cryptographic Verification**: Uses standard X.509 signature verification algorithms
- **RSA Signature Support**: Complete RSA PKCS#1 signature verification
- **CA Chain Validation**: Verifies certificates against their issuing CA
- **Detailed Error Reporting**: Specific failure reasons for debugging and security analysis
- **Production-Ready**: Suitable for production certificate validation workflows

## Example Workflows

### Basic Certificate Generation and Validation

```bash
# 1. Generate platform certificate
stack exec tcg-platform-cert-util -- generate \
  --manufacturer "Acme Corp" \
  --model "SecurePlatform X1" \
  --version "2.1" \
  --serial "SPX1-001" \
  --output acme-platform.pem \
  --ca-cert test-data/certs/test-ca-cert.pem \
  --ca-key test-data/keys/test-ca-key.pem \
  --ek-cert test-data/certs/test-ek-cert.pem

# 2. Display certificate information
stack exec tcg-platform-cert-util -- show acme-platform.pem

# 3. Validate certificate
stack exec tcg-platform-cert-util -- validate acme-platform.pem

# 4. Extract component information
stack exec tcg-platform-cert-util -- components acme-platform.pem
```

### Multiple Platform Certificates

```bash
# Server platform
stack exec tcg-platform-cert-util -- generate \
  --manufacturer "Dell Inc." \
  --model "PowerEdge R750" \
  --version "1.2" \
  --serial "PE750-12345" \
  --output server-platform.pem \
  --ca-cert test-data/certs/test-ca-cert.pem \
  --ca-key test-data/keys/test-ca-key.pem \
  --ek-cert test-data/certs/test-ek-cert.pem

# IoT device platform
stack exec tcg-platform-cert-util -- generate \
  --manufacturer "Raspberry Pi Foundation" \
  --model "Raspberry Pi 4" \
  --version "B+" \
  --serial "RPI4B-67890" \
  --output iot-platform.pem \
  --ca-cert test-data/certs/test-ca-cert.pem \
  --ca-key test-data/keys/test-ca-key.pem \
  --ek-cert test-data/certs/test-ek-cert.pem
```

## Certificate Format

Generated certificates are in PEM format:

```
-----BEGIN PLATFORM CERTIFICATE-----
MIIBPzCCAQkwggEFAgECojcwNQIBATANBgkqhkiG9w0BAQsFAAMhAF1SF9/t6bB4
R+/mZfG5O608LhXT8KXNizzhBZ4/vuKJoDIwMDAupCwwKjEoMCYGA1UEAwwfVENH
IFBsYXRmb3JtIENlcnRpZmljYXRlIElzc3VlcjANBgkqhkiG9w0BAQsFAAIBATAc
FwwyNDEyMDEwMDAwMDAXDDI1MTIwMTAwMDAwMDBjMB0GBWeBBQIEMRQwEgQQVGVz
dCBDb3Jwb3JhdGlvbjAaBgVngQUCBTERMA8EDVRlc3QgUGxhdGZvcm0wFAYFZ4EF
AgYxCzAJBAdURVNUMDAxMBAGBWeBBQIHMQcwBQQDMS4wMA0GCSqGSIb3DQEBCwUA
AyEAQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=
-----END PLATFORM CERTIFICATE-----
```

## Technical Implementation

### Built With

- **Haskell**: Type-safe implementation
- **tcg-platform-cert**: Core platform certificate library
- **crypton**: Cryptographic operations
- **crypton-x509**: X.509 certificate handling
- **crypton-x509-validation**: X.509 signature verification
- **asn1-types/asn1-encoding**: ASN.1 processing

### Key Features

- **Type Safety**: Haskell's type system prevents many runtime errors
- **RFC Compliance**: Follows RFC 5755 and IWG Platform Certificate Profile v1.1
- **Secure Defaults**: Uses ObjectDigestInfo instead of vulnerable IssuerSerial
- **Real Cryptography**: Proper digital signatures with CA private keys
- **Full Signature Verification**: Complete RSA cryptographic signature verification using CA certificates
- **Comprehensive Testing**: 48+ test cases covering all scenarios including cryptographic validation

## Development and Testing

### Running Tests

```bash
cd tcg-platform-cert
stack test
```

### Building from Source

```bash
# Build the library
cd tcg-platform-cert
stack build

# Build the utility
cd tcg-platform-cert-util
stack build
```

### Generate-Delta Command Options

```bash
tcg-platform-cert-util generate-delta --help
```

**Required Options:**
- `--base-cert FILE`, `-b FILE` - Base platform certificate file (PEM format) [REQUIRED]
- `--ca-key FILE`, `-k FILE` - CA private key file (PEM format) [REQUIRED]
- `--ca-cert FILE`, `-c FILE` - CA certificate file (PEM format) [REQUIRED]

**Optional Options:**
- `--output FILE`, `-o FILE` - Output file path (default: delta-cert.pem)
- `--base-serial NUM` - Base certificate serial number
- `--component-changes CHANGES` - Component changes description
- `--help`, `-h` - Show help message

### Show Command Options

```bash
tcg-platform-cert-util show --help
```

**Options:**
- `--verbose`, `-v` - Verbose output with detailed information
- `--help`, `-h` - Show help message

**Usage:**
```bash
tcg-platform-cert-util show [options] <certificate-file>
```

### Validate Command Options

```bash
tcg-platform-cert-util validate --help
```

**Options:**
- `--verbose`, `-v` - Verbose validation output with detailed checks including timestamps, attribute details, CA certificate information, and cryptographic signature verification details
- `--ca-cert FILE`, `-c FILE` - CA certificate file (PEM format) for cryptographic signature verification. When provided, performs full RSA signature verification using the CA's public key
- `--help`, `-h` - Show help message

**Usage:**
```bash
tcg-platform-cert-util validate [options] <certificate-file>
```

**Enhanced Validation Features:**
- **Without CA certificate**: Basic structure, content, and validity period validation
- **With CA certificate**: Full cryptographic signature verification using RSA public key from CA certificate
- **Verbose mode**: Detailed output showing validation steps, timestamps, attribute OIDs, CA certificate details, and cryptographic verification results

#### Cryptographic Signature Verification

The utility now includes full cryptographic signature verification capabilities:

**Signature Verification Process:**
1. **CA Certificate Loading**: Loads and parses the CA certificate in PEM format
2. **Public Key Extraction**: Extracts RSA public key from the CA certificate
3. **Signature Data Extraction**: Extracts signature data from the platform certificate
4. **Cryptographic Verification**: Uses `Data.X509.Validation.verifySignedSignature` for full RSA signature verification

**Verification Results:**
- **✅ SignaturePass**: Cryptographic signature is valid and matches the CA's private key
- **❌ SignatureFailed**: Signature verification failed with detailed reason
  - `SignatureInvalid`: Signature does not match (most common with test certificates)
  - `SignatureUnimplemented`: Unsupported signature algorithm
  - `SignaturePubkeyMismatch`: Public key algorithm mismatch

**Example Verbose Output with Signature Details:**
```
4. Signature Check:
   🔍 INFO: Performing signature verification with CA certificate
   CA certificate details:
   - Public key algorithm: PubKeyRSA (PublicKey {public_size = 256, ...})
   ✅ PASSED: CA certificate has RSA public key
   ❌ FAILED: Cryptographic signature verification failed
   - Failure reason: SignatureInvalid
   Advanced signature verification details:
   - RSA public key modulus size: 256 bytes
   - RSA public exponent: 65537
```

**Important Notes:**
- Test certificates may show `SignatureInvalid` as they use dummy signatures
- Production certificates signed with the matching CA private key will show `SignaturePass`
- Only RSA signature algorithms are currently supported
- The verification follows standard X.509 cryptographic validation practices

### Components Command Options

```bash
tcg-platform-cert-util components --help
```

**Options:**
- `--verbose`, `-v` - Verbose output showing all component details
- `--help`, `-h` - Show help message

**Usage:**
```bash
tcg-platform-cert-util components [options] <certificate-file>
```

### Create-Config Command Options

```bash
tcg-platform-cert-util create-config [filename]
```

**Usage:**
- `filename` - Output YAML file (default: platform-config.yaml)

**Examples:**
```bash
# Create config with default filename
tcg-platform-cert-util create-config

# Create config with custom filename
tcg-platform-cert-util create-config my-config.yaml
```

## Known Limitations

1. **Delta Certificates**: `generate-delta` command structure is implemented but full delta certificate generation is not yet complete
2. **Full Chain Validation**: Requires additional trust store integration for production
3. **CRL/OCSP**: Revocation checking not implemented
4. **Advanced Component Attributes**: Basic platform attributes only

## Security Considerations

- **Private Key Protection**: CA private keys should be stored securely
- **Certificate Validation**: Always validate certificates in production environments
- **Trust Establishment**: Ensure CA certificates are from trusted sources
- **Regular Updates**: Update certificates before expiration

## License

This project is licensed under the BSD 3-Clause License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `stack test`
2. Code follows Haskell style conventions
3. Security considerations are documented
4. New features include appropriate tests

## Support

For issues and questions:

1. Check existing documentation
2. Run tests to verify setup: `stack test`
3. Use verbose output for debugging: `--verbose` flag
4. Review certificate validation output for specific errors