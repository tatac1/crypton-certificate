{-# LANGUAGE OverloadedStrings #-}

-- | Test vector definitions for PKITS-style AC validation tests.
--
-- This module provides:
-- * Test case data types
-- * Predefined test vectors for signature, validity, issuer, and revocation tests
-- * Utilities for building test scenarios
module TestVectors
  ( -- * Test Case Types
    TestCase (..),
    TestResult (..),
    TestCategory (..),

    -- * Test Vector Collections
    signatureTestCases,
    validityTestCases,
    issuerTestCases,
    basicConstraintsTestCases,
    keyUsageTestCases,
    revocationTestCases,
    rfc5755TestCases,

    -- * DateTime utilities
    defaultValidityStart,
    defaultValidityEnd,
    pastDateTime,
    futureDateTime,
    currentDateTime,
    addDays,
    addYears,
  )
where

import Data.Hourglass

--------------------------------------------------------------------------------
-- Test Case Types
--------------------------------------------------------------------------------

-- | Expected result of a test case.
data TestResult
  = ExpectSuccess
  -- ^ Test should pass validation
  | ExpectError String
  -- ^ Test should fail with specific error type
  | ExpectWarning String
  -- ^ Test should pass but with warning
  deriving (Show, Eq)

-- | Test categories corresponding to PKITS sections.
data TestCategory
  = CatSignature       -- ^ 4.1 Signature Verification (AC-SIG-*)
  | CatValidity        -- ^ 4.2 Validity Periods (AC-VAL-*)
  | CatIssuer          -- ^ 4.3 Issuer/Name Chaining (AC-ISS-*)
  | CatBasicConstraints -- ^ 4.6 Basic Constraints (AC-BC-*)
  | CatKeyUsage        -- ^ 4.7 Key Usage (AC-KU-*)
  | CatRevocation      -- ^ 4.4 Revocation (AC-REV-*)
  | CatRFC5755         -- ^ RFC 5755 Profile (AC-RFC-*)
  deriving (Show, Eq, Enum, Bounded)

-- | A test case definition.
data TestCase = TestCase
  { tcId :: String
  -- ^ Unique test ID (e.g., "AC-SIG-1.1")
  , tcName :: String
  -- ^ Human-readable test name
  , tcDescription :: String
  -- ^ Detailed description of what the test verifies
  , tcCategory :: TestCategory
  -- ^ Test category
  , tcExpected :: TestResult
  -- ^ Expected result
  }
  deriving (Show, Eq)

--------------------------------------------------------------------------------
-- DateTime utilities
--------------------------------------------------------------------------------

-- | Default validity start (2020-01-01)
defaultValidityStart :: DateTime
defaultValidityStart = DateTime (Date 2020 January 1) (TimeOfDay 0 0 0 0)

-- | Default validity end (2030-01-01)
defaultValidityEnd :: DateTime
defaultValidityEnd = DateTime (Date 2030 January 1) (TimeOfDay 0 0 0 0)

-- | A past DateTime (2010-01-01)
pastDateTime :: DateTime
pastDateTime = DateTime (Date 2010 January 1) (TimeOfDay 0 0 0 0)

-- | A future DateTime (2040-01-01)
futureDateTime :: DateTime
futureDateTime = DateTime (Date 2040 January 1) (TimeOfDay 0 0 0 0)

-- | Current DateTime for testing (2024-06-01)
currentDateTime :: DateTime
currentDateTime = DateTime (Date 2024 June 1) (TimeOfDay 12 0 0 0)

-- | Add days to a DateTime.
addDays :: DateTime -> Int -> DateTime
addDays dt days = timeAdd dt (Seconds $ fromIntegral $ days * 86400)

-- | Add years to a DateTime (approximate, 365 days per year).
addYears :: DateTime -> Int -> DateTime
addYears dt years = addDays dt (years * 365)

--------------------------------------------------------------------------------
-- Signature Test Cases (PKITS 4.1)
--------------------------------------------------------------------------------

signatureTestCases :: [TestCase]
signatureTestCases =
  [ TestCase
      { tcId = "AC-SIG-1.1"
      , tcName = "Valid AC Signature"
      , tcDescription = "AC with valid RSA-SHA256 signature"
      , tcCategory = CatSignature
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-SIG-1.2"
      , tcName = "Invalid AC Signature (corrupted)"
      , tcDescription = "AC signature bytes have been corrupted"
      , tcCategory = CatSignature
      , tcExpected = ExpectError "InvalidSignature"
      }
  , TestCase
      { tcId = "AC-SIG-1.3"
      , tcName = "Algorithm Mismatch"
      , tcDescription = "AC signature algorithm differs from AA certificate"
      , tcCategory = CatSignature
      , tcExpected = ExpectError "AlgorithmMismatch"
      }
  , TestCase
      { tcId = "AC-SIG-1.4"
      , tcName = "DSA Signature Verification"
      , tcDescription = "AC with valid DSA signature"
      , tcCategory = CatSignature
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-SIG-1.5"
      , tcName = "ECDSA Signature Verification"
      , tcDescription = "AC with valid ECDSA signature"
      , tcCategory = CatSignature
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-SIG-1.6"
      , tcName = "MD5 Signature (weak)"
      , tcDescription = "AC with MD5 signature algorithm (cryptographically broken)"
      , tcCategory = CatSignature
      , tcExpected = ExpectError "WeakSignatureAlgorithm"
      }
  , TestCase
      { tcId = "AC-SIG-1.7"
      , tcName = "SHA1 Signature (deprecated)"
      , tcDescription = "AC with SHA1 signature algorithm (deprecated)"
      , tcCategory = CatSignature
      , tcExpected = ExpectWarning "DeprecatedSignatureAlgorithm"
      }
  ]

--------------------------------------------------------------------------------
-- Validity Period Test Cases (PKITS 4.2)
--------------------------------------------------------------------------------

validityTestCases :: [TestCase]
validityTestCases =
  [ TestCase
      { tcId = "AC-VAL-2.1"
      , tcName = "AA Certificate Not Yet Valid"
      , tcDescription = "AA certificate notBefore is in the future"
      , tcCategory = CatValidity
      , tcExpected = ExpectError "AANotYetValid"
      }
  , TestCase
      { tcId = "AC-VAL-2.2"
      , tcName = "AA Certificate Expired"
      , tcDescription = "AA certificate notAfter is in the past"
      , tcCategory = CatValidity
      , tcExpected = ExpectError "AAExpired"
      }
  , TestCase
      { tcId = "AC-VAL-2.3"
      , tcName = "AC Not Yet Valid"
      , tcDescription = "AC notBeforeTime is in the future"
      , tcCategory = CatValidity
      , tcExpected = ExpectError "ACNotYetValid"
      }
  , TestCase
      { tcId = "AC-VAL-2.4"
      , tcName = "AC Expired"
      , tcDescription = "AC notAfterTime is in the past"
      , tcCategory = CatValidity
      , tcExpected = ExpectError "ACExpired"
      }
  , TestCase
      { tcId = "AC-VAL-2.5"
      , tcName = "Valid Period"
      , tcDescription = "Both AA and AC are within their validity periods"
      , tcCategory = CatValidity
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-VAL-2.6"
      , tcName = "Boundary: AC Start Time Exact"
      , tcDescription = "Validation time equals AC notBeforeTime exactly"
      , tcCategory = CatValidity
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-VAL-2.7"
      , tcName = "Boundary: AC End Time Exact"
      , tcDescription = "Validation time equals AC notAfterTime exactly"
      , tcCategory = CatValidity
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-VAL-2.8"
      , tcName = "GeneralizedTime Format"
      , tcDescription = "AC using GeneralizedTime format (post-2050)"
      , tcCategory = CatValidity
      , tcExpected = ExpectSuccess
      }
  ]

--------------------------------------------------------------------------------
-- Issuer Verification Test Cases (PKITS 4.3)
--------------------------------------------------------------------------------

issuerTestCases :: [TestCase]
issuerTestCases =
  [ TestCase
      { tcId = "AC-ISS-3.1"
      , tcName = "Issuer DN Mismatch"
      , tcDescription = "AC issuer DN does not match AA subject DN"
      , tcCategory = CatIssuer
      , tcExpected = ExpectError "IssuerMismatch"
      }
  , TestCase
      { tcId = "AC-ISS-3.2"
      , tcName = "RDN Order Different"
      , tcDescription = "AC issuer has RDNs in different order than AA subject"
      , tcCategory = CatIssuer
      , tcExpected = ExpectError "IssuerMismatch"
      }
  , TestCase
      { tcId = "AC-ISS-3.3"
      , tcName = "Whitespace Normalization"
      , tcDescription = "AC issuer DN with internal whitespace differences"
      , tcCategory = CatIssuer
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-ISS-3.4"
      , tcName = "Case Insensitive Match"
      , tcDescription = "AC issuer DN with different case"
      , tcCategory = CatIssuer
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-ISS-3.5"
      , tcName = "Multiple Issuer Names"
      , tcDescription = "AC with multiple issuer names, one matching"
      , tcCategory = CatIssuer
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-ISS-3.6"
      , tcName = "IssuerUniqueID Match"
      , tcDescription = "AC holder with issuerUniqueID matching AA"
      , tcCategory = CatIssuer
      , tcExpected = ExpectSuccess
      }
  ]

--------------------------------------------------------------------------------
-- Basic Constraints Test Cases (PKITS 4.6)
--------------------------------------------------------------------------------

basicConstraintsTestCases :: [TestCase]
basicConstraintsTestCases =
  [ TestCase
      { tcId = "AC-BC-4.1"
      , tcName = "AA Missing Basic Constraints"
      , tcDescription = "AA certificate has no basicConstraints extension"
      , tcCategory = CatBasicConstraints
      , tcExpected = ExpectError "AANotCA"
      }
  , TestCase
      { tcId = "AC-BC-4.2"
      , tcName = "AA cA=false (critical)"
      , tcDescription = "AA certificate has basicConstraints with cA=false (critical)"
      , tcCategory = CatBasicConstraints
      , tcExpected = ExpectError "AANotCA"
      }
  , TestCase
      { tcId = "AC-BC-4.3"
      , tcName = "AA cA=false (non-critical)"
      , tcDescription = "AA certificate has basicConstraints with cA=false (non-critical)"
      , tcCategory = CatBasicConstraints
      , tcExpected = ExpectError "AANotCA"
      }
  , TestCase
      { tcId = "AC-BC-4.4"
      , tcName = "AA cA=true"
      , tcDescription = "AA certificate has basicConstraints with cA=true"
      , tcCategory = CatBasicConstraints
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-BC-4.5"
      , tcName = "Path Length Exceeded"
      , tcDescription = "Certificate chain exceeds pathLenConstraint"
      , tcCategory = CatBasicConstraints
      , tcExpected = ExpectError "PathTooLong"
      }
  ]

--------------------------------------------------------------------------------
-- Key Usage Test Cases (PKITS 4.7)
--------------------------------------------------------------------------------

keyUsageTestCases :: [TestCase]
keyUsageTestCases =
  [ TestCase
      { tcId = "AC-KU-5.1"
      , tcName = "AA Missing Key Usage"
      , tcDescription = "AA certificate missing keyCertSign key usage"
      , tcCategory = CatKeyUsage
      , tcExpected = ExpectError "InvalidKeyUsage"
      }
  , TestCase
      { tcId = "AC-KU-5.2"
      , tcName = "AA Valid Key Usage"
      , tcDescription = "AA certificate has appropriate key usage for signing ACs"
      , tcCategory = CatKeyUsage
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-KU-5.3"
      , tcName = "AA Missing cRLSign"
      , tcDescription = "AA certificate missing cRLSign for CRL validation"
      , tcCategory = CatKeyUsage
      , tcExpected = ExpectError "InvalidKeyUsage"
      }
  ]

--------------------------------------------------------------------------------
-- Revocation Test Cases (PKITS 4.4)
--------------------------------------------------------------------------------

revocationTestCases :: [TestCase]
revocationTestCases =
  [ TestCase
      { tcId = "AC-REV-6.1"
      , tcName = "ACRL Missing"
      , tcDescription = "No ACRL available for revocation checking"
      , tcCategory = CatRevocation
      , tcExpected = ExpectError "RevocationStatusUnknown"
      }
  , TestCase
      { tcId = "AC-REV-6.2"
      , tcName = "AA Certificate Revoked"
      , tcDescription = "AA certificate is listed in CRL"
      , tcCategory = CatRevocation
      , tcExpected = ExpectError "AARevoked"
      }
  , TestCase
      { tcId = "AC-REV-6.3"
      , tcName = "AC Revoked"
      , tcDescription = "AC is listed in ACRL"
      , tcCategory = CatRevocation
      , tcExpected = ExpectError "ACRevoked"
      }
  , TestCase
      { tcId = "AC-REV-6.4"
      , tcName = "AC Not Revoked"
      , tcDescription = "AC is not listed in ACRL"
      , tcCategory = CatRevocation
      , tcExpected = ExpectSuccess
      }
  , TestCase
      { tcId = "AC-REV-6.5"
      , tcName = "ACRL Expired"
      , tcDescription = "ACRL nextUpdate is in the past"
      , tcCategory = CatRevocation
      , tcExpected = ExpectError "CRLExpired"
      }
  , TestCase
      { tcId = "AC-REV-6.6"
      , tcName = "ACRL Signature Verification"
      , tcDescription = "ACRL signature verification"
      , tcCategory = CatRevocation
      , tcExpected = ExpectSuccess
      }
  ]

--------------------------------------------------------------------------------
-- RFC 5755 Profile Test Cases
--------------------------------------------------------------------------------

rfc5755TestCases :: [TestCase]
rfc5755TestCases =
  [ TestCase
      { tcId = "AC-RFC-8.1"
      , tcName = "v1Form Used"
      , tcDescription = "AC uses v1Form issuer (prohibited by RFC 5755)"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "V1FormNotAllowed"
      }
  , TestCase
      { tcId = "AC-RFC-8.2"
      , tcName = "V2Form baseCertificateID Present"
      , tcDescription = "V2Form contains baseCertificateID (prohibited)"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "V2FormBaseCertificateIDPresent"
      }
  , TestCase
      { tcId = "AC-RFC-8.3"
      , tcName = "V2Form objectDigestInfo Present"
      , tcDescription = "V2Form contains objectDigestInfo (prohibited)"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "V2FormObjectDigestInfoPresent"
      }
  , TestCase
      { tcId = "AC-RFC-8.4"
      , tcName = "Serial Number Too Long"
      , tcDescription = "AC serialNumber exceeds 20 octets"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "SerialNumberTooLong"
      }
  , TestCase
      { tcId = "AC-RFC-8.5"
      , tcName = "Holder All Fields Empty"
      , tcDescription = "AC holder has no fields set (all Nothing)"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "HolderMissingAllFields"
      }
  ]

