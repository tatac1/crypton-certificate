{-# LANGUAGE OverloadedStrings #-}

-- | Test vector definitions for PKITS-style AC validation tests.
--
-- This module provides:
-- * Test case data types
-- * Predefined test vectors for signature, validity, issuer, and revocation tests
-- * Utilities for building test scenarios
--
-- All test vectors are structured around the validation steps defined in
-- RFC 5755 Section 5 ("Attribute Certificate Validation"):
--   step 1: Verify the AC signature
--   step 2: Verify the AA certificate path (substeps a-d)
--   step 3: Verify the AC validity period
--   step 4: Check targeting information
--   step 5: Process any recognized critical extensions
--
-- Test ID naming convention follows PKITS (Public Key Interoperability
-- Test Suite) style:
--   AC-SIG-x.y  = Signature verification tests        (PKITS Section 4.1)
--   AC-VAL-x.y  = Validity period tests                (PKITS Section 4.2)
--   AC-ISS-x.y  = Issuer / name chaining tests         (PKITS Section 4.3)
--   AC-REV-x.y  = Revocation tests                     (PKITS Section 4.4)
--   AC-BC-x.y   = Basic constraints tests               (PKITS Section 4.6)
--   AC-KU-x.y   = Key usage tests                       (PKITS Section 4.7)
--   AC-RFC-x.y  = RFC 5755 profile conformance tests
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
--
-- Maps to the three possible outcomes of AC validation per RFC 5755 Section 5:
--   - ExpectSuccess: AC passes all validation steps
--   - ExpectError: AC fails a MUST/MUST NOT requirement (hard failure)
--   - ExpectWarning: AC passes but uses a deprecated algorithm (SHOULD NOT)
--
-- RFC 5755 Section 5 defines the following validation steps:
--   step 1: Check the AC signature
--   step 2: Check the AA certificate chain (substeps a-d)
--   step 3: Check the AC validity period
--   step 4: Check targeting information
--   step 5: Check any recognized critical extensions
--
-- A test case yields ExpectSuccess only when all five steps pass.
-- ExpectError indicates a violation of a MUST-level requirement in one of
-- those steps.  ExpectWarning indicates the AC is technically valid but uses
-- a SHOULD NOT algorithm (e.g., SHA-1) that a conforming implementation
-- ought to flag.
data TestResult
  = ExpectSuccess
  -- ^ Test should pass validation
  | ExpectError String
  -- ^ Test should fail with specific error type
  | ExpectWarning String
  -- ^ Test should pass but with warning
  deriving (Show, Eq)

-- | Test categories corresponding to PKITS sections.
--
-- Each category maps to one or more validation steps from RFC 5755 Section 5
-- and to a section of the PKITS test suite.  The mapping is:
--
--   CatSignature       -> step 1: signature verification
--   CatValidity        -> step 3: validity period checking
--   CatIssuer          -> step 2: issuer and holder name chaining
--   CatBasicConstraints -> step 2: AA certificate path validation
--   CatKeyUsage        -> step 2: AA certificate key usage checking
--   CatRevocation      -> Section 6 (Revocation): revocation status checking
--   CatRFC5755         -> steps 1-5: overall RFC 5755 profile conformance
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
--
-- Each TestCase encapsulates a single validation scenario.  The 'tcId' field
-- uses the PKITS naming convention (e.g., "AC-SIG-1.1") to uniquely identify
-- the test.  The 'tcExpected' field records the expected outcome of running
-- the AC validation algorithm (RFC 5755 Section 5) against the scenario
-- described in 'tcDescription'.
--
-- The fields are:
--   tcId          - Unique PKITS-style identifier (e.g., "AC-SIG-1.1")
--   tcName        - Short human-readable name for display
--   tcDescription - Detailed description of the validation scenario
--   tcCategory    - Which PKITS section / RFC 5755 step is being tested
--   tcExpected    - Expected validation outcome (success, error, or warning)
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

-- | Default validity start (2020-01-01 00:00:00 UTC).
--
-- RFC 5755 Section 4.2.6 (Validity):
--   AttCertValidityPeriod ::= SEQUENCE {
--     notBeforeTime  GeneralizedTime,
--     notAfterTime   GeneralizedTime
--   }
--
-- This date represents a typical start of a long-lived AC validity period.
-- Per RFC 5755: "The notBeforeTime field specifies the earliest time from
-- which the AC is deemed to be valid."
--
-- Used in: mkTestValidityPeriod, genValidity, and all static test functions.
defaultValidityStart :: DateTime
defaultValidityStart = DateTime (Date 2020 January 1) (TimeOfDay 0 0 0 0)

-- | Default validity end (2030-01-01 00:00:00 UTC).
--
-- RFC 5755 Section 4.2.6 (Validity):
--   AttCertValidityPeriod ::= SEQUENCE {
--     notBeforeTime  GeneralizedTime,
--     notAfterTime   GeneralizedTime
--   }
--
-- This date represents the end of a long-lived AC validity period.
-- Per RFC 5755: "The notAfterTime field specifies the latest time at which
-- the AC is deemed to be valid."
--
-- Used in: mkTestValidityPeriod, genValidity, and all static test functions.
defaultValidityEnd :: DateTime
defaultValidityEnd = DateTime (Date 2030 January 1) (TimeOfDay 0 0 0 0)

-- | A past DateTime (2010-01-01 00:00:00 UTC).
--
-- RFC 5755 Section 5 step 3 requires that the current time falls within the
-- AC validity period.  This value is well before 'defaultValidityStart' and
-- can be used to construct expired ACs or AA certificates whose notAfter has
-- already passed.
--
-- Used in: validity period tests (AC-VAL-*) for expired-certificate scenarios.
pastDateTime :: DateTime
pastDateTime = DateTime (Date 2010 January 1) (TimeOfDay 0 0 0 0)

-- | A future DateTime (2040-01-01 00:00:00 UTC).
--
-- RFC 5755 Section 5 step 3 requires that the current time falls within the
-- AC validity period.  This value is well after 'defaultValidityEnd' and can
-- be used to construct ACs or AA certificates whose notBefore is still in the
-- future (i.e., not yet valid).
--
-- Used in: validity period tests (AC-VAL-*) for not-yet-valid scenarios.
futureDateTime :: DateTime
futureDateTime = DateTime (Date 2040 January 1) (TimeOfDay 0 0 0 0)

-- | Current DateTime for testing (2024-06-01 12:00:00 UTC).
--
-- This is the simulated "current time" used during validation.  RFC 5755
-- Section 5 step 3 checks:
--   notBeforeTime <= currentTime <= notAfterTime
--
-- The value 2024-06-01T12:00:00Z falls within the default validity window
-- [2020-01-01, 2030-01-01], making it the normal "happy path" time.
--
-- Used in: all test categories as the reference validation time.
currentDateTime :: DateTime
currentDateTime = DateTime (Date 2024 June 1) (TimeOfDay 12 0 0 0)

-- | Add days to a DateTime.
--
-- Utility for constructing test validity periods.  Converts days to seconds
-- (days * 86400) and delegates to 'timeAdd'.
--
-- RFC 5755 Section 4.2.6 uses GeneralizedTime for validity bounds, so this
-- helper makes it straightforward to create offsets from a base time without
-- manually computing Seconds values.
--
-- Used in: test setup for boundary and offset validity period scenarios.
addDays :: DateTime -> Int -> DateTime
addDays dt days = timeAdd dt (Seconds $ fromIntegral $ days * 86400)

-- | Add years to a DateTime (approximate, 365 days per year).
--
-- Utility for constructing test validity periods spanning multiple years.
-- Uses a 365-day approximation (no leap year adjustment), which is sufficient
-- for test vector construction.
--
-- RFC 5755 Section 4.2.6 notes that validity periods are expressed as
-- GeneralizedTime; this helper is a convenient way to build multi-year
-- windows such as the default 10-year span [2020, 2030].
--
-- Used in: test setup for long-lived validity period scenarios.
addYears :: DateTime -> Int -> DateTime
addYears dt years = addDays dt (years * 365)

--------------------------------------------------------------------------------
-- Signature Test Cases (PKITS 4.1)
--------------------------------------------------------------------------------

-- | Signature Test Cases (PKITS Section 4.1)
--
-- These test vectors cover RFC 5755 Section 5 step 1:
--   "The AC signature MUST be verified.  If the signature cannot be verified,
--    the AC MUST be rejected."
--
-- Step 1 of the AC validation algorithm (RFC 5755 Section 5) verifies
-- the AC digital signature.
--
-- Additionally, the AC's ASN.1 structure (Section 4.1) requires that the
-- signature algorithm in the outer SEQUENCE match the algorithm in the
-- TBSAttributeCertificate's signature field.  Algorithm mismatches
-- constitute a MUST-level failure.
--
-- AC-SIG-1.1: Valid RSA-SHA256 signature            -> ExpectSuccess
-- AC-SIG-1.2: Corrupted signature bytes             -> ExpectError InvalidSignature
-- AC-SIG-1.3: Algorithm mismatch between AC and AA  -> ExpectError AlgorithmMismatch
-- AC-SIG-1.4: Valid DSA signature                   -> ExpectSuccess
-- AC-SIG-1.5: Valid ECDSA signature                 -> ExpectSuccess
-- AC-SIG-1.6: MD5 (weak)                            -> ExpectError WeakSignatureAlgorithm
-- AC-SIG-1.7: SHA1 (deprecated)                     -> ExpectWarning DeprecatedSignatureAlgorithm
signatureTestCases :: [TestCase]
signatureTestCases =
  [
    -- | AC-SIG-1.1: RFC 5755 Section 5 step 1 -- valid RSA-SHA256 signature.
    -- The AA's public key successfully verifies the AC signature.
    -- Expected: validation passes (all steps succeed).
    TestCase
      { tcId = "AC-SIG-1.1"
      , tcName = "Valid AC Signature"
      , tcDescription = "AC with valid RSA-SHA256 signature"
      , tcCategory = CatSignature
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-SIG-1.2: RFC 5755 Section 5 step 1 -- corrupted signature bytes.
    -- The AC signature value has been tampered with after signing.
    -- Per RFC 5755 Section 5: "If the signature cannot be verified,
    -- the AC MUST be rejected."
    -- Expected: hard failure (InvalidSignature).
    TestCase
      { tcId = "AC-SIG-1.2"
      , tcName = "Invalid AC Signature (corrupted)"
      , tcDescription = "AC signature bytes have been corrupted"
      , tcCategory = CatSignature
      , tcExpected = ExpectError "InvalidSignature"
      }
  ,
    -- | AC-SIG-1.3: RFC 5755 Section 4.1 -- algorithm OID mismatch.
    -- The signatureAlgorithm in the AC's TBSAttributeCertificate differs
    -- from the AlgorithmIdentifier in the outer SEQUENCE.  RFC 5280
    -- Section 4.1.1.2 requires these to match; RFC 5755 Section 4.1
    -- inherits this structure.
    -- Expected: hard failure (AlgorithmMismatch).
    TestCase
      { tcId = "AC-SIG-1.3"
      , tcName = "Algorithm Mismatch"
      , tcDescription = "AC signature algorithm differs from AA certificate"
      , tcCategory = CatSignature
      , tcExpected = ExpectError "AlgorithmMismatch"
      }
  ,
    -- | AC-SIG-1.4: RFC 5755 Section 5 step 1 -- valid DSA signature.
    -- DSA is a supported algorithm per implementation security policy.
    -- The AA's DSA public key successfully verifies the AC signature.
    -- Expected: validation passes.
    TestCase
      { tcId = "AC-SIG-1.4"
      , tcName = "DSA Signature Verification"
      , tcDescription = "AC with valid DSA signature"
      , tcCategory = CatSignature
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-SIG-1.5: RFC 5755 Section 5 step 1 -- valid ECDSA signature.
    -- ECDSA is a supported algorithm per implementation security policy.
    -- The AA's ECDSA public key successfully verifies the AC signature.
    -- Expected: validation passes.
    TestCase
      { tcId = "AC-SIG-1.5"
      , tcName = "ECDSA Signature Verification"
      , tcDescription = "AC with valid ECDSA signature"
      , tcCategory = CatSignature
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-SIG-1.6: Security best practices -- MD5 is cryptographically broken.
    -- MD5 MUST NOT be used for signature generation per current best practice
    -- (see also RFC 6151).  This is a MUST-level failure.
    -- Expected: hard failure (WeakSignatureAlgorithm).
    TestCase
      { tcId = "AC-SIG-1.6"
      , tcName = "MD5 Signature (weak)"
      , tcDescription = "AC with MD5 signature algorithm (cryptographically broken)"
      , tcCategory = CatSignature
      , tcExpected = ExpectError "WeakSignatureAlgorithm"
      }
  ,
    -- | AC-SIG-1.7: Security best practices -- SHA-1 is deprecated.
    -- SHA-1 SHOULD NOT be used for signature generation (see RFC 6194).
    -- The AC is technically valid but the algorithm is deprecated, so a
    -- conforming implementation SHOULD warn.
    -- Expected: warning (DeprecatedSignatureAlgorithm).
    TestCase
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

-- | Validity Period Test Cases (PKITS Section 4.2)
--
-- These test vectors cover RFC 5755 Section 5 step 3 and Section 4.2.6:
--   "The AC MUST have a valid validity period at the time of validation.
--    The notBeforeTime MUST be before the notAfterTime."
--
-- RFC 5755 Section 4.2.6 defines:
--   AttCertValidityPeriod ::= SEQUENCE {
--     notBeforeTime  GeneralizedTime,
--     notAfterTime   GeneralizedTime
--   }
--
-- Step 3 also requires checking the AA certificate's own validity period
-- (notBefore / notAfter from RFC 5280 Section 4.1.2.5), because an expired
-- or not-yet-valid AA cannot issue valid ACs.
--
-- AC-VAL-2.1: AA notBefore in the future               -> ExpectError AANotYetValid
-- AC-VAL-2.2: AA notAfter in the past                  -> ExpectError AAExpired
-- AC-VAL-2.3: AC notBeforeTime in the future            -> ExpectError ACNotYetValid
-- AC-VAL-2.4: AC notAfterTime in the past               -> ExpectError ACExpired
-- AC-VAL-2.5: Both AA and AC within validity periods    -> ExpectSuccess
-- AC-VAL-2.6: Validation time == AC notBeforeTime       -> ExpectSuccess
-- AC-VAL-2.7: Validation time == AC notAfterTime        -> ExpectSuccess
-- AC-VAL-2.8: AC using GeneralizedTime (post-2050)      -> ExpectSuccess
validityTestCases :: [TestCase]
validityTestCases =
  [
    -- | AC-VAL-2.1: RFC 5755 Section 5 step 2/step 3 -- AA not yet valid.
    -- The AA certificate's notBefore is in the future relative to the
    -- validation time.  An AA that is not yet valid cannot have issued a
    -- valid AC.
    -- Expected: hard failure (AANotYetValid).
    TestCase
      { tcId = "AC-VAL-2.1"
      , tcName = "AA Certificate Not Yet Valid"
      , tcDescription = "AA certificate notBefore is in the future"
      , tcCategory = CatValidity
      , tcExpected = ExpectError "AANotYetValid"
      }
  ,
    -- | AC-VAL-2.2: RFC 5755 Section 5 step 2/step 3 -- AA expired.
    -- The AA certificate's notAfter is in the past relative to the
    -- validation time.  An expired AA cannot have issued a currently-valid AC.
    -- Expected: hard failure (AAExpired).
    TestCase
      { tcId = "AC-VAL-2.2"
      , tcName = "AA Certificate Expired"
      , tcDescription = "AA certificate notAfter is in the past"
      , tcCategory = CatValidity
      , tcExpected = ExpectError "AAExpired"
      }
  ,
    -- | AC-VAL-2.3: RFC 5755 Section 5 step 3 / Section 4.2.6 -- AC not yet valid.
    -- The AC's notBeforeTime is in the future.  Per RFC 5755:
    --   "The current time MUST fall within the validity period."
    -- Expected: hard failure (ACNotYetValid).
    TestCase
      { tcId = "AC-VAL-2.3"
      , tcName = "AC Not Yet Valid"
      , tcDescription = "AC notBeforeTime is in the future"
      , tcCategory = CatValidity
      , tcExpected = ExpectError "ACNotYetValid"
      }
  ,
    -- | AC-VAL-2.4: RFC 5755 Section 5 step 3 / Section 4.2.6 -- AC expired.
    -- The AC's notAfterTime is in the past.  The AC has lapsed and MUST be
    -- rejected.
    -- Expected: hard failure (ACExpired).
    TestCase
      { tcId = "AC-VAL-2.4"
      , tcName = "AC Expired"
      , tcDescription = "AC notAfterTime is in the past"
      , tcCategory = CatValidity
      , tcExpected = ExpectError "ACExpired"
      }
  ,
    -- | AC-VAL-2.5: RFC 5755 Section 5 step 3 -- happy-path validity.
    -- Both the AA certificate and the AC have validity periods that contain
    -- the current validation time ('currentDateTime').
    -- Expected: validation passes.
    TestCase
      { tcId = "AC-VAL-2.5"
      , tcName = "Valid Period"
      , tcDescription = "Both AA and AC are within their validity periods"
      , tcCategory = CatValidity
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-VAL-2.6: RFC 5755 Section 5 step 3 -- boundary: start time.
    -- The validation time equals the AC's notBeforeTime exactly.  The
    -- comparison is inclusive (>=), so the AC is considered valid at the
    -- exact start boundary.
    -- Expected: validation passes.
    TestCase
      { tcId = "AC-VAL-2.6"
      , tcName = "Boundary: AC Start Time Exact"
      , tcDescription = "Validation time equals AC notBeforeTime exactly"
      , tcCategory = CatValidity
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-VAL-2.7: RFC 5755 Section 5 step 3 -- boundary: end time.
    -- The validation time equals the AC's notAfterTime exactly.  The
    -- comparison is inclusive (<=), so the AC is considered valid at the
    -- exact end boundary.
    -- Expected: validation passes.
    TestCase
      { tcId = "AC-VAL-2.7"
      , tcName = "Boundary: AC End Time Exact"
      , tcDescription = "Validation time equals AC notAfterTime exactly"
      , tcCategory = CatValidity
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-VAL-2.8: RFC 5755 Section 4.2.6 -- GeneralizedTime encoding.
    -- RFC 5755 Section 4.2.6 requires GeneralizedTime for both notBeforeTime
    -- and notAfterTime.  This test uses a date beyond 2050 to ensure the
    -- implementation handles GeneralizedTime (as opposed to UTCTime, which
    -- is limited to the range 1950-2049 per RFC 5280 Section 4.1.2.5).
    -- Expected: validation passes.
    TestCase
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

-- | Issuer Verification Test Cases (PKITS Section 4.3)
--
-- These test vectors cover RFC 5755 Section 5 step 2 and Section 4.2.3:
--   "The AC issuer field is a SEQUENCE of GeneralName.  For this profile,
--    the issuer MUST contain exactly one name, which MUST be a directoryName."
--
-- RFC 5755 Section 4.2.3 defines:
--   AttCertIssuer ::= CHOICE {
--     v1Form   GeneralNames,            -- MUST NOT be used; see Section 4.2.3
--     v2Form   [0] V2Form               -- issuerName MUST contain one DN
--   }
--
-- Step 2 requires that the AC issuer DN matches the AA certificate's
-- subject DN.  RFC 5280 Section 7.1 defines the DN matching rules,
-- including case-insensitive comparison of PrintableString attribute
-- values and insignificant whitespace handling.
--
-- AC-ISS-3.1: Issuer DN does not match AA subject DN       -> ExpectError IssuerMismatch
-- AC-ISS-3.2: RDN sequence order differs                   -> ExpectError IssuerMismatch
-- AC-ISS-3.3: Whitespace normalization (insignificant)     -> ExpectSuccess
-- AC-ISS-3.4: Case-insensitive matching                    -> ExpectSuccess
-- AC-ISS-3.5: Multiple issuer names, one matching          -> ExpectSuccess
-- AC-ISS-3.6: Holder issuerUniqueID matches AA             -> ExpectSuccess
issuerTestCases :: [TestCase]
issuerTestCases =
  [
    -- | AC-ISS-3.1: RFC 5755 Section 5 step 2 / Section 4.2.3 -- DN mismatch.
    -- The AC issuer directoryName does not match any AA certificate's
    -- subject DN.  The AC cannot be chained to a valid AA.
    -- Expected: hard failure (IssuerMismatch).
    TestCase
      { tcId = "AC-ISS-3.1"
      , tcName = "Issuer DN Mismatch"
      , tcDescription = "AC issuer DN does not match AA subject DN"
      , tcCategory = CatIssuer
      , tcExpected = ExpectError "IssuerMismatch"
      }
  ,
    -- | AC-ISS-3.2: RFC 5280 Section 7.1 -- RDN ordering.
    -- The AC issuer has the same RDN components as the AA subject, but
    -- in a different order.  Per RFC 5280 Section 7.1, DN matching is
    -- order-sensitive (each RDN in the sequence must match positionally).
    -- Expected: hard failure (IssuerMismatch).
    TestCase
      { tcId = "AC-ISS-3.2"
      , tcName = "RDN Order Different"
      , tcDescription = "AC issuer has RDNs in different order than AA subject"
      , tcCategory = CatIssuer
      , tcExpected = ExpectError "IssuerMismatch"
      }
  ,
    -- | AC-ISS-3.3: RFC 5280 Section 7.1 -- insignificant whitespace.
    -- The AC issuer DN contains extra internal whitespace that should be
    -- normalized during comparison.  Per RFC 5280 Section 7.1:
    --   "Implementations MUST ... compress internal whitespace to a single
    --    space character."
    -- Expected: validation passes (names match after normalization).
    TestCase
      { tcId = "AC-ISS-3.3"
      , tcName = "Whitespace Normalization"
      , tcDescription = "AC issuer DN with internal whitespace differences"
      , tcCategory = CatIssuer
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-ISS-3.4: RFC 5280 Section 7.1 -- case-insensitive comparison.
    -- The AC issuer DN uses different letter casing than the AA subject.
    -- Per RFC 5280 Section 7.1, PrintableString attribute values are
    -- compared case-insensitively.
    -- Expected: validation passes (names match case-insensitively).
    TestCase
      { tcId = "AC-ISS-3.4"
      , tcName = "Case Insensitive Match"
      , tcDescription = "AC issuer DN with different case"
      , tcCategory = CatIssuer
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-ISS-3.5: RFC 5755 Section 4.2.3 -- multiple issuer names.
    -- The AC contains multiple GeneralName entries in the issuer field,
    -- only one of which matches the AA subject DN.  Per RFC 5755
    -- Section 4.2.3 the issuer "MUST contain exactly one name", but this
    -- test validates that implementations can still locate a matching name
    -- when multiple are present (robustness / interoperability check).
    -- Expected: validation passes (match found among the names).
    TestCase
      { tcId = "AC-ISS-3.5"
      , tcName = "Multiple Issuer Names"
      , tcDescription = "AC with multiple issuer names, one matching"
      , tcCategory = CatIssuer
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-ISS-3.6: RFC 5755 Section 4.2.2 -- holder with issuerUniqueID.
    -- The AC holder uses the baseCertificateID form, which includes an
    -- optional issuerUniqueID.  When present, the issuerUniqueID in the
    -- holder MUST match the issuerUniqueID in the holder's PKC (RFC 5755
    -- Section 4.2.2).  This test verifies successful matching.
    -- Expected: validation passes.
    TestCase
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

-- | Basic Constraints Test Cases (PKITS Section 4.6)
--
-- These test vectors cover RFC 5755 Section 5 step 2 -- AA certificate
-- path validation -- specifically the basicConstraints extension defined
-- in RFC 5280 Section 4.2.1.9:
--   BasicConstraints ::= SEQUENCE {
--     cA                      BOOLEAN DEFAULT FALSE,
--     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
--   }
--
-- RFC 5755 Section 5 step 2 requires validation of the AA certificate
-- chain.  The AA (or any intermediate CA in the chain) MUST have a valid
-- basicConstraints extension with cA=TRUE if it issues certificates to
-- subordinate entities.
--
-- Additionally, the pathLenConstraint field limits the maximum number of
-- non-self-issued intermediate certificates that may follow a certificate
-- in a valid certification path.
--
-- AC-BC-4.1: AA missing basicConstraints entirely        -> ExpectError AANotCA
-- AC-BC-4.2: AA cA=FALSE (critical extension)            -> ExpectError AANotCA
-- AC-BC-4.3: AA cA=FALSE (non-critical extension)        -> ExpectError AANotCA
-- AC-BC-4.4: AA cA=TRUE                                  -> ExpectSuccess
-- AC-BC-4.5: Certificate chain exceeds pathLenConstraint  -> ExpectError PathTooLong
basicConstraintsTestCases :: [TestCase]
basicConstraintsTestCases =
  [
    -- | AC-BC-4.1: RFC 5280 Section 4.2.1.9 -- missing basicConstraints.
    -- The AA certificate has no basicConstraints extension at all.  Per
    -- RFC 5280, a certificate without basicConstraints MUST NOT be treated
    -- as a CA.  Without CA status the AA cannot sign ACs.
    -- Expected: hard failure (AANotCA).
    TestCase
      { tcId = "AC-BC-4.1"
      , tcName = "AA Missing Basic Constraints"
      , tcDescription = "AA certificate has no basicConstraints extension"
      , tcCategory = CatBasicConstraints
      , tcExpected = ExpectError "AANotCA"
      }
  ,
    -- | AC-BC-4.2: RFC 5280 Section 4.2.1.9 -- cA=FALSE (critical).
    -- The AA certificate has a critical basicConstraints extension with
    -- cA=FALSE.  This explicitly declares the certificate is NOT a CA.
    -- Expected: hard failure (AANotCA).
    TestCase
      { tcId = "AC-BC-4.2"
      , tcName = "AA cA=false (critical)"
      , tcDescription = "AA certificate has basicConstraints with cA=false (critical)"
      , tcCategory = CatBasicConstraints
      , tcExpected = ExpectError "AANotCA"
      }
  ,
    -- | AC-BC-4.3: RFC 5280 Section 4.2.1.9 -- cA=FALSE (non-critical).
    -- The AA certificate has a non-critical basicConstraints extension with
    -- cA=FALSE.  Even though the extension is non-critical, the cA flag is
    -- still semantically binding -- the certificate is not a CA.
    -- Expected: hard failure (AANotCA).
    TestCase
      { tcId = "AC-BC-4.3"
      , tcName = "AA cA=false (non-critical)"
      , tcDescription = "AA certificate has basicConstraints with cA=false (non-critical)"
      , tcCategory = CatBasicConstraints
      , tcExpected = ExpectError "AANotCA"
      }
  ,
    -- | AC-BC-4.4: RFC 5280 Section 4.2.1.9 -- cA=TRUE (happy path).
    -- The AA certificate has basicConstraints with cA=TRUE, confirming it
    -- is authorized to act as a CA and sign ACs.
    -- Expected: validation passes.
    TestCase
      { tcId = "AC-BC-4.4"
      , tcName = "AA cA=true"
      , tcDescription = "AA certificate has basicConstraints with cA=true"
      , tcCategory = CatBasicConstraints
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-BC-4.5: RFC 5280 Section 4.2.1.9 -- pathLenConstraint exceeded.
    -- The certificate chain from the trust anchor to the AA exceeds the
    -- pathLenConstraint specified in an intermediate CA's basicConstraints.
    -- Per RFC 5280 Section 6.1.4 step (l), this MUST cause path validation
    -- to fail.
    -- Expected: hard failure (PathTooLong).
    TestCase
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

-- | Key Usage Test Cases (PKITS Section 4.7)
--
-- These test vectors cover RFC 5755 Section 5 step 2 -- AA certificate
-- path validation -- specifically the keyUsage extension defined in
-- RFC 5280 Section 4.2.1.3:
--   KeyUsage ::= BIT STRING {
--     digitalSignature  (0),
--     ...
--     keyCertSign       (5),
--     cRLSign           (6),
--     ...
--   }
--
-- RFC 5755 Section 5 step 2 requires that the AA certificate have the
-- appropriate key usage bits set.  For signing ACs, the AA certificate
-- MUST include the keyCertSign and/or digitalSignature key usage bit.
-- For signing ACRLs (Attribute Certificate Revocation Lists), the
-- cRLSign bit MUST be present.
--
-- AC-KU-5.1: AA missing keyCertSign key usage        -> ExpectError InvalidKeyUsage
-- AC-KU-5.2: AA has appropriate key usage for ACs    -> ExpectSuccess
-- AC-KU-5.3: AA missing cRLSign for CRL validation   -> ExpectError InvalidKeyUsage
keyUsageTestCases :: [TestCase]
keyUsageTestCases =
  [
    -- | AC-KU-5.1: RFC 5280 Section 4.2.1.3 -- missing keyCertSign.
    -- The AA certificate's keyUsage extension does not include the
    -- keyCertSign bit.  Without this bit the AA is not authorized to
    -- sign certificates (including ACs).
    -- Expected: hard failure (InvalidKeyUsage).
    TestCase
      { tcId = "AC-KU-5.1"
      , tcName = "AA Missing Key Usage"
      , tcDescription = "AA certificate missing keyCertSign key usage"
      , tcCategory = CatKeyUsage
      , tcExpected = ExpectError "InvalidKeyUsage"
      }
  ,
    -- | AC-KU-5.2: RFC 5280 Section 4.2.1.3 -- valid key usage (happy path).
    -- The AA certificate has the keyCertSign (and possibly digitalSignature)
    -- key usage bit set, authorizing it to sign ACs.
    -- Expected: validation passes.
    TestCase
      { tcId = "AC-KU-5.2"
      , tcName = "AA Valid Key Usage"
      , tcDescription = "AA certificate has appropriate key usage for signing ACs"
      , tcCategory = CatKeyUsage
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-KU-5.3: RFC 5280 Section 4.2.1.3 -- missing cRLSign.
    -- The AA certificate's keyUsage extension does not include the cRLSign
    -- bit.  Without this bit the AA cannot sign CRLs, so ACRL validation
    -- (RFC 5755 Section 6, Revocation) will fail.
    -- Expected: hard failure (InvalidKeyUsage).
    TestCase
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

-- | Revocation Test Cases (PKITS Section 4.4)
--
-- These test vectors cover RFC 5755 Section 6 (Revocation):
--   "Check that the AC has not been revoked by obtaining the appropriate
--    ACRL (Attribute Certificate Revocation List), and verify that the
--    AC serial number is not listed."
--
-- RFC 5755 Section 4.3.6 specifies the noRevAvail extension:
--   id-ce-noRevAvail  OBJECT IDENTIFIER ::= { id-ce 56 }
--
-- When the noRevAvail extension is present, no revocation checking is
-- needed.  Otherwise, the relying party MUST check revocation status via
-- ACRL or OCSP.
--
-- RFC 5755 Section 6 describes the ACRL profile, based on RFC 5280
-- Section 5 (CRL profile), including:
--   - CRL signature verification
--   - CRL validity (thisUpdate / nextUpdate)
--   - Serial number lookup
--
-- AC-REV-6.1: No ACRL available for revocation checking   -> ExpectError RevocationStatusUnknown
-- AC-REV-6.2: AA certificate is listed in CRL             -> ExpectError AARevoked
-- AC-REV-6.3: AC is listed in ACRL                        -> ExpectError ACRevoked
-- AC-REV-6.4: AC is not listed in ACRL                    -> ExpectSuccess
-- AC-REV-6.5: ACRL nextUpdate is in the past              -> ExpectError CRLExpired
-- AC-REV-6.6: ACRL signature verification                 -> ExpectSuccess
revocationTestCases :: [TestCase]
revocationTestCases =
  [
    -- | AC-REV-6.1: RFC 5755 Section 6 (Revocation) -- no ACRL available.
    -- The AC does not carry the noRevAvail extension, and no ACRL can be
    -- obtained from the distribution points.  The relying party cannot
    -- determine revocation status.
    -- Expected: hard failure (RevocationStatusUnknown).
    TestCase
      { tcId = "AC-REV-6.1"
      , tcName = "ACRL Missing"
      , tcDescription = "No ACRL available for revocation checking"
      , tcCategory = CatRevocation
      , tcExpected = ExpectError "RevocationStatusUnknown"
      }
  ,
    -- | AC-REV-6.2: RFC 5755 Section 5 step 2 / Section 6 (Revocation) -- AA certificate revoked.
    -- The AA certificate itself has been revoked (appears on the PKC CRL).
    -- A revoked AA cannot issue valid ACs.
    -- Expected: hard failure (AARevoked).
    TestCase
      { tcId = "AC-REV-6.2"
      , tcName = "AA Certificate Revoked"
      , tcDescription = "AA certificate is listed in CRL"
      , tcCategory = CatRevocation
      , tcExpected = ExpectError "AARevoked"
      }
  ,
    -- | AC-REV-6.3: RFC 5755 Section 6 (Revocation) -- AC revoked.
    -- The AC serial number appears on the ACRL.  Per RFC 5755 Section 5:
    --   "If the AC serial number is listed on the ACRL, the AC MUST be
    --    rejected."
    -- Expected: hard failure (ACRevoked).
    TestCase
      { tcId = "AC-REV-6.3"
      , tcName = "AC Revoked"
      , tcDescription = "AC is listed in ACRL"
      , tcCategory = CatRevocation
      , tcExpected = ExpectError "ACRevoked"
      }
  ,
    -- | AC-REV-6.4: RFC 5755 Section 6 (Revocation) -- AC not revoked (happy path).
    -- The ACRL is available, its signature verifies, and the AC serial
    -- number is not listed.  Revocation checking passes.
    -- Expected: validation passes.
    TestCase
      { tcId = "AC-REV-6.4"
      , tcName = "AC Not Revoked"
      , tcDescription = "AC is not listed in ACRL"
      , tcCategory = CatRevocation
      , tcExpected = ExpectSuccess
      }
  ,
    -- | AC-REV-6.5: RFC 5280 Section 5.1.2.5 (via RFC 5755 Section 6) -- expired CRL.
    -- The ACRL's nextUpdate field is in the past, meaning the CRL is stale.
    -- Per RFC 5280 Section 6.3: "If the current time is after the value of
    -- the nextUpdate field, then a new CRL SHOULD be obtained."  When no
    -- fresh CRL is available, revocation status is indeterminate.
    -- Expected: hard failure (CRLExpired).
    TestCase
      { tcId = "AC-REV-6.5"
      , tcName = "ACRL Expired"
      , tcDescription = "ACRL nextUpdate is in the past"
      , tcCategory = CatRevocation
      , tcExpected = ExpectError "CRLExpired"
      }
  ,
    -- | AC-REV-6.6: RFC 5755 Section 6 / RFC 5280 Section 6.3 -- CRL signature.
    -- The ACRL signature is verified using the AA's public key.  This
    -- confirms that the CRL was issued by the expected authority and has
    -- not been tampered with.
    -- Expected: validation passes (CRL signature is valid).
    TestCase
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

-- | RFC 5755 Profile Conformance Test Cases
--
-- These test vectors cover specific MUST/MUST NOT constraints from the
-- RFC 5755 attribute certificate profile that are not covered by the
-- generic PKITS categories above.  They exercise structural validation
-- of the AC fields themselves, rather than cryptographic or temporal checks.
--
-- Key RFC 5755 sections tested:
--
--   Section 4.2.3 (Issuer):
--     "The v1Form choice MUST NOT be used."
--     "If the v2Form is used, only the issuerName component MUST be present."
--     "The v2Form MUST NOT contain baseCertificateID or objectDigestInfo."
--
--   Section 4.2.5 (Serial Number):
--     "The serialNumber field MUST contain a positive integer no longer
--      than 20 octets."
--
--   Section 4.2.2 (Holder):
--     "At least one of the Holder fields MUST be present."
--
-- AC-RFC-8.1: v1Form issuer used (prohibited)                -> ExpectError V1FormNotAllowed
-- AC-RFC-8.2: V2Form with baseCertificateID (prohibited)     -> ExpectError V2FormBaseCertificateIDPresent
-- AC-RFC-8.3: V2Form with objectDigestInfo (prohibited)      -> ExpectError V2FormObjectDigestInfoPresent
-- AC-RFC-8.4: Serial number exceeds 20 octets                -> ExpectError SerialNumberTooLong
-- AC-RFC-8.5: Holder has no fields set (all Nothing)         -> ExpectError HolderMissingAllFields
rfc5755TestCases :: [TestCase]
rfc5755TestCases =
  [
    -- | AC-RFC-8.1: RFC 5755 Section 4.2.3 -- v1Form issuer prohibited.
    -- The AC uses the v1Form choice of AttCertIssuer.  Per RFC 5755
    -- Section 4.2.3: "Conformant ACs MUST NOT use the v1Form."
    -- Expected: hard failure (V1FormNotAllowed).
    TestCase
      { tcId = "AC-RFC-8.1"
      , tcName = "v1Form Used"
      , tcDescription = "AC uses v1Form issuer (prohibited by RFC 5755)"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "V1FormNotAllowed"
      }
  ,
    -- | AC-RFC-8.2: RFC 5755 Section 4.2.3 -- V2Form with baseCertificateID.
    -- The AC's V2Form issuer contains a baseCertificateID component.
    -- Per RFC 5755 Section 4.2.3: "The issuer field MUST use the v2Form
    -- alternative.  The issuerName component MUST be present; the
    -- baseCertificateID and objectDigestInfo components MUST NOT be present."
    -- Expected: hard failure (V2FormBaseCertificateIDPresent).
    TestCase
      { tcId = "AC-RFC-8.2"
      , tcName = "V2Form baseCertificateID Present"
      , tcDescription = "V2Form contains baseCertificateID (prohibited)"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "V2FormBaseCertificateIDPresent"
      }
  ,
    -- | AC-RFC-8.3: RFC 5755 Section 4.2.3 -- V2Form with objectDigestInfo.
    -- The AC's V2Form issuer contains an objectDigestInfo component.
    -- Per RFC 5755 Section 4.2.3: "The baseCertificateID and
    -- objectDigestInfo components MUST NOT be present."
    -- Expected: hard failure (V2FormObjectDigestInfoPresent).
    TestCase
      { tcId = "AC-RFC-8.3"
      , tcName = "V2Form objectDigestInfo Present"
      , tcDescription = "V2Form contains objectDigestInfo (prohibited)"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "V2FormObjectDigestInfoPresent"
      }
  ,
    -- | AC-RFC-8.4: RFC 5755 Section 4.2.5 -- serial number length constraint.
    -- The AC serialNumber field contains a value that encodes to more than
    -- 20 octets.  Per RFC 5755 Section 4.2.5: "The serialNumber field MUST
    -- contain a positive integer no longer than 20 octets."
    -- Expected: hard failure (SerialNumberTooLong).
    TestCase
      { tcId = "AC-RFC-8.4"
      , tcName = "Serial Number Too Long"
      , tcDescription = "AC serialNumber exceeds 20 octets"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "SerialNumberTooLong"
      }
  ,
    -- | AC-RFC-8.5: RFC 5755 Section 4.2.2 -- holder must have at least one field.
    -- The AC's Holder has all three optional fields set to Nothing
    -- (baseCertificateID, entityName, objectDigestInfo).  Per RFC 5755
    -- Section 4.2.2: "For this profile, either baseCertificateID or
    -- entityName MUST be present."
    -- Expected: hard failure (HolderMissingAllFields).
    TestCase
      { tcId = "AC-RFC-8.5"
      , tcName = "Holder All Fields Empty"
      , tcDescription = "AC holder has no fields set (all Nothing)"
      , tcCategory = CatRFC5755
      , tcExpected = ExpectError "HolderMissingAllFields"
      }
  ]
