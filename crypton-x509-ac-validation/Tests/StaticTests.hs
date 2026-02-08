{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | PKITS-style static tests for AC validation.
--
-- This module contains test cases based on NIST PKITS (Public Key
-- Interoperability Test Suite) adapted for Attribute Certificate validation.
module StaticTests
  ( staticTests,
  )
where

import Certificate
import Data.Hourglass
import Data.X509
import Data.X509.AC.Validation
import Data.X509.AC.Validation.Path
import Data.X509.AC.Validation.Revocation
import Data.X509.AC.Validation.Signature
import Data.X509.AC.Validation.Validity
import Data.X509.AttCert
import Data.X509.Attribute
import Test.Tasty
import Test.Tasty.HUnit
import TestVectors

-- | All Static Test Groups (PKITS-Style)
--
-- RFC 5755 Section 5 (AC Validation):
--   Defines the full validation procedure for Attribute Certificates,
--   encompassing signature verification, validity period checking,
--   issuer path validation, revocation status, and profile conformance.
--
-- This top-level group aggregates all PKITS-style test categories:
--   - AC-SIG-*: Signature verification (Section 5 Step 1)
--   - AC-VAL-*: Validity period checking (Section 5 Step 3, Section 4.2.6)
--   - AC-ISS-*: Issuer verification (Section 5 Step 2, Section 4.2.3)
--   - AC-BC-*:  Basic constraints on the AA (Section 5 Step 2)
--   - AC-KU-*:  Key usage on the AA (Section 5 Step 2)
--   - AC-REV-*: Revocation checking (Section 6)
--   - AC-RFC-*: RFC 5755 profile conformance (Section 4)
staticTests :: TestTree
staticTests =
  testGroup
    "PKITS-Style Static Tests"
    [ signatureTests,
      validityTests,
      issuerTests,
      basicConstraintsTests,
      keyUsageTests,
      revocationTests,
      rfc5755Tests
    ]

--------------------------------------------------------------------------------
-- Signature Verification Tests (AC-SIG-*)
--------------------------------------------------------------------------------

-- | Signature Verification Tests (AC-SIG-*)
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 1: "Check the signature on the AC by:
--     1. Using the AA's public key and the appropriate algorithm
--     2. Verifying that the value of the signature is valid"
--
-- Algorithm policy (implementation security policy, per RFC 5755 Section 8):
--   SHA256 with RSA: accepted (RECOMMENDED)
--   SHA1 with RSA: deprecated (SHOULD NOT be used for new ACs)
--   MD5 with RSA: rejected (MUST NOT be used)
--
-- These tests verify that the signature verification engine correctly
-- distinguishes between valid, deprecated, and weak algorithms, matching
-- the algorithm tiers enforced by the implementation's security policy.
signatureTests :: TestTree
signatureTests =
  testGroup
    "Signature Verification (AC-SIG-*)"
    [ testCase "AC-SIG-1.1: Valid AC Signature (RSA-SHA256)" testValidSignature,
      testCase "AC-SIG-1.6: MD5 Signature (weak) - rejected" testWeakMD5Signature,
      testCase "AC-SIG-1.7: SHA1 Signature (deprecated) - warning" testDeprecatedSHA1Signature
    ]

-- | AC-SIG-1.1: Valid AC Signature (RSA-SHA256)
--
-- Algorithm policy (implementation security policy, per RFC 5755 Section 8):
--   Algorithm strength is enforced as an implementation security policy.
--   RFC 5755 defers to RFC 5280 for algorithm usage guidance.
--
-- RFC 5280 Section 7.1.3:
--   "The signature algorithm field MUST contain the same algorithm identifier
--    as the signatureAlgorithm field in the sequence TBSCertificate"
--
-- Test scenario:
--   1. Generate RSA-2048 key pair with SHA256 hash
--   2. Create an AA certificate (self-signed) using the key pair
--   3. Create an AC signed by the AA's private key
--   4. Verify the AC signature using the AA's public key
--
-- What is verified:
--   verifyACSignature returns SigSuccess for a correctly signed AC.
--   This confirms that the RSA-SHA256 signature chain (AA key -> AC signature)
--   is valid when both certificates use the same key pair and algorithm.
--
-- Expected: SigSuccess
-- What would fail: SigError if the signature bytes don't match,
--   SigWarning if the algorithm is deprecated but accepted.
-- NOT verified: Whether signature verification fails for corrupted
--   signatures -- that would be AC-SIG-1.2.
testValidSignature :: Assertion
testValidSignature = do
  -- Generate AA keys and certificate
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  -- Create AC signed by AA
  let holder = mkTestHolder (pairSignedCert aaPair)
  let validity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 1 validity (Attributes []) []

  -- Extract public key from AA certificate
  let aaCert = signedObject (getSigned (pairSignedCert aaPair))
  let pubKey = certPubKey aaCert

  -- Verify signature
  case verifyACSignature pubKey (acpSignedAC acPair) of
    SigSuccess -> return ()
    SigWarning w -> assertFailure $ "Expected success but got warning: " ++ show w
    SigError e -> assertFailure $ "Expected success but got error: " ++ show e

-- | AC-SIG-1.6: MD5 Signature (weak) - rejected
--
-- Algorithm policy (implementation security policy, per RFC 5755 Section 8):
--   Algorithm strength is enforced as an implementation security policy.
--   RFC 5755 defers to RFC 5280 for algorithm usage guidance.
--
-- RFC 6151 (Updated Security Considerations for the MD5 Message-Digest
--   and the HMAC-MD5 Algorithms):
--   "Attacks on MD5 have advanced to the point that it is no longer
--    acceptable for use where collision resistance is required"
--
-- Test scenario:
--   1. Generate RSA-2048 key pair with MD5 hash (a known weak algorithm)
--   2. Create an AA certificate signed with RSA-MD5
--   3. Create an AC signed by the AA with RSA-MD5
--   4. Attempt to verify the AC signature
--
-- What is verified:
--   verifyACSignature returns SigError (SigWeakAlgorithm "MD5") for an AC
--   signed with the MD5 algorithm. The algorithm name in the error must be
--   exactly "MD5".
--
-- Expected: SigError (SigWeakAlgorithm "MD5")
-- What would fail: SigSuccess if the implementation does not reject MD5,
--   SigWarning if it only warns instead of rejecting.
-- NOT verified: Whether other weak algorithms (e.g., SHA-0) are also
--   rejected -- that would require separate test vectors.
testWeakMD5Signature :: Assertion
testWeakMD5Signature = do
  -- Generate AA keys with MD5 (weak algorithm)
  aaKeys <- generateKeys (AlgRSA 2048 hashMD5)
  aaPair <- mkAA 1 "Test AA MD5" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let validity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 1 validity (Attributes []) []

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))
  let pubKey = certPubKey aaCert

  case verifyACSignature pubKey (acpSignedAC acPair) of
    SigError (SigWeakAlgorithm alg) ->
      assertEqual "Algorithm should be MD5" "MD5" alg
    SigSuccess -> assertFailure "Expected weak algorithm error but got success"
    SigWarning _ -> assertFailure "Expected weak algorithm error but got warning"
    SigError e -> assertFailure $ "Unexpected error: " ++ show e

-- | AC-SIG-1.7: SHA1 Signature (deprecated) - warning
--
-- Algorithm policy (implementation security policy, per RFC 5755 Section 8):
--   Algorithm strength is enforced as an implementation security policy.
--   RFC 5755 defers to RFC 5280 for algorithm usage guidance.
--
-- NIST SP 800-131A Revision 2 (Transitioning Use of Cryptographic Algorithms):
--   SHA-1 for digital signature generation is disallowed after 2013.
--   SHA-1 for digital signature verification is deprecated (legacy use only).
--
-- Test scenario:
--   1. Generate RSA-2048 key pair with SHA1 hash (a deprecated algorithm)
--   2. Create an AA certificate signed with RSA-SHA1
--   3. Create an AC signed by the AA with RSA-SHA1
--   4. Attempt to verify the AC signature
--
-- What is verified:
--   verifyACSignature returns SigWarning (SigDeprecatedAlgorithm "SHA1") for
--   an AC signed with the SHA1 algorithm. SHA1 is not outright rejected (it
--   may still be encountered in legacy environments), but a warning is raised
--   to alert the relying party.
--
-- Expected: SigWarning (SigDeprecatedAlgorithm "SHA1")
-- What would fail: SigSuccess if the implementation silently accepts SHA1,
--   SigError if it rejects SHA1 outright.
-- NOT verified: Whether the warning is propagated correctly to the full
--   AC validation pipeline -- that is tested at the integration level.
testDeprecatedSHA1Signature :: Assertion
testDeprecatedSHA1Signature = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA1)
  aaPair <- mkAA 1 "Test AA SHA1" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let validity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 1 validity (Attributes []) []

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))
  let pubKey = certPubKey aaCert

  case verifyACSignature pubKey (acpSignedAC acPair) of
    SigWarning (SigDeprecatedAlgorithm alg) ->
      assertEqual "Algorithm should be SHA1" "SHA1" alg
    SigSuccess -> assertFailure "Expected deprecated warning but got success"
    SigError e -> assertFailure $ "Expected warning but got error: " ++ show e

--------------------------------------------------------------------------------
-- Validity Period Tests (AC-VAL-*)
--------------------------------------------------------------------------------

-- | Validity Period Tests (AC-VAL-*)
--
-- RFC 5755 Section 4.2.6 (Attribute Certificate Validity):
--   "The attrCertValidityPeriod field specifies the period for which the
--    AC issuer expects the binding between the holder and the attributes
--    fields to be valid."
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 3: "Check that the current date/time is within the validity
--    period of the AC."
--
-- RFC 5755 Section 4.2.6 (GeneralizedTime encoding):
--   "The notBeforeTime and notAfterTime fields are of type GeneralizedTime.
--    GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu)."
--
-- These tests verify boundary conditions and failure cases for the
-- AC validity period: not-yet-valid, expired, within-range, and
-- exact boundary at notBeforeTime.
validityTests :: TestTree
validityTests =
  testGroup
    "Validity Period (AC-VAL-*)"
    [ testCase "AC-VAL-2.3: AC Not Yet Valid" testACNotYetValid,
      testCase "AC-VAL-2.4: AC Expired" testACExpired,
      testCase "AC-VAL-2.5: Valid Period" testValidPeriod,
      testCase "AC-VAL-2.6: Boundary - AC Start Time Exact" testBoundaryStart
    ]

-- | AC-VAL-2.3: AC Not Yet Valid
--
-- RFC 5755 Section 4.2.6 (Attribute Certificate Validity):
--   "The attrCertValidityPeriod field specifies the period for which the
--    AC issuer expects the binding between the holder and the attributes
--    fields to be valid."
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 3: "Check that the current date/time is within the validity
--    period of the AC."
--   An AC whose notBeforeTime is in the future relative to the validation
--   time MUST be rejected.
--
-- Test scenario:
--   1. Generate RSA-2048 AA key pair and certificate with a wide validity window
--   2. Create an AC whose notBeforeTime is set to a future date
--   3. Validate the AC at the current time (which is before notBeforeTime)
--
-- What is verified:
--   validateACValidity returns ValidityFailed (ACNotYetValid ...) when the
--   current time precedes the AC's notBeforeTime. This confirms the
--   implementation rejects ACs that are not yet effective.
--
-- Expected: ValidityFailed (ACNotYetValid _ _)
-- What would fail: ValidityOK if the implementation ignores notBeforeTime,
--   ValidityFailed with a different error variant.
-- NOT verified: Whether a clock-skew tolerance is applied -- that would
--   require a separate parameterized test.
testACNotYetValid :: Assertion
testACNotYetValid = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  -- AC starts in the future
  let acValidity = mkTestValidityPeriod futureDateTime (addYears futureDateTime 1)
  acPair <- mkTestAC aaPair holder 1 acValidity (Attributes []) []

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case validateACValidity currentDateTime aaCert (acpSignedAC acPair) of
    ValidityFailed (ACNotYetValid _ _) -> return ()
    ValidityFailed e -> assertFailure $ "Unexpected error: " ++ show e
    ValidityOK -> assertFailure "Expected ACNotYetValid error"

-- | AC-VAL-2.4: AC Expired
--
-- RFC 5755 Section 4.2.6 (Attribute Certificate Validity):
--   "The attrCertValidityPeriod field specifies the period for which the
--    AC issuer expects the binding between the holder and the attributes
--    fields to be valid."
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 3: "Check that the current date/time is within the validity
--    period of the AC."
--   An AC whose notAfterTime is in the past relative to the validation
--   time MUST be rejected.
--
-- Test scenario:
--   1. Generate RSA-2048 AA key pair and certificate
--   2. Create an AC whose notAfterTime is a date in the past (30 days after
--      a past start date, both of which are before the current time)
--   3. Validate the AC at the current time (which is after notAfterTime)
--
-- What is verified:
--   validateACValidity returns ValidityFailed (ACExpired ...) when the
--   current time is after the AC's notAfterTime. This confirms expired
--   ACs are properly rejected.
--
-- Expected: ValidityFailed (ACExpired _ _)
-- What would fail: ValidityOK if the implementation ignores expiration,
--   ValidityFailed with a different error variant.
-- NOT verified: Whether grace periods or clock-skew tolerance apply.
testACExpired :: Assertion
testACExpired = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  -- AC ended in the past
  let acValidity = mkTestValidityPeriod pastDateTime (addDays pastDateTime 30)
  acPair <- mkTestAC aaPair holder 1 acValidity (Attributes []) []

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case validateACValidity currentDateTime aaCert (acpSignedAC acPair) of
    ValidityFailed (ACExpired _ _) -> return ()
    ValidityFailed e -> assertFailure $ "Unexpected error: " ++ show e
    ValidityOK -> assertFailure "Expected ACExpired error"

-- | AC-VAL-2.5: Valid Period
--
-- RFC 5755 Section 4.2.6 (Attribute Certificate Validity):
--   "The attrCertValidityPeriod field specifies the period for which the
--    AC issuer expects the binding between the holder and the attributes
--    fields to be valid."
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 3: "Check that the current date/time is within the validity
--    period of the AC."
--   When the current time falls within [notBeforeTime, notAfterTime],
--   the validity check MUST succeed.
--
-- Test scenario:
--   1. Generate RSA-2048 AA key pair and certificate
--   2. Create an AC with a validity period that spans the current time
--      (defaultValidityStart <= currentDateTime <= defaultValidityEnd)
--   3. Validate the AC at the current time
--
-- What is verified:
--   validateACValidity returns ValidityOK when both the AA certificate
--   and the AC are within their respective validity periods. This is the
--   happy-path test confirming normal operation.
--
-- Expected: ValidityOK
-- What would fail: ValidityFailed for any reason, indicating a false
--   rejection of a valid AC.
-- NOT verified: Interactions between AA validity and AC validity when
--   they differ -- that is a separate concern.
testValidPeriod :: Assertion
testValidPeriod = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let acValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 1 acValidity (Attributes []) []

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case validateACValidity currentDateTime aaCert (acpSignedAC acPair) of
    ValidityOK -> return ()
    ValidityFailed e -> assertFailure $ "Expected valid but got: " ++ show e

-- | AC-VAL-2.6: Boundary - AC Start Time Exact
--
-- RFC 5755 Section 4.2.6 (Attribute Certificate Validity):
--   "The attrCertValidityPeriod field specifies the period for which the
--    AC issuer expects the binding between the holder and the attributes
--    fields to be valid."
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 3: "Check that the current date/time is within the validity
--    period of the AC."
--   The boundary condition where the validation time exactly equals
--   notBeforeTime MUST be accepted (inclusive lower bound).
--
-- Test scenario:
--   1. Generate RSA-2048 AA key pair and certificate
--   2. Create an AC whose notBeforeTime is set to currentDateTime exactly
--   3. Validate the AC at exactly currentDateTime (i.e., time == notBeforeTime)
--
-- What is verified:
--   validateACValidity returns ValidityOK when the validation time is
--   exactly equal to the AC's notBeforeTime. This confirms that the
--   lower boundary of the validity interval is inclusive (>=, not >).
--
-- Expected: ValidityOK
-- What would fail: ValidityFailed (ACNotYetValid ...) if the implementation
--   uses a strict greater-than comparison instead of greater-than-or-equal.
-- NOT verified: The upper boundary (time == notAfterTime) -- that would
--   be a separate boundary test.
testBoundaryStart :: Assertion
testBoundaryStart = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let acValidity = mkTestValidityPeriod currentDateTime defaultValidityEnd
  acPair <- mkTestAC aaPair holder 1 acValidity (Attributes []) []

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  -- Validation time exactly at notBeforeTime
  case validateACValidity currentDateTime aaCert (acpSignedAC acPair) of
    ValidityOK -> return ()
    ValidityFailed e -> assertFailure $ "Boundary should pass but got: " ++ show e

--------------------------------------------------------------------------------
-- Issuer Verification Tests (AC-ISS-*)
--------------------------------------------------------------------------------

-- | Issuer Verification Tests (AC-ISS-*)
--
-- RFC 5755 Section 4.2.3 (Issuer):
--   "The issuer field of the AC MUST contain a non-empty distinguished
--    name in the issuerName field of the V2Form."
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 2: "Verify that the AC issuer field matches the subject
--    field (or a subjectAltName extension value) of the AA certificate."
--
-- These tests verify that the issuer DN matching logic correctly detects
-- mismatches between the AC issuer field and the AA certificate subject,
-- and that it accepts a correct match.
issuerTests :: TestTree
issuerTests =
  testGroup
    "Issuer Verification (AC-ISS-*)"
    [ testCase "AC-ISS-3.1: Issuer DN Mismatch" testIssuerMismatch,
      testCase "AC-ISS-matching: Issuer DN Match" testIssuerMatch
    ]

-- | AC-ISS-3.1: Issuer DN Mismatch
--
-- RFC 5755 Section 4.2.3 (Issuer):
--   "The issuer field of the AC MUST contain a non-empty distinguished
--    name in the issuerName field of the V2Form."
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 2: "Verify that the AC issuer field matches the subject
--    field (or a subjectAltName extension value) of the AA certificate."
--   When the AC's issuer DN does not match the AA certificate's subject DN,
--   the validation MUST fail.
--
-- Test scenario:
--   1. Create two distinct AAs: "AA One" (serial 1) and "AA Two" (serial 2)
--   2. Create an AC signed by AA1 (whose issuer field references AA1's DN)
--   3. Attempt to validate the AC against AA2's certificate
--
-- What is verified:
--   validateACIssuer returns PathFailed (IssuerMismatch ...) when the AC's
--   issuer DN ("AA One") does not match the validating AA's subject DN
--   ("AA Two"). This simulates a scenario where a relying party attempts
--   to validate an AC against the wrong AA.
--
-- Expected: PathFailed (IssuerMismatch _ _)
-- What would fail: PathOK if the implementation does not compare issuer DNs,
--   PathFailed with a different error variant.
-- NOT verified: Whether partial DN matching (e.g., matching only the CN
--   component) is correctly handled -- that requires separate DN-level tests.
testIssuerMismatch :: Assertion
testIssuerMismatch = do
  -- Create two different AAs
  aaKeys1 <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair1 <- mkAA 1 "AA One" validPeriod Self aaKeys1

  aaKeys2 <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair2 <- mkAA 2 "AA Two" validPeriod Self aaKeys2

  -- Create AC signed by AA1
  let holder = mkTestHolder (pairSignedCert aaPair1)
  let acValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair1 holder 1 acValidity (Attributes []) []

  -- But try to validate with AA2's certificate
  let aaCert2 = signedObject (getSigned (pairSignedCert aaPair2))

  case validateACIssuer aaCert2 (acpSignedAC acPair) of
    PathFailed (IssuerMismatch _ _) -> return ()
    PathFailed e -> assertFailure $ "Unexpected error: " ++ show e
    PathOK -> assertFailure "Expected IssuerMismatch error"

-- | AC-ISS-matching: Issuer DN Match
--
-- RFC 5755 Section 4.2.3 (Issuer):
--   "The issuer field of the AC MUST contain a non-empty distinguished
--    name in the issuerName field of the V2Form."
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 2: "Verify that the AC issuer field matches the subject
--    field (or a subjectAltName extension value) of the AA certificate."
--   When the AC's issuer DN matches the AA certificate's subject DN,
--   the validation MUST succeed.
--
-- Test scenario:
--   1. Create a single AA ("Test AA")
--   2. Create an AC signed by that AA (issuer field references "Test AA")
--   3. Validate the AC against the same AA's certificate
--
-- What is verified:
--   validateACIssuer returns PathOK when the AC's issuer DN matches the
--   AA's subject DN. This is the happy-path test for issuer verification.
--
-- Expected: PathOK
-- What would fail: PathFailed for any reason, indicating a false rejection
--   of a valid issuer-AA binding.
-- NOT verified: Case sensitivity or encoding normalization of DN components.
testIssuerMatch :: Assertion
testIssuerMatch = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let acValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 1 acValidity (Attributes []) []

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case validateACIssuer aaCert (acpSignedAC acPair) of
    PathOK -> return ()
    PathFailed e -> assertFailure $ "Expected match but got: " ++ show e

--------------------------------------------------------------------------------
-- Basic Constraints Tests (AC-BC-*)
--------------------------------------------------------------------------------

-- | Basic Constraints Tests (AC-BC-*)
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 2: The AA certificate SHOULD be checked for appropriate
--   basic constraints. While RFC 5755 does not mandate that AAs be CAs,
--   the implementation may require the cA flag to be true if the AA
--   is also used as part of a PKI hierarchy.
--
-- RFC 5280 Section 4.2.1.9 (Basic Constraints):
--   "The cA boolean indicates whether the certified public key may be
--    used to verify certificate signatures."
--
-- These tests verify that the AA certificate's basicConstraints
-- extension is correctly checked during AC validation path processing.
basicConstraintsTests :: TestTree
basicConstraintsTests =
  testGroup
    "Basic Constraints (AC-BC-*)"
    [ testCase "AC-BC-4.4: AA with cA=true passes" testAAWithCATrue
    ]

-- | AC-BC-4.4: AA with cA=true passes
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 2: The AA certificate SHOULD be checked for appropriate
--   basic constraints. An AA certificate with cA=true indicates it
--   is authorized as a certificate authority and can serve as an AA.
--
-- RFC 5280 Section 4.2.1.9 (Basic Constraints):
--   "The cA boolean indicates whether the certified public key may be
--    used to verify certificate signatures."
--
-- Test scenario:
--   1. Create an AA certificate via mkAA (which sets basicConstraints cA=true)
--   2. Validate the AA certificate's basic constraints
--
-- What is verified:
--   validateAABasicConstraints returns PathOK for an AA certificate that
--   has the cA flag set to true. This confirms that certificates with
--   proper CA authority are accepted as valid AAs.
--
-- Expected: PathOK
-- What would fail: PathFailed if the implementation rejects certificates
--   with cA=true, which would be incorrect.
-- NOT verified: Whether an AA certificate without cA=true is rejected --
--   that would be a complementary negative test (AC-BC-4.1/4.2).
testAAWithCATrue :: Assertion
testAAWithCATrue = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  -- mkAA creates a certificate with basicConstraints cA=true
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case validateAABasicConstraints aaCert of
    PathOK -> return ()
    PathFailed e -> assertFailure $ "Expected valid but got: " ++ show e

--------------------------------------------------------------------------------
-- Key Usage Tests (AC-KU-*)
--------------------------------------------------------------------------------

-- | Key Usage Tests (AC-KU-*)
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 2: "If the AA certificate includes a key usage extension,
--    verify that the digitalSignature bit is set."
--
-- RFC 5280 Section 4.2.1.3 (Key Usage):
--   "The digitalSignature bit is asserted when the subject public key
--    is used for verifying digital signatures, other than signatures
--    on certificates (bit 5) and CRLs (bit 6)."
--
-- These tests verify that the AA certificate's key usage extension
-- is correctly validated during AC validation path processing.
keyUsageTests :: TestTree
keyUsageTests =
  testGroup
    "Key Usage (AC-KU-*)"
    [ testCase "AC-KU-5.2: AA with valid key usage passes" testAAValidKeyUsage
    ]

-- | AC-KU-5.2: AA with valid key usage passes
--
-- RFC 5755 Section 5 (AC Validation):
--   Step 2: "If the AA certificate includes a key usage extension,
--    verify that the digitalSignature bit is set."
--
-- RFC 5280 Section 4.2.1.3 (Key Usage):
--   "The digitalSignature bit is asserted when the subject public key
--    is used for verifying digital signatures."
--   "The keyCertSign bit is asserted when the subject public key is
--    used for verifying signatures on public key certificates."
--
-- Test scenario:
--   1. Create an AA certificate via mkAA (which sets both keyCertSign
--      and digitalSignature key usage bits)
--   2. Validate the AA certificate's key usage
--
-- What is verified:
--   validateAAKeyUsage returns PathOK for an AA certificate that has
--   the digitalSignature (and keyCertSign) key usage bits set.
--   This confirms that the key usage check accepts an AA with the
--   appropriate bits for signing ACs.
--
-- Expected: PathOK
-- What would fail: PathFailed if the implementation rejects valid
--   key usage combinations.
-- NOT verified: Whether an AA certificate without digitalSignature
--   is rejected -- that would be a complementary negative test
--   (AC-KU-5.1).
testAAValidKeyUsage :: Assertion
testAAValidKeyUsage = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  -- mkAA creates a certificate with keyCertSign and digitalSignature
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case validateAAKeyUsage aaCert of
    PathOK -> return ()
    PathFailed e -> assertFailure $ "Expected valid but got: " ++ show e

--------------------------------------------------------------------------------
-- Revocation Tests (AC-REV-*)
--------------------------------------------------------------------------------

-- | Revocation Tests (AC-REV-*)
--
-- RFC 5755 Section 6 (Revocation):
--   "ACs MAY be revoked by the AC issuer. In order to support
--    revocation, the AC issuer makes available an Attribute Certificate
--    Revocation List (ACRL)."
--
-- RFC 5755 Section 6 (Revocation):
--   Revocation checking involves:
--     1. Obtaining the relevant ACRL(s)
--     2. Verifying the ACRL signature
--     3. Checking that the AC serial number is not listed
--     4. Checking that the CRL is within its validity period
--
-- RFC 5755 Section 6 also notes:
--   "AC issuers SHOULD use short validity periods, making revocation
--    less important than for PKCs. Nevertheless, revocation support
--    is specified for environments that require it."
--
-- These tests verify all aspects of AC and AA revocation checking:
-- revoked AC detection, non-revoked AC acceptance, revoked AA
-- detection, expired CRL handling, and missing CRL handling.
revocationTests :: TestTree
revocationTests =
  testGroup
    "Revocation (AC-REV-*)"
    [ testCase "AC-REV-6.1: AC revoked (on ACRL)" testACRevoked,
      testCase "AC-REV-6.2: AC not revoked (not on ACRL)" testACNotRevoked,
      testCase "AC-REV-6.3: AA certificate revoked" testAARevoked,
      testCase "AC-REV-6.4: CRL expired" testCRLExpired,
      testCase "AC-REV-6.6: No CRL available" testNoCRLAvailable
    ]

-- | AC-REV-6.1: AC revoked (on ACRL)
--
-- RFC 5755 Section 6 (Revocation):
--   "ACs MAY be revoked by the AC issuer. In order to support
--    revocation, the AC issuer makes available an Attribute Certificate
--    Revocation List (ACRL)."
--
-- RFC 5755 Section 6 (Revocation):
--   "Check that the AC serial number is not listed on
--    an applicable ACRL."
--   An AC whose serial number appears on the ACRL MUST be rejected.
--
-- Test scenario:
--   1. Create an AA and an AC with serial number 100
--   2. Create an ACRL that lists serial 100 as revoked (with a past
--      revocation date)
--   3. Check the revocation status of the AC against the ACRL
--
-- What is verified:
--   checkACRevocation returns RevocationFailed (ACRevoked 100 _) when the
--   AC's serial number is found on the ACRL. The serial number in the
--   error is verified to be exactly 100.
--
-- Expected: RevocationFailed (ACRevoked 100 _)
-- What would fail: NotRevoked if the serial number lookup fails,
--   RevocationUnknown if the ACRL is not processed.
-- NOT verified: Whether multiple revoked entries on the same ACRL are
--   all detected -- this test uses a single-entry ACRL.
testACRevoked :: Assertion
testACRevoked = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let acValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 100 acValidity (Attributes []) []

  -- Create ACRL with AC serial 100 revoked
  let revokedEntry = mkRevokedCertificate 100 pastDateTime
  acrl <- mkTestCRL aaPair pastDateTime (Just futureDateTime) [revokedEntry]

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case checkACRevocation currentDateTime (Just acrl) Nothing aaCert (acpSignedAC acPair) of
    RevocationFailed (ACRevoked serialNum _) ->
      assertEqual "Serial should be 100" 100 serialNum
    NotRevoked -> assertFailure "Expected ACRevoked but got NotRevoked"
    RevocationUnknown reason -> assertFailure $ "Expected ACRevoked but got Unknown: " ++ reason
    RevocationFailed e -> assertFailure $ "Unexpected error: " ++ show e

-- | AC-REV-6.2: AC not revoked (not on ACRL)
--
-- RFC 5755 Section 6 (Revocation):
--   "ACs MAY be revoked by the AC issuer. In order to support
--    revocation, the AC issuer makes available an Attribute Certificate
--    Revocation List (ACRL)."
--
-- RFC 5755 Section 6 (Revocation):
--   "Check that the AC serial number is not listed on
--    an applicable ACRL."
--   An AC whose serial number does NOT appear on the ACRL MUST be
--   accepted (with respect to revocation).
--
-- Test scenario:
--   1. Create an AA and an AC with serial number 100
--   2. Create an ACRL that lists a different serial (999) as revoked
--   3. Check the revocation status of the AC (serial 100) against the ACRL
--
-- What is verified:
--   checkACRevocation returns NotRevoked when the AC's serial number (100)
--   is not listed on the ACRL (which only contains serial 999). This is
--   the happy-path test for revocation checking.
--
-- Expected: NotRevoked
-- What would fail: RevocationFailed if the serial number lookup incorrectly
--   matches, RevocationUnknown if the ACRL is not processed.
-- NOT verified: Whether an empty ACRL (no revoked entries) also returns
--   NotRevoked -- that is a separate edge case.
testACNotRevoked :: Assertion
testACNotRevoked = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let acValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 100 acValidity (Attributes []) []

  -- Create ACRL with a different serial revoked (not 100)
  let revokedEntry = mkRevokedCertificate 999 pastDateTime
  acrl <- mkTestCRL aaPair pastDateTime (Just futureDateTime) [revokedEntry]

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case checkACRevocation currentDateTime (Just acrl) Nothing aaCert (acpSignedAC acPair) of
    NotRevoked -> return ()
    RevocationFailed e -> assertFailure $ "Expected NotRevoked but got: " ++ show e
    RevocationUnknown reason -> assertFailure $ "Expected NotRevoked but got Unknown: " ++ reason

-- | AC-REV-6.3: AA certificate revoked
--
-- RFC 5755 Section 6 (Revocation):
--   In addition to checking the AC's own revocation status,
--   the AA's PKC (public key certificate) revocation status MUST also
--   be checked. If the AA's certificate has been revoked, all ACs
--   issued by that AA MUST be considered invalid.
--
-- RFC 5280 Section 5.1 (CRL Fields):
--   "The scope of each CRL is indicated by the CRL's issuer field."
--   A CRL issued by the same entity that issued the AA's PKC is used
--   to check the AA's revocation status.
--
-- Test scenario:
--   1. Create an AA (serial 1) and an AC (serial 100) signed by that AA
--   2. Create a CRL (for PKCs) that lists the AA's serial (1) as revoked
--   3. Check the revocation status, providing the AA CRL but no ACRL
--
-- What is verified:
--   checkACRevocation returns RevocationFailed (AARevoked 1 _) when the
--   AA's own certificate serial number (1) is found on the AA's CRL.
--   This confirms that the revocation engine checks the AA's certificate
--   status in addition to the AC's status.
--
-- Expected: RevocationFailed (AARevoked 1 _)
-- What would fail: NotRevoked if the implementation only checks ACRL
--   and ignores the AA CRL, RevocationUnknown if the CRL is not processed.
-- NOT verified: Whether a revoked AA with a valid ACRL correctly fails --
--   that would test priority between AA revocation and AC revocation.
testAARevoked :: Assertion
testAARevoked = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let acValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 100 acValidity (Attributes []) []

  -- Create CRL for AA certificate (serial 1)
  let revokedEntry = mkRevokedCertificate 1 pastDateTime
  aaCrl <- mkTestCRL aaPair pastDateTime (Just futureDateTime) [revokedEntry]

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case checkACRevocation currentDateTime Nothing (Just aaCrl) aaCert (acpSignedAC acPair) of
    RevocationFailed (AARevoked serialNum _) ->
      assertEqual "AA serial should be 1" 1 serialNum
    NotRevoked -> assertFailure "Expected AARevoked but got NotRevoked"
    RevocationUnknown reason -> assertFailure $ "Expected AARevoked but got Unknown: " ++ reason
    RevocationFailed e -> assertFailure $ "Unexpected error: " ++ show e

-- | AC-REV-6.4: CRL expired
--
-- RFC 5280 Section 5.1.2.5 (Next Update):
--   "The nextUpdate field indicates the date by which the next CRL will
--    be issued. ... Conforming applications MUST NOT use CRLs past the
--    nextUpdate time."
--
-- RFC 5755 Section 6 (Revocation):
--   When checking revocation, the CRL used MUST itself be
--   within its validity period. An expired CRL (nextUpdate in the past)
--   MUST NOT be relied upon for revocation decisions.
--
-- Test scenario:
--   1. Create an AA and an AC (serial 100)
--   2. Create an ACRL with nextUpdate set to a past date
--      (both thisUpdate and nextUpdate are in the past)
--   3. Check the revocation status using the expired ACRL
--
-- What is verified:
--   checkACRevocation returns RevocationFailed (CRLExpired ...) when the
--   provided ACRL's nextUpdate has passed. This confirms that expired
--   CRLs are rejected rather than silently accepted.
--
-- Expected: RevocationFailed (CRLExpired _ _)
-- What would fail: NotRevoked if the implementation ignores the CRL's
--   nextUpdate field, RevocationUnknown if it treats expired CRLs as
--   unavailable instead of failed.
-- NOT verified: Whether a CRL without nextUpdate is accepted or rejected --
--   RFC 5280 says applications SHOULD treat it as valid, which would be
--   a separate test.
testCRLExpired :: Assertion
testCRLExpired = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let acValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 100 acValidity (Attributes []) []

  -- Create expired CRL (nextUpdate in the past)
  let revokedEntry = mkRevokedCertificate 999 pastDateTime
  expiredCrl <- mkTestCRL aaPair pastDateTime (Just pastDateTime) [revokedEntry]

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case checkACRevocation currentDateTime (Just expiredCrl) Nothing aaCert (acpSignedAC acPair) of
    RevocationFailed (CRLExpired _ _) -> return ()
    NotRevoked -> assertFailure "Expected CRLExpired but got NotRevoked"
    RevocationUnknown reason -> assertFailure $ "Expected CRLExpired but got Unknown: " ++ reason
    RevocationFailed e -> assertFailure $ "Unexpected error: " ++ show e

-- | AC-REV-6.6: No CRL available
--
-- RFC 5755 Section 6 (Revocation):
--   "ACs MAY be revoked by the AC issuer."
--   Revocation support is optional. When no CRL is available, the
--   revocation status cannot be determined.
--
-- RFC 5755 Section 6 (Revocation):
--   When no ACRL and no AA CRL are available, the revocation
--   status of the AC is unknown. The relying party's policy determines
--   whether an unknown revocation status is acceptable.
--
-- Test scenario:
--   1. Create an AA and an AC (serial 100)
--   2. Check the revocation status with both ACRL and AA CRL set to Nothing
--
-- What is verified:
--   checkACRevocation returns RevocationUnknown when neither an ACRL
--   nor an AA CRL is provided. This confirms that the implementation
--   correctly distinguishes between "not revoked" (positive assertion)
--   and "revocation status unknown" (no data available).
--
-- Expected: RevocationUnknown _
-- What would fail: NotRevoked if the implementation assumes non-revoked
--   when no CRL is available, RevocationFailed if it treats missing CRLs
--   as a hard failure.
-- NOT verified: Whether the relying party's policy (e.g., "fail-open"
--   vs "fail-closed") correctly handles the RevocationUnknown result.
testNoCRLAvailable :: Assertion
testNoCRLAvailable = do
  aaKeys <- generateKeys (AlgRSA 2048 hashSHA256)
  aaPair <- mkAA 1 "Test AA" validPeriod Self aaKeys

  let holder = mkTestHolder (pairSignedCert aaPair)
  let acValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
  acPair <- mkTestAC aaPair holder 100 acValidity (Attributes []) []

  let aaCert = signedObject (getSigned (pairSignedCert aaPair))

  case checkACRevocation currentDateTime Nothing Nothing aaCert (acpSignedAC acPair) of
    RevocationUnknown _ -> return ()
    NotRevoked -> assertFailure "Expected RevocationUnknown but got NotRevoked"
    RevocationFailed e -> assertFailure $ "Expected RevocationUnknown but got: " ++ show e

--------------------------------------------------------------------------------
-- RFC 5755 Profile Tests (AC-RFC-*)
--------------------------------------------------------------------------------

-- | RFC 5755 Profile Conformance Tests (AC-RFC-*)
--
-- RFC 5755 Section 4 (Attribute Certificate Profile):
--   Defines the mandatory profile for Attribute Certificates, including
--   structural requirements for the version, holder, issuer, serialNumber,
--   and other fields.
--
-- RFC 5755 Section 4.2.1 (Version):
--   "version MUST be v2(1)"
--
-- RFC 5755 Section 4.2.2 (Holder):
--   "At least one of the three options in the Holder SEQUENCE MUST be present"
--
-- RFC 5755 Section 4.2.5 (Serial Number):
--   "The serial number MUST be a positive INTEGER ... no more than 20 octets"
--
-- RFC 5755 Section 4.2.3 (Issuer):
--   "Only the v2Form choice of AttCertIssuer SHALL be used."
--   "baseCertificateID and objectDigestInfo MUST NOT be present."
--   "issuerName MUST contain exactly one GeneralName of type directoryName."
--
-- These tests verify structural conformance of the AttributeCertificateInfo
-- fields to the RFC 5755 profile. Each test constructs an ACI with a
-- specific profile violation and verifies that validateRFC5755Profile
-- reports the correct error.
rfc5755Tests :: TestTree
rfc5755Tests =
  testGroup
    "RFC 5755 Profile (AC-RFC-*)"
    [ testCase "AC-RFC-8.1: v1Form Used (rejected)" testV1FormRejected,
      testCase "AC-RFC-8.2: V2Form baseCertificateID Present (rejected)" testV2FormBaseCertID,
      testCase "AC-RFC-8.3: V2Form objectDigestInfo Present (rejected)" testV2FormObjDigest,
      testCase "AC-RFC-8.4: Serial Number Too Long (rejected)" testSerialTooLong,
      testCase "AC-RFC-8.5: Serial Number Not Positive (rejected)" testSerialNotPositive,
      testCase "AC-RFC-8.6: Holder All Fields Empty (rejected)" testHolderEmpty,
      testCase "AC-RFC-8.7: V2Form issuerName not single directoryName (rejected)" testIssuerNotSingleDN,
      testCase "AC-RFC-8.8: Valid RFC 5755 Profile" testValidRFC5755Profile
    ]

-- | AC-RFC-8.1: v1Form Used (rejected)
--
-- RFC 5755 Section 4.2.3 (Issuer):
--   "Only the v2Form choice of AttCertIssuer SHALL be used.
--    Implementations that conform to this profile MUST NOT use the
--    v1Form choice."
--
-- ASN.1 definition (RFC 5755 Section 4):
--   AttCertIssuer ::= CHOICE {
--     v1Form   GeneralNames,  -- MUST NOT be used in this profile
--     v2Form   [0] V2Form     -- The only allowed form
--   }
--
-- Test scenario:
--   1. Construct an AttributeCertificateInfo with AttCertIssuerV1 (the v1Form)
--   2. Run validateRFC5755Profile against this ACI
--
-- What is verified:
--   validateRFC5755Profile includes V1FormNotAllowed in its error list.
--   This confirms that the profile validator rejects the deprecated v1Form
--   issuer choice.
--
-- Expected: V1FormNotAllowed in vrErrors
-- What would fail: Empty vrErrors if the implementation accepts v1Form,
--   or a different error if the wrong check fires.
-- NOT verified: Whether v1Form ACs can still be parsed (this test is
--   about profile validation, not ASN.1 decoding).
testV1FormRejected :: Assertion
testV1FormRejected = do
  -- Create ACI with v1Form issuer
  let aci = AttributeCertificateInfo
        { aciVersion = 1
        , aciHolder = Holder (Just (IssuerSerial [] 1 Nothing)) Nothing Nothing
        , aciIssuer = AttCertIssuerV1 [AltDirectoryName (mkDn "Test AA")]  -- v1Form!
        , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
        , aciSerialNumber = 1
        , aciValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
        , aciAttributes = Attributes []
        , aciIssuerUniqueID = Nothing
        , aciExtensions = Extensions Nothing
        }

  let result = validateRFC5755Profile aci
  assertBool "Should have V1FormNotAllowed error" $
    V1FormNotAllowed `elem` vrErrors result

-- | AC-RFC-8.2: V2Form baseCertificateID Present (rejected)
--
-- RFC 5755 Section 4.2.3 (Issuer):
--   "Conforming ACs MUST NOT use the baseCertificateID field of V2Form."
--
-- ASN.1 definition (RFC 5755 Section 4):
--   V2Form ::= SEQUENCE {
--     issuerName            GeneralNames  OPTIONAL,
--     baseCertificateID     [0] IssuerSerial  OPTIONAL,
--     objectDigestInfo      [1] ObjectDigestInfo  OPTIONAL
--   }
--
-- The baseCertificateID was included in the ASN.1 definition for
-- extensibility but MUST NOT be present in conforming ACs per the
-- profile constraints of RFC 5755.
--
-- Test scenario:
--   1. Construct a V2Form with baseCertificateID set to a non-Nothing value
--   2. Wrap it in an AttributeCertificateInfo
--   3. Run validateRFC5755Profile
--
-- What is verified:
--   validateRFC5755Profile includes V2FormBaseCertificateIDPresent in its
--   error list. This confirms that the profile validator detects the
--   prohibited baseCertificateID field.
--
-- Expected: V2FormBaseCertificateIDPresent in vrErrors
-- What would fail: Empty vrErrors if the implementation ignores this field.
-- NOT verified: Whether an ACI with both baseCertificateID and
--   objectDigestInfo produces two separate errors -- that combination
--   is tested implicitly if both checks are independent.
testV2FormBaseCertID :: Assertion
testV2FormBaseCertID = do
  let v2form = V2Form
        { v2formIssuerName = [AltDirectoryName (mkDn "Test AA")]
        , v2formBaseCertificateID = Just (IssuerSerial [] 1 Nothing)  -- Not allowed!
        , v2formObjectDigestInfo = Nothing
        }
  let aci = AttributeCertificateInfo
        { aciVersion = 1
        , aciHolder = Holder (Just (IssuerSerial [] 1 Nothing)) Nothing Nothing
        , aciIssuer = AttCertIssuerV2 v2form
        , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
        , aciSerialNumber = 1
        , aciValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
        , aciAttributes = Attributes []
        , aciIssuerUniqueID = Nothing
        , aciExtensions = Extensions Nothing
        }

  let result = validateRFC5755Profile aci
  assertBool "Should have V2FormBaseCertificateIDPresent error" $
    V2FormBaseCertificateIDPresent `elem` vrErrors result

-- | AC-RFC-8.3: V2Form objectDigestInfo Present (rejected)
--
-- RFC 5755 Section 4.2.3 (Issuer):
--   "Conforming ACs MUST NOT use the objectDigestInfo field of V2Form."
--
-- ASN.1 definition (RFC 5755 Section 4):
--   ObjectDigestInfo ::= SEQUENCE {
--     digestedObjectType  ENUMERATED { ... },
--     otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
--     digestAlgorithm     AlgorithmIdentifier,
--     objectDigest        BIT STRING
--   }
--
-- The objectDigestInfo mechanism allows binding an AC to a specific
-- public key by digest, but conforming implementations MUST NOT use it
-- per the profile constraints of RFC 5755.
--
-- Test scenario:
--   1. Construct an ObjectDigestInfo with type OIDPublicKey
--   2. Attach it to a V2Form via v2formObjectDigestInfo
--   3. Wrap in an AttributeCertificateInfo and run validateRFC5755Profile
--
-- What is verified:
--   validateRFC5755Profile includes V2FormObjectDigestInfoPresent in its
--   error list. This confirms that the profile validator detects the
--   prohibited objectDigestInfo field.
--
-- Expected: V2FormObjectDigestInfoPresent in vrErrors
-- What would fail: Empty vrErrors if the implementation ignores this field.
-- NOT verified: Whether ObjectDigestInfo with different digest types
--   (e.g., OIDPublicKeyCert) is also rejected -- the check should be
--   field-presence-based, not value-based.
testV2FormObjDigest :: Assertion
testV2FormObjDigest = do
  let objDigest = ObjectDigestInfo
        { odiObjectType = OIDPublicKey
        , odiOtherObjectTypeID = Nothing
        , odiDigestAlgorithm = SignatureALG HashSHA256 PubKeyALG_RSA
        , odiObjectDigest = ""
        }
  let v2form = V2Form
        { v2formIssuerName = [AltDirectoryName (mkDn "Test AA")]
        , v2formBaseCertificateID = Nothing
        , v2formObjectDigestInfo = Just objDigest  -- Not allowed!
        }
  let aci = AttributeCertificateInfo
        { aciVersion = 1
        , aciHolder = Holder (Just (IssuerSerial [] 1 Nothing)) Nothing Nothing
        , aciIssuer = AttCertIssuerV2 v2form
        , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
        , aciSerialNumber = 1
        , aciValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
        , aciAttributes = Attributes []
        , aciIssuerUniqueID = Nothing
        , aciExtensions = Extensions Nothing
        }

  let result = validateRFC5755Profile aci
  assertBool "Should have V2FormObjectDigestInfoPresent error" $
    V2FormObjectDigestInfoPresent `elem` vrErrors result

-- | AC-RFC-8.4: Serial Number Too Long (rejected)
--
-- RFC 5755 Section 4.2.5 (Serial Number):
--   "The serial number MUST be a positive INTEGER assigned by the AC
--    issuer. It MUST be unique for each AC issued by a given AC issuer.
--    The serial number MUST be no more than 20 octets long."
--
-- RFC 5280 Section 4.1.2.2 (Serial Number) — referenced by RFC 5755:
--   "Conforming CAs MUST NOT use serialNumber values longer than 20 octets."
--   The same constraint applies to AC serial numbers per RFC 5755.
--
-- Test scenario:
--   1. Construct an ACI with a serial number of 2^168, which requires
--      21 bytes to encode (exceeding the 20-octet limit)
--   2. Run validateRFC5755Profile
--
-- What is verified:
--   validateRFC5755Profile includes a SerialNumberTooLong error in its
--   error list. This confirms that the profile validator detects serial
--   numbers exceeding the 20-octet DER encoding limit.
--
-- Expected: SerialNumberTooLong _ in vrErrors
-- What would fail: Empty vrErrors if the implementation does not check
--   serial number length.
-- NOT verified: Whether a serial number of exactly 20 octets (the maximum
--   allowed) is accepted -- that would be a boundary test.
testSerialTooLong :: Assertion
testSerialTooLong = do
  -- Serial number > 2^160 (more than 20 octets)
  let hugeSerial = 2 ^ (168 :: Integer)  -- 21 bytes
  let aci = AttributeCertificateInfo
        { aciVersion = 1
        , aciHolder = Holder (Just (IssuerSerial [] 1 Nothing)) Nothing Nothing
        , aciIssuer = AttCertIssuerV2 $ V2Form [AltDirectoryName (mkDn "Test AA")] Nothing Nothing
        , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
        , aciSerialNumber = hugeSerial
        , aciValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
        , aciAttributes = Attributes []
        , aciIssuerUniqueID = Nothing
        , aciExtensions = Extensions Nothing
        }

  let result = validateRFC5755Profile aci
  assertBool "Should have SerialNumberTooLong error" $
    any isSerialTooLong (vrErrors result)
  where
    isSerialTooLong (SerialNumberTooLong _) = True
    isSerialTooLong _ = False

-- | AC-RFC-8.5: Serial Number Not Positive (rejected)
--
-- RFC 5755 Section 4.2.5 (Serial Number):
--   "The serial number MUST be a positive INTEGER assigned by the AC
--    issuer."
--   A serial number of zero or negative is not a positive integer and
--   MUST be rejected.
--
-- Test scenario:
--   1. Construct an ACI with serial number 0 (not positive)
--   2. Run validateRFC5755Profile
--
-- What is verified:
--   validateRFC5755Profile includes a SerialNumberNotPositive error in
--   its error list. This confirms that the profile validator detects
--   non-positive serial numbers.
--
-- Expected: SerialNumberNotPositive _ in vrErrors
-- What would fail: Empty vrErrors if the implementation accepts zero
--   as a valid serial number.
-- NOT verified: Whether negative serial numbers are also detected (they
--   would fail the same check, but a dedicated test could confirm).
testSerialNotPositive :: Assertion
testSerialNotPositive = do
  let aci = AttributeCertificateInfo
        { aciVersion = 1
        , aciHolder = Holder (Just (IssuerSerial [] 1 Nothing)) Nothing Nothing
        , aciIssuer = AttCertIssuerV2 $ V2Form [AltDirectoryName (mkDn "Test AA")] Nothing Nothing
        , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
        , aciSerialNumber = 0  -- Not positive!
        , aciValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
        , aciAttributes = Attributes []
        , aciIssuerUniqueID = Nothing
        , aciExtensions = Extensions Nothing
        }

  let result = validateRFC5755Profile aci
  assertBool "Should have SerialNumberNotPositive error" $
    any isSerialNotPositive (vrErrors result)
  where
    isSerialNotPositive (SerialNumberNotPositive _) = True
    isSerialNotPositive _ = False

-- | AC-RFC-8.6: Holder All Fields Empty (rejected)
--
-- RFC 5755 Section 4.2.2 (Holder):
--   "At least one of the three options in the Holder SEQUENCE MUST be
--    present for a conforming AC."
--
-- ASN.1 definition (RFC 5755 Section 4):
--   Holder ::= SEQUENCE {
--     baseCertificateID   [0] IssuerSerial OPTIONAL,
--     entityName          [1] GeneralNames OPTIONAL,
--     objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
--   }
--
-- An AC with all three fields set to Nothing identifies no holder at all,
-- which is meaningless and MUST be rejected.
--
-- Test scenario:
--   1. Construct an ACI with Holder Nothing Nothing Nothing
--      (all three Holder fields absent)
--   2. Run validateRFC5755Profile
--
-- What is verified:
--   validateRFC5755Profile includes HolderMissingAllFields in its error
--   list. This confirms that the profile validator detects a completely
--   empty Holder structure.
--
-- Expected: HolderMissingAllFields in vrErrors
-- What would fail: Empty vrErrors if the implementation allows an empty Holder.
-- NOT verified: Whether a Holder with exactly one field set is accepted --
--   that is tested in the valid profile test (AC-RFC-8.8).
testHolderEmpty :: Assertion
testHolderEmpty = do
  let aci = AttributeCertificateInfo
        { aciVersion = 1
        , aciHolder = Holder Nothing Nothing Nothing  -- All fields empty!
        , aciIssuer = AttCertIssuerV2 $ V2Form [AltDirectoryName (mkDn "Test AA")] Nothing Nothing
        , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
        , aciSerialNumber = 1
        , aciValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
        , aciAttributes = Attributes []
        , aciIssuerUniqueID = Nothing
        , aciExtensions = Extensions Nothing
        }

  let result = validateRFC5755Profile aci
  assertBool "Should have HolderMissingAllFields error" $
    HolderMissingAllFields `elem` vrErrors result

-- | AC-RFC-8.7: V2Form issuerName not single directoryName (rejected)
--
-- RFC 5755 Section 4.2.3 (Issuer):
--   "The issuerName field of V2Form MUST contain exactly one
--    GeneralName, and that GeneralName MUST be of type directoryName."
--
-- When the issuerName contains multiple GeneralNames, or when the single
-- GeneralName is not of type directoryName (e.g., rfc822Name, uniformResourceIdentifier),
-- the AC does not conform to the RFC 5755 profile.
--
-- Test scenario:
--   1. Construct a V2Form with two directoryName entries in issuerName
--      (violating the "exactly one" requirement)
--   2. Wrap in an AttributeCertificateInfo and run validateRFC5755Profile
--
-- What is verified:
--   validateRFC5755Profile includes an IssuerNameNotSingleDirectoryName
--   error in its error list. This confirms that the profile validator
--   enforces the single-directoryName constraint on the issuer field.
--
-- Expected: IssuerNameNotSingleDirectoryName _ in vrErrors
-- What would fail: Empty vrErrors if the implementation allows multiple
--   issuer names.
-- NOT verified: Whether a single non-directoryName GeneralName (e.g.,
--   rfc822Name) is also rejected -- that would be a separate test case.
testIssuerNotSingleDN :: Assertion
testIssuerNotSingleDN = do
  -- Multiple issuer names
  let v2form = V2Form
        { v2formIssuerName = [AltDirectoryName (mkDn "AA1"), AltDirectoryName (mkDn "AA2")]
        , v2formBaseCertificateID = Nothing
        , v2formObjectDigestInfo = Nothing
        }
  let aci = AttributeCertificateInfo
        { aciVersion = 1
        , aciHolder = Holder (Just (IssuerSerial [] 1 Nothing)) Nothing Nothing
        , aciIssuer = AttCertIssuerV2 v2form
        , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
        , aciSerialNumber = 1
        , aciValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
        , aciAttributes = Attributes []
        , aciIssuerUniqueID = Nothing
        , aciExtensions = Extensions Nothing
        }

  let result = validateRFC5755Profile aci
  assertBool "Should have IssuerNameNotSingleDirectoryName error" $
    any isIssuerNotSingleDN (vrErrors result)
  where
    isIssuerNotSingleDN (IssuerNameNotSingleDirectoryName _) = True
    isIssuerNotSingleDN _ = False

-- | AC-RFC-8.8: Valid RFC 5755 Profile
--
-- RFC 5755 Section 4 (Attribute Certificate Profile):
--   A conforming AC MUST satisfy all of the following:
--     - version is v2(1)
--     - Holder has at least one field present
--     - Issuer uses v2Form with exactly one directoryName in issuerName
--     - baseCertificateID and objectDigestInfo are absent in V2Form
--     - Serial number is a positive integer of at most 20 octets
--
-- Test scenario:
--   1. Construct an ACI that satisfies all RFC 5755 profile requirements:
--      - version = 1 (v2)
--      - Holder with baseCertificateID present
--      - V2Form with single directoryName, no baseCertificateID,
--        no objectDigestInfo
--      - Serial number = 1 (positive, 1 octet)
--   2. Run validateRFC5755Profile
--
-- What is verified:
--   validateRFC5755Profile returns a result with an empty error list,
--   confirming that a properly constructed ACI passes all profile checks.
--   This is the positive/happy-path test for the profile validator.
--
-- Expected: vrErrors result == []
-- What would fail: Non-empty vrErrors if the profile validator has
--   a false positive for any check.
-- NOT verified: Whether all possible valid ACI variations pass (e.g.,
--   Holder with entityName instead of baseCertificateID).
testValidRFC5755Profile :: Assertion
testValidRFC5755Profile = do
  let aci = AttributeCertificateInfo
        { aciVersion = 1
        , aciHolder = Holder (Just (IssuerSerial [] 1 Nothing)) Nothing Nothing
        , aciIssuer = AttCertIssuerV2 $ V2Form [AltDirectoryName (mkDn "Test AA")] Nothing Nothing
        , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
        , aciSerialNumber = 1
        , aciValidity = mkTestValidityPeriod defaultValidityStart defaultValidityEnd
        , aciAttributes = Attributes []
        , aciIssuerUniqueID = Nothing
        , aciExtensions = Extensions Nothing
        }

  let result = validateRFC5755Profile aci
  assertEqual "Should have no errors" [] (vrErrors result)

--------------------------------------------------------------------------------
-- Helper Functions
--------------------------------------------------------------------------------

-- | Valid period spanning current time (2020-2030)
--
-- This helper provides a default validity window used by most tests to
-- create AA certificates and ACs that are valid at the test's
-- currentDateTime. The window spans from defaultValidityStart (2020)
-- to defaultValidityEnd (2030), ensuring that the synthetic test time
-- falls within the range.
--
-- Used by: signatureTests, issuerTests, basicConstraintsTests,
--   keyUsageTests, revocationTests, and any test that needs an AA
--   certificate with a standard validity period.
validPeriod :: (DateTime, DateTime)
validPeriod = (defaultValidityStart, defaultValidityEnd)
