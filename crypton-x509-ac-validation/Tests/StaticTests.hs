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

-- | All static test groups
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

signatureTests :: TestTree
signatureTests =
  testGroup
    "Signature Verification (AC-SIG-*)"
    [ testCase "AC-SIG-1.1: Valid AC Signature (RSA-SHA256)" testValidSignature,
      testCase "AC-SIG-1.6: MD5 Signature (weak) - rejected" testWeakMD5Signature,
      testCase "AC-SIG-1.7: SHA1 Signature (deprecated) - warning" testDeprecatedSHA1Signature
    ]

-- | AC-SIG-1.1: Valid signature should pass
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

-- | AC-SIG-1.6: MD5 signature should be rejected as weak
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

-- | AC-SIG-1.7: SHA1 signature should produce warning (deprecated)
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

validityTests :: TestTree
validityTests =
  testGroup
    "Validity Period (AC-VAL-*)"
    [ testCase "AC-VAL-2.3: AC Not Yet Valid" testACNotYetValid,
      testCase "AC-VAL-2.4: AC Expired" testACExpired,
      testCase "AC-VAL-2.5: Valid Period" testValidPeriod,
      testCase "AC-VAL-2.6: Boundary - AC Start Time Exact" testBoundaryStart
    ]

-- | AC-VAL-2.3: AC with future notBeforeTime should fail
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

-- | AC-VAL-2.4: AC with past notAfterTime should fail
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

-- | AC-VAL-2.5: Both AA and AC within validity period should pass
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

-- | AC-VAL-2.6: Validation time exactly equals notBeforeTime should pass
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

issuerTests :: TestTree
issuerTests =
  testGroup
    "Issuer Verification (AC-ISS-*)"
    [ testCase "AC-ISS-3.1: Issuer DN Mismatch" testIssuerMismatch,
      testCase "AC-ISS-matching: Issuer DN Match" testIssuerMatch
    ]

-- | AC-ISS-3.1: AC issuer should match AA subject
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

-- | Issuer DN should match AA subject
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

basicConstraintsTests :: TestTree
basicConstraintsTests =
  testGroup
    "Basic Constraints (AC-BC-*)"
    [ testCase "AC-BC-4.4: AA with cA=true passes" testAAWithCATrue
    ]

-- | AC-BC-4.4: AA certificate with cA=true should pass
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

keyUsageTests :: TestTree
keyUsageTests =
  testGroup
    "Key Usage (AC-KU-*)"
    [ testCase "AC-KU-5.2: AA with valid key usage passes" testAAValidKeyUsage
    ]

-- | AC-KU-5.2: AA with appropriate key usage should pass
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

-- | AC-REV-6.1: AC on ACRL should be detected as revoked
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

-- | AC-REV-6.2: AC not on ACRL should pass
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

-- | AC-REV-6.3: Revoked AA certificate should cause failure
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

-- | AC-REV-6.4: Expired CRL should cause failure
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

-- | AC-REV-6.6: No CRL available should return unknown
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

-- | AC-RFC-8.1: v1Form issuer should be rejected
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

-- | AC-RFC-8.2: V2Form with baseCertificateID should be rejected
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

-- | AC-RFC-8.3: V2Form with objectDigestInfo should be rejected
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

-- | AC-RFC-8.4: Serial number exceeding 20 octets should be rejected
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

-- | AC-RFC-8.5: Non-positive serial number should be rejected
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

-- | AC-RFC-8.6: Holder with all fields empty should be rejected
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

-- | AC-RFC-8.7: V2Form issuerName not single directoryName should be rejected
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

-- | AC-RFC-8.8: Valid RFC 5755 profile should pass
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
validPeriod :: (DateTime, DateTime)
validPeriod = (defaultValidityStart, defaultValidityEnd)
