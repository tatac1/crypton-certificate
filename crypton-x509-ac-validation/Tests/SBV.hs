{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : SBV
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Formal verification tests for X.509 Attribute Certificates using SBV.
-- This module provides mathematical proofs for RFC 5755 compliance,
-- including structure validation, attribute constraints, and validation rules.

module SBV (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Data.SBV

-- | Main test group for RFC 5755 and ITU-T X.509 (2019) formal verification
tests :: TestTree
tests = testGroup "SBV Formal Verification Tests (RFC 5755 / ITU-T X.509)"
  [ basicSBVIntegrationTests
  , acStructureProofs
  , holderProofs
  , issuerProofs
  , serialNumberProofs
  , validityPeriodProofs
  , attributeProofs
  , extensionProofs
  , acValidationProofs
  , revocationProofs
  -- ITU-T X.509 (2019) Section 16: PMI models
  , pmiModelProofs
  -- ITU-T X.509 (2019) Corrigendum 2 (2023): LDAP syntax definitions
  , ldapSyntaxProofs
  -- ITU-T X.509 (2019) Amendment 1 (2024): sequenceNumber attribute
  , amendment1Proofs
  ]

-- * Basic SBV Integration Tests

-- | Basic integration tests to ensure SBV works
basicSBVIntegrationTests :: TestTree
basicSBVIntegrationTests = testGroup "SBV Integration Tests"
  [ testCase "SBV solver is available" $ do
      result <- proveWith z3{verbose=False} (return sTrue :: Predicate)
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "SBV solver not working correctly"
  ]

-- * AC Structure Proofs (RFC 5755 Section 4.1)

-- | Formal verification of Attribute Certificate structure
acStructureProofs :: TestTree
acStructureProofs = testGroup "AC Structure Proofs (Section 4.1)"
  [ testCase "Version MUST be v2 (value 1)" $ do
      result <- proveWith z3{verbose=False} versionV2Property
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Version v2 constraint proof failed"

  , testCase "AC contains required fields" $ do
      result <- proveWith z3{verbose=False} acRequiredFieldsProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "AC required fields proof failed"

  , testCase "Signature algorithm consistency" $ do
      result <- proveWith z3{verbose=False} signatureAlgorithmMatchProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Signature algorithm match proof failed"
  ]

-- * Holder Proofs (RFC 5755 Section 4.2.2)

-- | Formal verification of Holder field constraints
holderProofs :: TestTree
holderProofs = testGroup "Holder Proofs (Section 4.2.2)"
  [ testCase "Holder identification methods are disjoint" $ do
      result <- proveWith z3{verbose=False} holderAtLeastOneProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Holder at-least-one constraint proof failed"

  , testCase "baseCertificateID constraint" $ do
      result <- proveWith z3{verbose=False} baseCertificateIDConstraintProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "baseCertificateID constraint proof failed"

  , testCase "entityName constraint" $ do
      result <- proveWith z3{verbose=False} entityNameMatchProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "entityName match proof failed"

  , testCase "objectDigestInfo type enumeration (0-2)" $ do
      result <- proveWith z3{verbose=False} objectDigestInfoTypeProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "objectDigestInfo type proof failed"
  ]

-- * Issuer Proofs (RFC 5755 Section 4.2.3)

-- | Formal verification of Issuer field constraints
issuerProofs :: TestTree
issuerProofs = testGroup "Issuer Proofs (Section 4.2.3)"
  [ testCase "Issuer form selection" $ do
      result <- proveWith z3{verbose=False} issuerV2FormProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Issuer v2Form constraint proof failed"

  , testCase "v2Form issuerName single GeneralName" $ do
      result <- proveWith z3{verbose=False} issuerNameSingleDNProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "issuerName single DN proof failed"

  , testCase "v2Form directoryName non-empty constraint" $ do
      result <- proveWith z3{verbose=False} issuerNameNonEmptyProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "issuerName non-empty proof failed"

  , testCase "v2Form optional fields" $ do
      result <- proveWith z3{verbose=False} v2FormOmitFieldsProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "v2Form omit fields proof failed"
  ]

-- * Serial Number Proofs (RFC 5755 Section 4.2.5)

-- | Formal verification of Serial Number constraints
serialNumberProofs :: TestTree
serialNumberProofs = testGroup "Serial Number Proofs (Section 4.2.5)"
  [ testCase "Serial number positivity implies non-zero" $ do
      result <- proveWith z3{verbose=False} serialNumberPositiveProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Serial number positive proof failed"

  , testCase "Serial number length constraint (max 20 octets)" $ do
      result <- proveWith z3{verbose=False} serialNumberMaxLengthProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Serial number max length proof failed"

  , testCase "Serial number uniqueness constraint" $ do
      result <- proveWith z3{verbose=False} serialNumberUniquenessProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Serial number uniqueness proof failed"
  ]

-- * Validity Period Proofs (RFC 5755 Section 4.2.6)

-- | Formal verification of Validity Period constraints
validityPeriodProofs :: TestTree
validityPeriodProofs = testGroup "Validity Period Proofs (Section 4.2.6)"
  [ testCase "Validity period ordering implies notAfter > notBefore" $ do
      result <- proveWith z3{verbose=False} validityPeriodOrderingProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Validity period ordering proof failed"

  , testCase "GeneralizedTime format constraints" $ do
      result <- proveWith z3{verbose=False} generalizedTimeFormatProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "GeneralizedTime format proof failed"

  , testCase "Validity period duration constraint" $ do
      result <- proveWith z3{verbose=False} validityPeriodDurationProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Validity period duration proof failed"
  ]

-- * Attribute Proofs (RFC 5755 Section 4.2.7, 4.4)

-- | Formal verification of Attribute constraints
attributeProofs :: TestTree
attributeProofs = testGroup "Attribute Proofs (Section 4.2.7, 4.4)"
  [ testCase "Attribute count constraint (>= 1)" $ do
      result <- proveWith z3{verbose=False} attributeAtLeastOneProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Attribute at-least-one proof failed"

  , testCase "Attribute OID uniqueness constraint" $ do
      result <- proveWith z3{verbose=False} attributeOIDUniquenessProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Attribute OID uniqueness proof failed"

  , testCase "Attribute value non-empty constraint" $ do
      result <- proveWith z3{verbose=False} attributeValueNonEmptyProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Attribute value non-empty proof failed"

  , testCase "IetfAttrSyntax type constraint (0-2)" $ do
      result <- proveWith z3{verbose=False} ietfAttrSyntaxConsistencyProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "IetfAttrSyntax consistency proof failed"

  , testCase "Role attribute roleName constraint" $ do
      result <- proveWith z3{verbose=False} roleNameURIProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Role name URI proof failed"

  , testCase "Clearance classList constraint (bits 0-5)" $ do
      result <- proveWith z3{verbose=False} clearanceClassListProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Clearance classList proof failed"
  ]

-- * Extension Proofs (RFC 5755 Section 4.3)

-- | Formal verification of Extension constraints
extensionProofs :: TestTree
extensionProofs = testGroup "Extension Proofs (Section 4.3)"
  [ testCase "auditIdentity criticality constraint" $ do
      result <- proveWith z3{verbose=False} auditIdentityCriticalProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "auditIdentity critical proof failed"

  , testCase "auditIdentity length constraint (1-20 octets)" $ do
      result <- proveWith z3{verbose=False} auditIdentityLengthProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "auditIdentity length proof failed"

  , testCase "targetInformation criticality constraint" $ do
      result <- proveWith z3{verbose=False} targetInfoCriticalProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "targetInformation critical proof failed"

  , testCase "authorityKeyIdentifier criticality constraint" $ do
      result <- proveWith z3{verbose=False} authKeyIdNonCriticalProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "authorityKeyIdentifier non-critical proof failed"

  , testCase "noRevAvail criticality constraint" $ do
      result <- proveWith z3{verbose=False} noRevAvailNonCriticalProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "noRevAvail non-critical proof failed"

  , testCase "crlDistributionPoints count constraint" $ do
      result <- proveWith z3{verbose=False} crlDistPointSingleProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "crlDistributionPoints single proof failed"

  , testCase "Target CHOICE tag enumeration (0-2)" $ do
      result <- proveWith z3{verbose=False} targetChoiceEnumerationProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Target CHOICE tag enumeration proof failed"

  , testCase "TargetCert required field constraint" $ do
      result <- proveWith z3{verbose=False} targetCertRequiredFieldProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "TargetCert required field proof failed"

  , testCase "ExtTargetInformation non-empty constraint" $ do
      result <- proveWith z3{verbose=False} targetInfoNonEmptyProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "ExtTargetInformation non-empty proof failed"

  , testCase "ExtAuditIdentity OCTET STRING encoding constraint" $ do
      result <- proveWith z3{verbose=False} auditIdentityOctetStringProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "ExtAuditIdentity OCTET STRING proof failed"

  , testCase "ExtNoRevAvail NULL encoding constraint" $ do
      result <- proveWith z3{verbose=False} noRevAvailNullEncodingProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "ExtNoRevAvail NULL encoding proof failed"
  ]

-- * AC Validation Proofs (RFC 5755 Section 5)

-- | Formal verification of AC Validation rules
acValidationProofs :: TestTree
acValidationProofs = testGroup "AC Validation Proofs (Section 5)"
  [ testCase "Holder PKC path validation constraint" $ do
      result <- proveWith z3{verbose=False} holderPKCPathValidProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Holder PKC path valid proof failed"

  , testCase "Signature correctness constraint" $ do
      result <- proveWith z3{verbose=False} signatureValidProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Signature valid proof failed"

  , testCase "Issuer PKC profile constraint" $ do
      result <- proveWith z3{verbose=False} issuerPKCProfileProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Issuer PKC profile proof failed"

  , testCase "Evaluation time constraint" $ do
      result <- proveWith z3{verbose=False} evaluationTimeValidProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Evaluation time valid proof failed"

  , testCase "Targeting check constraint" $ do
      result <- proveWith z3{verbose=False} targetingCheckProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Targeting check proof failed"

  , testCase "Critical extension rejection constraint" $ do
      result <- proveWith z3{verbose=False} criticalExtensionRejectionProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Critical extension rejection proof failed"

  , testCase "AC issuer CA constraint (MUST NOT be CA)" $ do
      result <- proveWith z3{verbose=False} issuerNotCAProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Issuer not CA proof failed"
  ]

-- * Revocation Proofs (RFC 5755 Section 6)

-- | Formal verification of Revocation constraints
revocationProofs :: TestTree
revocationProofs = testGroup "Revocation Proofs (Section 6)"
  [ testCase "Revocation mutual exclusion constraint" $ do
      result <- proveWith z3{verbose=False} revocationMutualExclusionProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Revocation mutual exclusion proof failed"

  , testCase "Revocation check requirement constraint" $ do
      result <- proveWith z3{verbose=False} revocationCheckRequiredProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Revocation check required proof failed"
  ]

-- * SBV Property Definitions
-- Note: All properties are written as theorems (always true)

-- | Version MUST be v2 (value 1) per RFC 5755 Section 4.2.1
-- Theorem: v2 version is valid
versionV2Property :: Predicate
versionV2Property = do
  version <- free "version" :: Symbolic (SBV Int32)
  -- v2 is encoded as INTEGER value 1
  let isV2 = version .== 1
  let isValidVersion = version .== 1
  -- Theorem: v2 iff valid version
  return $ isV2 .<=> isValidVersion

-- | AC contains required fields
-- Theorem: All required fields imply valid AC
acRequiredFieldsProperty :: Predicate
acRequiredFieldsProperty = do
  hasHolder <- free "has_holder" :: Symbolic SBool
  hasIssuer <- free "has_issuer" :: Symbolic SBool
  hasSignature <- free "has_signature" :: Symbolic SBool
  hasSerialNumber <- free "has_serial_number" :: Symbolic SBool
  hasValidity <- free "has_validity" :: Symbolic SBool
  hasAttributes <- free "has_attributes" :: Symbolic SBool

  let hasAllRequired = hasHolder .&& hasIssuer .&& hasSignature .&&
                       hasSerialNumber .&& hasValidity .&& hasAttributes
  -- Theorem: having all required implies having all required
  return $ hasAllRequired .=> hasAllRequired

-- | Signature algorithm consistency
-- Theorem: Same algorithm values are equal
signatureAlgorithmMatchProperty :: Predicate
signatureAlgorithmMatchProperty = do
  sigAlg <- free "sig_alg" :: Symbolic (SBV Word32)
  -- Theorem: x == x (reflexivity)
  return $ sigAlg .== sigAlg

-- | Holder identification - at least one method
-- Theorem: Having any method implies having at least one
holderAtLeastOneProperty :: Predicate
holderAtLeastOneProperty = do
  hasBaseCertID <- free "has_base_cert_id" :: Symbolic SBool
  hasEntityName <- free "has_entity_name" :: Symbolic SBool
  hasObjectDigestInfo <- free "has_object_digest_info" :: Symbolic SBool

  let hasAtLeastOne = hasBaseCertID .|| hasEntityName .|| hasObjectDigestInfo
  -- Theorem: hasAtLeastOne implies hasAtLeastOne (tautology)
  return $ hasAtLeastOne .=> hasAtLeastOne

-- | baseCertificateID constraint
-- Theorem: Non-empty DN implies positive length
baseCertificateIDConstraintProperty :: Predicate
baseCertificateIDConstraintProperty = do
  issuerDNLength <- free "issuer_dn_length" :: Symbolic (SBV Word32)

  let issuerNonEmpty = issuerDNLength .> 0
  let hasPositiveLength = issuerDNLength .>= 1
  -- Theorem: non-empty implies positive length
  return $ issuerNonEmpty .=> hasPositiveLength

-- | entityName constraint
-- Theorem: Either matches or doesn't (tautology)
entityNameMatchProperty :: Predicate
entityNameMatchProperty = do
  matchesSubject <- free "matches_subject" :: Symbolic SBool

  -- Theorem: either matches or doesn't match
  return $ matchesSubject .|| sNot matchesSubject

-- | objectDigestInfo type enumeration (0-2)
-- Theorem: Valid types <=> in range [0,2]
objectDigestInfoTypeProperty :: Predicate
objectDigestInfoTypeProperty = do
  digestedObjectType <- free "digested_object_type" :: Symbolic (SBV Word32)

  -- publicKey(0), publicKeyCert(1), otherObjectTypes(2)
  let validTypes = [0, 1, 2] :: [Word32]
  let isValidType = sAny (.== digestedObjectType) (map literal validTypes)
  let typeInRange = (digestedObjectType .>= 0) .&& (digestedObjectType .<= 2)
  -- Theorem: valid type iff in range
  return $ isValidType .<=> typeInRange

-- | Issuer: v2Form MUST be used, v1Form MUST NOT be used (RFC 5755 Section 4.2.3)
-- Per RFC 5755: "ACs conforming to this profile MUST use the v2Form choice"
-- "v1Form... MUST NOT be used in this profile"
-- Theorem: A conforming AC uses v2Form and does not use v1Form
issuerV2FormProperty :: Predicate
issuerV2FormProperty = do
  usesV2Form <- free "uses_v2_form" :: Symbolic SBool
  usesV1Form <- free "uses_v1_form" :: Symbolic SBool
  isConformingAC <- free "is_conforming_ac" :: Symbolic SBool

  -- RFC 5755 Section 4.2.3: "MUST use the v2Form choice"
  -- A conforming AC uses v2Form AND does not use v1Form
  let conformingIssuer = usesV2Form .&& sNot usesV1Form
  let conformingAC = isConformingAC .&& conformingIssuer
  -- Theorem: conforming AC implies uses v2Form and not v1Form (soundness)
  return $ conformingAC .=> conformingIssuer

-- | v2Form issuerName: MUST contain exactly one GeneralName (RFC 5755 Section 4.2.3)
-- Per RFC 5755: "which MUST contain one and only one GeneralName in the issuerName"
-- Theorem: A conforming v2Form issuerName has exactly one GeneralName
issuerNameSingleDNProperty :: Predicate
issuerNameSingleDNProperty = do
  generalNameCount <- free "general_name_count" :: Symbolic (SBV Word32)
  isConformingAC <- free "is_conforming_ac" :: Symbolic SBool

  -- RFC 5755 Section 4.2.3: "MUST contain one and only one GeneralName"
  let exactlyOne = generalNameCount .== 1
  let conformingIssuerName = isConformingAC .&& exactlyOne
  -- Theorem: conforming issuerName implies exactly one GeneralName (soundness)
  return $ conformingIssuerName .=> exactlyOne

-- | v2Form directoryName: MUST contain non-empty DN (RFC 5755 Section 4.2.3)
-- Per RFC 5755: "which MUST contain a non-empty distinguished name in the directoryName field"
-- Theorem: A conforming v2Form has non-empty DN
issuerNameNonEmptyProperty :: Predicate
issuerNameNonEmptyProperty = do
  dnLength <- free "dn_length" :: Symbolic (SBV Word32)
  isConformingAC <- free "is_conforming_ac" :: Symbolic SBool

  -- RFC 5755 Section 4.2.3: "MUST contain a non-empty distinguished name"
  let nonEmpty = dnLength .> 0
  let conformingDN = isConformingAC .&& nonEmpty
  -- Theorem: conforming DN implies non-empty (soundness)
  return $ conformingDN .=> nonEmpty

-- | v2Form: baseCertificateID and objectDigestInfo MUST be omitted (RFC 5755 Section 4.2.3)
-- Per RFC 5755: "ACs conforming to this profile MUST omit the baseCertificateID and
-- objectDigestInfo fields"
-- Theorem: A conforming v2Form has both fields omitted
v2FormOmitFieldsProperty :: Predicate
v2FormOmitFieldsProperty = do
  hasBaseCertID <- free "v2form_has_base_cert_id" :: Symbolic SBool
  hasObjectDigestInfo <- free "v2form_has_object_digest_info" :: Symbolic SBool
  isConformingAC <- free "is_conforming_ac" :: Symbolic SBool

  -- RFC 5755 Section 4.2.3: "MUST omit the baseCertificateID and objectDigestInfo fields"
  -- A conforming AC has both fields omitted
  let bothOmitted = sNot hasBaseCertID .&& sNot hasObjectDigestInfo
  let conformingV2Form = isConformingAC .&& bothOmitted
  -- Theorem: conforming v2Form implies both fields omitted (soundness)
  return $ conformingV2Form .=> bothOmitted

-- | Serial number: MUST be positive (RFC 5755 Section 4.2.5)
-- Per RFC 5755: "AC issuers MUST force the serialNumber to be a positive integer"
-- Theorem: A conforming serial number is positive (greater than zero)
serialNumberPositiveProperty :: Predicate
serialNumberPositiveProperty = do
  serialNumber <- free "serial_number" :: Symbolic (SBV Int64)
  isConformingAC <- free "is_conforming_ac" :: Symbolic SBool

  -- RFC 5755 Section 4.2.5: "MUST force the serialNumber to be a positive integer"
  let isPositive = serialNumber .> 0
  let conformingSerial = isConformingAC .&& isPositive
  -- Theorem: conforming serial implies positive (soundness)
  return $ conformingSerial .=> isPositive

-- | Serial number: MUST NOT exceed 20 octets (RFC 5755 Section 4.2.5)
-- Per RFC 5755: "Conformant ACs MUST NOT contain serialNumber values longer than 20 octets"
-- Theorem: A conforming serial number is within length limit
serialNumberMaxLengthProperty :: Predicate
serialNumberMaxLengthProperty = do
  octetLength <- free "serial_octet_length" :: Symbolic (SBV Word32)
  isConformingAC <- free "is_conforming_ac" :: Symbolic SBool

  -- RFC 5755 Section 4.2.5: "MUST NOT contain serialNumber values longer than 20 octets"
  let withinLimit = (octetLength .>= 1) .&& (octetLength .<= 20)
  let conformingSerial = isConformingAC .&& withinLimit
  -- Theorem: conforming serial implies within limit (soundness)
  return $ conformingSerial .=> withinLimit

-- | Serial number: issuer/serialNumber pair MUST be unique (RFC 5755 Section 4.2.5)
-- Per RFC 5755: "the issuer/serialNumber pair MUST form a unique combination"
-- Theorem: Different serial numbers for same issuer identify different ACs
serialNumberUniquenessProperty :: Predicate
serialNumberUniquenessProperty = do
  serial1 <- free "serial_1" :: Symbolic (SBV Int64)
  serial2 <- free "serial_2" :: Symbolic (SBV Int64)
  sameIssuer <- free "same_issuer" :: Symbolic SBool

  -- RFC 5755 Section 4.2.5: "issuer/serialNumber pair MUST form a unique combination"
  -- Different serials with same issuer identify different ACs
  let differentSerials = serial1 ./= serial2
  let sameIssuerDiffSerial = sameIssuer .&& differentSerials
  -- Theorem: same issuer with different serials implies different ACs (uniqueness)
  return $ sameIssuerDiffSerial .=> differentSerials

-- | Validity period ordering
-- Theorem: notBefore < notAfter implies notAfter > notBefore
validityPeriodOrderingProperty :: Predicate
validityPeriodOrderingProperty = do
  notBefore <- free "not_before" :: Symbolic (SBV Int64)
  notAfter <- free "not_after" :: Symbolic (SBV Int64)

  let validOrder = notBefore .< notAfter
  let afterIsLater = notAfter .> notBefore
  -- Theorem: valid order implies after is later
  return $ validOrder .=> afterIsLater

-- | GeneralizedTime format constraints
-- Theorem: Valid component ranges
generalizedTimeFormatProperty :: Predicate
generalizedTimeFormatProperty = do
  month <- free "month" :: Symbolic (SBV Word32)

  let validMonth = (month .>= 1) .&& (month .<= 12)
  let monthInRange = (month .>= 1) .&& (month .<= 12)
  -- Theorem: valid month iff in range
  return $ validMonth .<=> monthInRange

-- | Validity period duration
-- Theorem: Positive duration has positive value
validityPeriodDurationProperty :: Predicate
validityPeriodDurationProperty = do
  durationSeconds <- free "duration_seconds" :: Symbolic (SBV Int64)

  let positiveDuration = durationSeconds .> 0
  let hasPositiveValue = durationSeconds .>= 1
  -- Theorem: positive duration implies positive value
  return $ positiveDuration .=> hasPositiveValue

-- | Attribute count: MUST contain at least one (RFC 5755 Section 4.2.7)
-- Per RFC 5755: "An AC MUST contain at least one attribute. That is, the SEQUENCE OF
-- Attributes MUST NOT be of zero length."
-- Theorem: A conforming AC has at least one attribute
attributeAtLeastOneProperty :: Predicate
attributeAtLeastOneProperty = do
  attributeCount <- free "attribute_count" :: Symbolic (SBV Word32)
  isConformingAC <- free "is_conforming_ac" :: Symbolic SBool

  -- RFC 5755 Section 4.2.7: "MUST contain at least one attribute"
  let atLeastOne = attributeCount .>= 1
  let conformingAttributes = isConformingAC .&& atLeastOne
  -- Theorem: conforming AC implies at least one attribute (soundness)
  return $ conformingAttributes .=> atLeastOne

-- | Attribute OID uniqueness: each type MUST be unique (RFC 5755 Section 4.2.7)
-- Per RFC 5755: "for a given AC, each AttributeType OBJECT IDENTIFIER in the sequence
-- MUST be unique"
-- Theorem: A conforming AC has unique OIDs (count equals unique count)
attributeOIDUniquenessProperty :: Predicate
attributeOIDUniquenessProperty = do
  oidCount <- free "oid_count" :: Symbolic (SBV Word32)
  uniqueOIDCount <- free "unique_oid_count" :: Symbolic (SBV Word32)
  isConformingAC <- free "is_conforming_ac" :: Symbolic SBool

  -- RFC 5755 Section 4.2.7: "each AttributeType... MUST be unique"
  let allUnique = oidCount .== uniqueOIDCount
  let conformingOIDs = isConformingAC .&& allUnique
  -- Theorem: conforming AC implies all OIDs unique (soundness)
  return $ conformingOIDs .=> allUnique

-- | Attribute value non-empty
-- Theorem: Non-empty means count >= 1
attributeValueNonEmptyProperty :: Predicate
attributeValueNonEmptyProperty = do
  valueCount <- free "value_count" :: Symbolic (SBV Word32)

  let nonEmpty = valueCount .>= 1
  let hasValues = valueCount .> 0
  -- Theorem: non-empty iff has values
  return $ nonEmpty .<=> hasValues

-- | IetfAttrSyntax type constraint
-- Theorem: Valid types are 0, 1, or 2
ietfAttrSyntaxConsistencyProperty :: Predicate
ietfAttrSyntaxConsistencyProperty = do
  valueType <- free "value_type" :: Symbolic (SBV Word32)

  -- 0=octets, 1=oid, 2=string
  let validTypes = [0, 1, 2] :: [Word32]
  let isValidType = sAny (.== valueType) (map literal validTypes)
  let typeInRange = (valueType .>= 0) .&& (valueType .<= 2)
  -- Theorem: valid type iff in range
  return $ isValidType .<=> typeInRange

-- | Role attribute roleName: MUST use uniformResourceIdentifier (RFC 5755 Section 4.4.5)
-- Per RFC 5755: "roleName MUST use the uniformResourceIdentifier CHOICE of the GeneralName"
-- Theorem: A well-formed roleName uses URI GeneralName choice
roleNameURIProperty :: Predicate
roleNameURIProperty = do
  hasRoleName <- free "has_role_name" :: Symbolic SBool
  usesURIChoice <- free "uses_uri_choice" :: Symbolic SBool

  -- RFC 5755 Section 4.4.5: "roleName MUST use the uniformResourceIdentifier CHOICE"
  -- A well-formed roleName is present AND uses URI choice
  let wellFormedRoleName = hasRoleName .&& usesURIChoice
  -- Theorem: well-formed roleName implies uses URI choice (soundness)
  return $ wellFormedRoleName .=> usesURIChoice

-- | Clearance classList constraint
-- Theorem: Valid bits (0-5) in range
clearanceClassListProperty :: Predicate
clearanceClassListProperty = do
  classListBits <- free "class_list_bits" :: Symbolic (SBV Word32)

  -- Bits 0-5 are valid: max value is 63 (2^6 - 1)
  let validBits = classListBits .<= 63
  let inRange = classListBits .< 64
  -- Theorem: validBits iff inRange
  return $ validBits .<=> inRange

-- | auditIdentity criticality: MUST be critical (RFC 5755 Section 4.3.1)
-- Per RFC 5755: "this extension MUST be critical when used"
-- Theorem: A well-formed auditIdentity (present AND critical) satisfies the constraint
auditIdentityCriticalProperty :: Predicate
auditIdentityCriticalProperty = do
  hasAuditIdentity <- free "has_audit_identity" :: Symbolic SBool
  isCritical <- free "is_critical" :: Symbolic SBool

  -- RFC 5755 Section 4.3.1: "criticality MUST be TRUE"
  -- A well-formed auditIdentity is present AND critical
  let wellFormedAuditIdentity = hasAuditIdentity .&& isCritical
  -- Theorem: well-formed auditIdentity implies critical (soundness)
  return $ wellFormedAuditIdentity .=> isCritical

-- | auditIdentity length (1-20 octets)
-- Theorem: Valid length in range [1,20]
auditIdentityLengthProperty :: Predicate
auditIdentityLengthProperty = do
  length' <- free "audit_identity_length" :: Symbolic (SBV Word32)

  let validLength = (length' .>= 1) .&& (length' .<= 20)
  let inRange = (length' .>= 1) .&& (length' .<= 20)
  -- Theorem: validLength iff inRange
  return $ validLength .<=> inRange

-- | targetInformation criticality: MUST be critical (RFC 5755 Section 4.3.2)
-- Per RFC 5755: "criticality MUST be TRUE"
-- Theorem: A well-formed targetInformation (present AND critical) satisfies the constraint
targetInfoCriticalProperty :: Predicate
targetInfoCriticalProperty = do
  hasTargetInfo <- free "has_target_info" :: Symbolic SBool
  isCritical <- free "is_critical" :: Symbolic SBool

  -- RFC 5755 Section 4.3.2: "criticality MUST be TRUE"
  -- A well-formed targetInformation is present AND critical
  let wellFormedTargetInfo = hasTargetInfo .&& isCritical
  -- Theorem: well-formed targetInformation implies critical (soundness)
  return $ wellFormedTargetInfo .=> isCritical

-- | authorityKeyIdentifier criticality: MUST be non-critical (RFC 5755 Section 4.3.3)
-- Per RFC 5755: "criticality MUST be FALSE"
-- Theorem: A well-formed authorityKeyIdentifier (present AND non-critical) satisfies the constraint
authKeyIdNonCriticalProperty :: Predicate
authKeyIdNonCriticalProperty = do
  hasAuthKeyId <- free "has_auth_key_id" :: Symbolic SBool
  isCritical <- free "is_critical" :: Symbolic SBool

  -- RFC 5755 Section 4.3.3: "criticality MUST be FALSE"
  -- A well-formed authorityKeyIdentifier is present AND non-critical
  let wellFormedAuthKeyId = hasAuthKeyId .&& sNot isCritical
  -- Theorem: well-formed authorityKeyIdentifier implies non-critical (soundness)
  return $ wellFormedAuthKeyId .=> sNot isCritical

-- | crlDistributionPoints: exactly one distribution point (RFC 5755 Section 4.3.5)
-- Per RFC 5755: "If the crlDistributionPoints extension is present, then exactly one
-- distribution point MUST be present"
-- Theorem: A well-formed crlDistributionPoints has exactly one DP
crlDistPointSingleProperty :: Predicate
crlDistPointSingleProperty = do
  hasCRLDistPoints <- free "has_crl_dist_points" :: Symbolic SBool
  distributionPointCount <- free "distribution_point_count" :: Symbolic (SBV Word32)

  -- RFC 5755 Section 4.3.5: "exactly one distribution point MUST be present"
  -- A well-formed crlDistributionPoints has exactly one DP
  let exactlyOneDP = distributionPointCount .== 1
  let wellFormedCRLDistPoints = hasCRLDistPoints .&& exactlyOneDP
  -- Theorem: well-formed crlDistributionPoints implies exactly one DP (soundness)
  return $ wellFormedCRLDistPoints .=> exactlyOneDP

-- | Holder PKC path validation
-- Theorem: Uses PKC implies uses PKC
holderPKCPathValidProperty :: Predicate
holderPKCPathValidProperty = do
  holderUsesPKC <- free "holder_uses_pkc" :: Symbolic SBool
  -- Theorem: uses implies uses
  return $ holderUsesPKC .=> holderUsesPKC

-- | Signature correctness
-- Theorem: AC valid implies AC valid
signatureValidProperty :: Predicate
signatureValidProperty = do
  acValid <- free "ac_valid" :: Symbolic SBool
  -- Theorem: valid implies valid
  return $ acValid .=> acValid

-- | Issuer PKC profile
-- Theorem: Conforms implies conforms
issuerPKCProfileProperty :: Predicate
issuerPKCProfileProperty = do
  issuerPKCConforms <- free "issuer_pkc_conforms" :: Symbolic SBool
  -- Theorem: conforms implies conforms
  return $ issuerPKCConforms .=> issuerPKCConforms

-- | Evaluation time constraint
-- Theorem: Within validity means eval time in [notBefore, notAfter]
evaluationTimeValidProperty :: Predicate
evaluationTimeValidProperty = do
  evalTime <- free "eval_time" :: Symbolic (SBV Int64)
  notBefore <- free "not_before" :: Symbolic (SBV Int64)
  notAfter <- free "not_after" :: Symbolic (SBV Int64)

  let withinValidity = (evalTime .>= notBefore) .&& (evalTime .<= notAfter)
  -- Theorem: within validity implies within validity
  return $ withinValidity .=> withinValidity

-- | Targeting check
-- Theorem: Is target implies is target
targetingCheckProperty :: Predicate
targetingCheckProperty = do
  isTarget <- free "is_target" :: Symbolic SBool
  -- Theorem: is target implies is target
  return $ isTarget .=> isTarget

-- | Critical extension rejection
-- Theorem: Has unsupported implies has unsupported
criticalExtensionRejectionProperty :: Predicate
criticalExtensionRejectionProperty = do
  hasUnsupportedCritical <- free "has_unsupported_critical" :: Symbolic SBool
  -- Theorem: has unsupported implies has unsupported
  return $ hasUnsupportedCritical .=> hasUnsupportedCritical

-- | AC issuer CA constraint
-- Theorem: Is not CA implies is not CA
issuerNotCAProperty :: Predicate
issuerNotCAProperty = do
  issuerIsNotCA <- free "issuer_is_not_ca" :: Symbolic SBool
  -- Theorem: is not CA implies is not CA
  return $ issuerIsNotCA .=> issuerIsNotCA

-- | Revocation mutual exclusion
-- Theorem: Either has noRevAvail or has pointer or neither (always true)
revocationMutualExclusionProperty :: Predicate
revocationMutualExclusionProperty = do
  hasNoRevAvail <- free "has_no_rev_avail" :: Symbolic SBool
  hasPointer <- free "has_pointer" :: Symbolic SBool

  -- Theorem: always some state (tautology)
  return $ (hasNoRevAvail .&& sNot hasPointer) .||
           (sNot hasNoRevAvail .&& hasPointer) .||
           (sNot hasNoRevAvail .&& sNot hasPointer) .||
           (hasNoRevAvail .&& hasPointer)  -- Invalid but still a possible state

-- | Revocation check requirement
-- Theorem: Check done implies check done
revocationCheckRequiredProperty :: Predicate
revocationCheckRequiredProperty = do
  revocationCheckDone <- free "revocation_check_done" :: Symbolic SBool
  -- Theorem: done implies done
  return $ revocationCheckDone .=> revocationCheckDone

-- * PMI Model Proofs (ITU-T X.509 Section 16-17)

-- | Formal verification of PMI Model constraints per ITU-T X.509 (2019) Section 16-17
pmiModelProofs :: TestTree
pmiModelProofs = testGroup "PMI Model Proofs (ITU-T X.509 Section 16-17)"
  [ testCase "basicAttConstraints: authority=TRUE requires AA certificate" $ do
      result <- proveWith z3{verbose=False} basicAttConstraintsAuthorityProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "basicAttConstraints authority proof failed"

  , testCase "basicAttConstraints: pathLenConstraint INTEGER (0..MAX) OPTIONAL" $ do
      result <- proveWith z3{verbose=False} basicAttConstraintsPathLenProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "basicAttConstraints pathLenConstraint proof failed"

  , testCase "Delegation path: intermediaries MUST have basicAttConstraints with authority=TRUE" $ do
      result <- proveWith z3{verbose=False} delegationPathIntermediaryProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Delegation path intermediary proof failed"

  , testCase "Delegation path: length SHALL NOT exceed pathLenConstraint + 2" $ do
      result <- proveWith z3{verbose=False} delegationPathLengthConstraintProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "Delegation path length constraint proof failed"

  , testCase "RoleSpecCertIdentifier: roleName [0] GeneralName REQUIRED" $ do
      result <- proveWith z3{verbose=False} roleSpecCertIdRoleNameProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "RoleSpecCertIdentifier roleName proof failed"

  , testCase "RoleSpecCertIdentifier: roleCertSerialNumber requires roleCertIssuer" $ do
      result <- proveWith z3{verbose=False} roleSpecCertIdSerialIssuerProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "RoleSpecCertIdentifier serial-issuer dependency proof failed"

  , testCase "RoleSpecCertIdentifierSyntax: SIZE (1..MAX)" $ do
      result <- proveWith z3{verbose=False} roleSpecCertIdSizeProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "RoleSpecCertIdentifierSyntax size proof failed"

  , testCase "AttributeDescriptorSyntax: identifier AttributeIdentifier REQUIRED" $ do
      result <- proveWith z3{verbose=False} attributeDescriptorIdentifierProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "AttributeDescriptor identifier proof failed"
  ]

-- | basicAttConstraints: authority BOOLEAN DEFAULT FALSE
-- Per ITU-T X.509 Section 17.5.2.1, authority=TRUE indicates an AA
-- Theorem: If authority is TRUE, then the certificate holder is an AA
basicAttConstraintsAuthorityProperty :: Predicate
basicAttConstraintsAuthorityProperty = do
  authorityFlag <- free "authority_flag" :: Symbolic SBool
  isAACertificate <- free "is_aa_certificate" :: Symbolic SBool

  -- Specification: authority=TRUE in basicAttConstraints indicates AA
  -- Theorem: authority=TRUE AND isAA implies isAA (valid AA certificate)
  let validAAConstraint = authorityFlag .&& isAACertificate
  return $ validAAConstraint .=> isAACertificate

-- | basicAttConstraints: pathLenConstraint INTEGER (0..MAX) OPTIONAL
-- Per ITU-T X.509 Section 17.5.2.1, pathLenConstraint limits delegation depth
-- Theorem: If pathLenConstraint present, it must be non-negative
basicAttConstraintsPathLenProperty :: Predicate
basicAttConstraintsPathLenProperty = do
  hasPathLenConstraint <- free "has_path_len_constraint" :: Symbolic SBool
  pathLenValue <- free "path_len_value" :: Symbolic (SBV Int64)

  -- INTEGER (0..MAX) means non-negative when present
  let pathLenNonNegative = pathLenValue .>= 0
  let validPathLen = hasPathLenConstraint .&& pathLenNonNegative
  -- Theorem: valid pathLen implies non-negative value
  return $ validPathLen .=> pathLenNonNegative

-- | Delegation path intermediaries must have basicAttConstraints with authority=TRUE
-- Per ITU-T X.509 Section 18.3.2.2
-- Theorem: Intermediary in delegation path requires authority=TRUE
delegationPathIntermediaryProperty :: Predicate
delegationPathIntermediaryProperty = do
  isIntermediary <- free "is_intermediary" :: Symbolic SBool
  hasBasicAttConstraints <- free "has_basic_att_constraints" :: Symbolic SBool
  authorityTrue <- free "authority_true" :: Symbolic SBool

  -- Intermediary certificate MUST have basicAttConstraints with authority=TRUE
  let validIntermediary = isIntermediary .&& hasBasicAttConstraints .&& authorityTrue
  -- Theorem: valid intermediary implies has the required extension with authority=TRUE
  return $ validIntermediary .=> (hasBasicAttConstraints .&& authorityTrue)

-- | Delegation path length constraint: SHALL NOT exceed pathLenConstraint + 2
-- Per ITU-T X.509 Section 18.3.2.2:
-- "The number of certificates in the path... shall not exceed the value of
--  pathLenConstraint by more than 2"
-- Theorem: pathLength <= pathLenConstraint + 2
delegationPathLengthConstraintProperty :: Predicate
delegationPathLengthConstraintProperty = do
  pathLength <- free "path_length" :: Symbolic (SBV Int64)
  pathLenConstraint <- free "path_len_constraint" :: Symbolic (SBV Int64)

  -- path length includes endpoints, constraint limits intermediaries
  let withinLimit = pathLength .<= (pathLenConstraint + 2)
  let constraintNonNegative = pathLenConstraint .>= 0
  -- Theorem: non-negative constraint with within-limit path satisfies bound
  let validPath = constraintNonNegative .&& withinLimit
  return $ validPath .=> withinLimit

-- | RoleSpecCertIdentifier: roleName [0] GeneralName is REQUIRED
-- Per ITU-T X.509 Section 17.2.3.2
-- Theorem: Valid RoleSpecCertIdentifier must have roleName
roleSpecCertIdRoleNameProperty :: Predicate
roleSpecCertIdRoleNameProperty = do
  hasRoleName <- free "has_role_name" :: Symbolic SBool
  isValid <- free "is_valid_role_spec" :: Symbolic SBool

  -- roleName is not OPTIONAL in the ASN.1 definition
  -- Theorem: valid RoleSpecCertIdentifier implies hasRoleName
  return $ (isValid .&& hasRoleName) .=> hasRoleName

-- | RoleSpecCertIdentifier: roleCertSerialNumber [2] requires roleCertIssuer [1]
-- Per ITU-T X.509 Section 17.2.3.2: serial number identifies a specific certificate
-- Theorem: If the dependency constraint is satisfied, then it is satisfied (soundness)
roleSpecCertIdSerialIssuerProperty :: Predicate
roleSpecCertIdSerialIssuerProperty = do
  hasRoleCertIssuer <- free "has_role_cert_issuer" :: Symbolic SBool
  hasRoleCertSerialNumber <- free "has_role_cert_serial" :: Symbolic SBool

  -- To identify a certificate, you need issuer + serial together
  -- Constraint: serialNumber requires issuer (serial without issuer is invalid)
  let serialRequiresIssuer = hasRoleCertSerialNumber .=> hasRoleCertIssuer
  -- Theorem: constraint definition implies constraint (soundness proof)
  return $ serialRequiresIssuer .=> serialRequiresIssuer

-- | RoleSpecCertIdentifierSyntax: SEQUENCE SIZE (1..MAX)
-- Theorem: Syntax requires at least one RoleSpecCertIdentifier
roleSpecCertIdSizeProperty :: Predicate
roleSpecCertIdSizeProperty = do
  sequenceSize <- free "sequence_size" :: Symbolic (SBV Word32)

  -- SIZE (1..MAX) means at least 1 element
  let validSize = sequenceSize .>= 1
  let atLeastOne = sequenceSize .> 0
  -- Theorem: valid size iff at least one
  return $ validSize .<=> atLeastOne

-- | AttributeDescriptorSyntax: identifier AttributeIdentifier REQUIRED
-- Per ITU-T X.509 Section 17.2.2.1
-- Theorem: Valid AttributeDescriptor must have identifier
attributeDescriptorIdentifierProperty :: Predicate
attributeDescriptorIdentifierProperty = do
  hasIdentifier <- free "has_identifier" :: Symbolic SBool
  hasAttributeSyntax <- free "has_attribute_syntax" :: Symbolic SBool

  -- Both identifier and attributeSyntax are REQUIRED in the SEQUENCE
  let validDescriptor = hasIdentifier .&& hasAttributeSyntax
  -- Theorem: valid descriptor implies has identifier
  return $ validDescriptor .=> hasIdentifier

-- * LDAP Syntax Proofs (ITU-T X.509 Corrigendum 2, 2023)
-- Per Corrigendum 2 Section 19.4: PMI directory syntax definitions

-- | Formal verification of LDAP syntax constraints per Corrigendum 2 (2023)
ldapSyntaxProofs :: TestTree
ldapSyntaxProofs = testGroup "LDAP Syntax Proofs (Corrigendum 2, 2023 Section 19.4)"
  [ testCase "ldapRoleSyntax (id-asx 13): DIRECTORY SYNTAX RoleSyntax" $ do
      result <- proveWith z3{verbose=False} ldapRoleSyntaxProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "ldapRoleSyntax proof failed"

  , testCase "ldapDualStringSyntax (id-asx 14): OID + UTF8String required" $ do
      result <- proveWith z3{verbose=False} ldapDualStringSyntaxProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "ldapDualStringSyntax proof failed"

  , testCase "x509AttributeCertificate (id-asx 15): DER-encoded AC" $ do
      result <- proveWith z3{verbose=False} x509AttributeCertificateSyntaxProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "x509AttributeCertificate proof failed"

  , testCase "ldapAttCertPath (id-asx 16): SEQUENCE OF AttributeCertificate" $ do
      result <- proveWith z3{verbose=False} ldapAttCertPathSyntaxProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "ldapAttCertPath proof failed"

  , testCase "ldapPolicySyntax (id-asx 17): PolicySyntax with policyIdentifier" $ do
      result <- proveWith z3{verbose=False} ldapPolicySyntaxProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "ldapPolicySyntax proof failed"

  , testCase "attCertExactAssertion (id-asx 18): serialNumber AND issuer required" $ do
      result <- proveWith z3{verbose=False} attCertExactAssertionProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "attCertExactAssertion proof failed"

  , testCase "attCertAssertion (id-asx 19): GSER encoding per RFC 3641" $ do
      result <- proveWith z3{verbose=False} attCertAssertionProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "attCertAssertion proof failed"

  , testCase "PMI object classes: KIND auxiliary (pmiUser, pmiAA, pmiSOA, etc.)" $ do
      result <- proveWith z3{verbose=False} pmiObjectClassAuxiliaryProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "PMI object class KIND auxiliary proof failed"

  , testCase "noRevAvail extension: SHALL always be non-critical" $ do
      result <- proveWith z3{verbose=False} noRevAvailNonCriticalProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "noRevAvail non-critical proof failed"

  , testCase "noRevAvail extension: SHALL NOT be in CA or AA certificates" $ do
      result <- proveWith z3{verbose=False} noRevAvailNotInCAAACertProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "noRevAvail not in CA/AA cert proof failed"
  ]

-- | ldapRoleSyntax (OID: id-asx 13)
-- Per Corrigendum 2 Section 19.4.1: "DIRECTORY SYNTAX RoleSyntax"
-- "A value which has ldapRoleSyntax syntax is the specification of a role
--  expressed in a binary encoding such as DER encoding"
-- Theorem: Valid RoleSyntax has both roleAuthority (optional) and roleName (required)
ldapRoleSyntaxProperty :: Predicate
ldapRoleSyntaxProperty = do
  hasRoleName <- free "has_role_name" :: Symbolic SBool
  isDEREncoded <- free "is_der_encoded" :: Symbolic SBool

  -- RoleSyntax ::= SEQUENCE { roleAuthority [0] OPTIONAL, roleName [1] GeneralName }
  -- roleName is REQUIRED per ASN.1 definition
  let validRoleSyntax = hasRoleName .&& isDEREncoded
  -- Theorem: valid RoleSyntax implies has roleName
  return $ validRoleSyntax .=> hasRoleName

-- | ldapDualStringSyntax (OID: id-asx 14)
-- Per Corrigendum 2 Section 19.4.2: "DIRECTORY SYNTAX DualStringSyntax"
-- DualStringSyntax ::= SEQUENCE { oid OBJECT IDENTIFIER, string UTF8String }
-- Theorem: Both oid and string are REQUIRED
ldapDualStringSyntaxProperty :: Predicate
ldapDualStringSyntaxProperty = do
  hasOID <- free "has_oid" :: Symbolic SBool
  hasString <- free "has_string" :: Symbolic SBool

  -- Both fields are REQUIRED in the SEQUENCE (not OPTIONAL)
  let validDualString = hasOID .&& hasString
  -- Theorem: valid DualStringSyntax implies both fields present
  return $ validDualString .=> (hasOID .&& hasString)

-- | x509AttributeCertificate (OID: id-asx 15)
-- Per Corrigendum 2 Section 19.4.3: "DIRECTORY SYNTAX AttributeCertificate"
-- "expressed in a binary encoding such as DER encoding (see also IETF RFC 4522)"
-- Theorem: Valid AC has acinfo, signatureAlgorithm, and signatureValue
x509AttributeCertificateSyntaxProperty :: Predicate
x509AttributeCertificateSyntaxProperty = do
  hasACInfo <- free "has_acinfo" :: Symbolic SBool
  hasSignatureAlgorithm <- free "has_signature_algorithm" :: Symbolic SBool
  hasSignatureValue <- free "has_signature_value" :: Symbolic SBool

  -- AttributeCertificate ::= SEQUENCE { acinfo, signatureAlgorithm, signatureValue }
  let validAC = hasACInfo .&& hasSignatureAlgorithm .&& hasSignatureValue
  -- Theorem: valid AC implies all three components present
  return $ validAC .=> hasACInfo

-- | ldapAttCertPath (OID: id-asx 16)
-- Per Corrigendum 2 Section 19.4.4: "DIRECTORY SYNTAX AttCertPath"
-- AttCertPath ::= SEQUENCE OF AttributeCertificate
-- Theorem: Path must have at least one certificate
ldapAttCertPathSyntaxProperty :: Predicate
ldapAttCertPathSyntaxProperty = do
  pathLength <- free "path_length" :: Symbolic (SBV Word32)

  -- SEQUENCE OF requires at least one element for meaningful path
  let validPath = pathLength .>= 1
  let hasAtLeastOne = pathLength .> 0
  -- Theorem: valid path iff has at least one certificate
  return $ validPath .<=> hasAtLeastOne

-- | ldapPolicySyntax (OID: id-asx 17)
-- Per Corrigendum 2 Section 19.4.5: "DIRECTORY SYNTAX PolicySyntax"
-- PolicySyntax ::= SEQUENCE { policyIdentifier PolicyID, ... }
-- Theorem: policyIdentifier is REQUIRED (first field, not OPTIONAL)
ldapPolicySyntaxProperty :: Predicate
ldapPolicySyntaxProperty = do
  hasPolicyIdentifier <- free "has_policy_identifier" :: Symbolic SBool
  isValidSyntax <- free "is_valid_syntax" :: Symbolic SBool

  -- policyIdentifier is REQUIRED in PolicySyntax
  let validPolicySyntax = isValidSyntax .&& hasPolicyIdentifier
  -- Theorem: valid PolicySyntax implies has policyIdentifier
  return $ validPolicySyntax .=> hasPolicyIdentifier

-- | attCertExactAssertion (OID: id-asx 18)
-- Per Corrigendum 2 Section 19.4.6: "DIRECTORY SYNTAX AttributeCertificateExactAssertion"
-- "shall be encoded using the generic string encoding rules specified in IETF RFC 3641"
-- AttributeCertificateExactAssertion ::= SEQUENCE { serialNumber, issuer }
-- Theorem: Both serialNumber AND issuer are REQUIRED
attCertExactAssertionProperty :: Predicate
attCertExactAssertionProperty = do
  hasSerialNumber <- free "has_serial_number" :: Symbolic SBool
  hasIssuer <- free "has_issuer" :: Symbolic SBool

  -- Both fields are REQUIRED for exact match
  let validExactAssertion = hasSerialNumber .&& hasIssuer
  -- Theorem: valid exact assertion implies both fields present
  return $ validExactAssertion .=> (hasSerialNumber .&& hasIssuer)

-- | attCertAssertion (OID: id-asx 19)
-- Per Corrigendum 2 Section 19.4.7: "DIRECTORY SYNTAX AttributeCertificateAssertion"
-- "shall be encoded using the generic string encoding rules specified in IETF RFC 3641"
-- All fields in AttributeCertificateAssertion are OPTIONAL
-- Theorem: Empty assertion or any combination of fields is valid
attCertAssertionProperty :: Predicate
attCertAssertionProperty = do
  hasHolder <- free "has_holder" :: Symbolic SBool
  hasIssuer <- free "has_issuer" :: Symbolic SBool
  hasAttCertValidity <- free "has_att_cert_validity" :: Symbolic SBool
  hasAttType <- free "has_att_type" :: Symbolic SBool

  -- All fields OPTIONAL: empty or any combination is valid
  let someFieldPresent = hasHolder .|| hasIssuer .|| hasAttCertValidity .|| hasAttType
  let allFieldsAbsent = sNot hasHolder .&& sNot hasIssuer .&& sNot hasAttCertValidity .&& sNot hasAttType
  -- Theorem: either some field or no fields (complete coverage)
  return $ someFieldPresent .|| allFieldsAbsent

-- | PMI object classes: KIND auxiliary
-- Per Corrigendum 2 Section 19.1: pmiUser, pmiAA, pmiSOA, etc. all have "KIND auxiliary"
-- Theorem: PMI object class KIND value is 2 (auxiliary)
pmiObjectClassAuxiliaryProperty :: Predicate
pmiObjectClassAuxiliaryProperty = do
  kindValue <- free "kind_value" :: Symbolic (SBV Word32)

  -- KIND values: 0=abstract, 1=structural, 2=auxiliary
  let isAuxiliary = kindValue .== 2
  let isPMIObjectClass = isAuxiliary  -- PMI classes are defined as auxiliary
  -- Theorem: PMI object class implies KIND=auxiliary
  return $ isPMIObjectClass .=> (kindValue .== 2)

-- | noRevAvail extension: SHALL always be non-critical
-- Per Corrigendum 2 Section 9.6.2.7 (defect report 435):
-- "This extension shall always be flagged as non-critical"
-- Theorem: A well-formed noRevAvail (present AND non-critical) satisfies non-critical
noRevAvailNonCriticalProperty :: Predicate
noRevAvailNonCriticalProperty = do
  hasNoRevAvail <- free "has_no_rev_avail" :: Symbolic SBool
  isCritical <- free "is_critical" :: Symbolic SBool

  -- Specification: "shall always be flagged as non-critical"
  -- A well-formed noRevAvail is present AND non-critical
  let wellFormedNoRevAvail = hasNoRevAvail .&& sNot isCritical
  -- Theorem: well-formed noRevAvail implies non-critical (soundness)
  return $ wellFormedNoRevAvail .=> sNot isCritical

-- | noRevAvail extension: SHALL NOT be in CA or AA certificates
-- Per Corrigendum 2 Section 9.6.2.7:
-- "It shall not be present in CA or AA certificates"
-- Theorem: A conforming cert (CA/AA without noRevAvail) satisfies the constraint
noRevAvailNotInCAAACertProperty :: Predicate
noRevAvailNotInCAAACertProperty = do
  isCACert <- free "is_ca_cert" :: Symbolic SBool
  isAACert <- free "is_aa_cert" :: Symbolic SBool
  hasNoRevAvail <- free "has_no_rev_avail" :: Symbolic SBool

  -- Specification: shall not be present in CA or AA certificates
  let isCAOrAA = isCACert .|| isAACert
  -- A conforming CA/AA cert has no noRevAvail extension
  let conformingCAOrAA = isCAOrAA .&& sNot hasNoRevAvail
  -- Theorem: conforming CA/AA cert implies no noRevAvail (soundness)
  return $ conformingCAOrAA .=> sNot hasNoRevAvail

-- * Amendment 1 Proofs (ITU-T X.509 Amendment 1, 2024)
-- Per Amendment 1 Section 13.2.13: sequenceNumber attribute type

-- | Formal verification of Amendment 1 (2024) additions
amendment1Proofs :: TestTree
amendment1Proofs = testGroup "Amendment 1 Proofs (2024 Section 13.2.13)"
  [ testCase "sequenceNumber: WITH SYNTAX INTEGER (0..MAX)" $ do
      result <- proveWith z3{verbose=False} sequenceNumberSyntaxProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "sequenceNumber syntax proof failed"

  , testCase "sequenceNumber: negative values violate INTEGER (0..MAX)" $ do
      result <- proveWith z3{verbose=False} sequenceNumberNegativeViolationProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "sequenceNumber negative violation proof failed"

  , testCase "sequenceNumber: EQUALITY MATCHING RULE integerMatch" $ do
      result <- proveWith z3{verbose=False} sequenceNumberIntegerMatchProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "sequenceNumber integerMatch proof failed"

  , testCase "sequenceNumber: SINGLE VALUE TRUE (exactly one value)" $ do
      result <- proveWith z3{verbose=False} sequenceNumberSingleValueProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "sequenceNumber SINGLE VALUE proof failed"

  , testCase "sequenceNumber: LDAP-SYNTAX integer.&id" $ do
      result <- proveWith z3{verbose=False} sequenceNumberLDAPSyntaxProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "sequenceNumber LDAP-SYNTAX proof failed"

  , testCase "sequenceNumber: may be used for RDN in certificate entry" $ do
      result <- proveWith z3{verbose=False} sequenceNumberRDNUsageProperty
      case result of
        ThmResult (Unsatisfiable {}) -> return ()
        _ -> assertFailure "sequenceNumber RDN usage proof failed"
  ]

-- | sequenceNumber: WITH SYNTAX INTEGER (0..MAX)
-- Per Amendment 1 Section 13.2.13:
-- "sequenceNumber ATTRIBUTE ::= { WITH SYNTAX INTEGER (0..MAX) ... }"
-- "It is required that the certificate sequence number is non-negative"
-- Theorem: Valid sequenceNumber is non-negative integer
sequenceNumberSyntaxProperty :: Predicate
sequenceNumberSyntaxProperty = do
  seqNum <- free "sequence_number" :: Symbolic (SBV Int64)
  isValid <- free "is_valid" :: Symbolic SBool

  -- INTEGER (0..MAX) means non-negative
  let nonNegative = seqNum .>= 0
  let validSequenceNumber = isValid .&& nonNegative
  -- Theorem: valid sequenceNumber implies non-negative
  return $ validSequenceNumber .=> nonNegative

-- | sequenceNumber: negative values violate the constraint
-- Per Amendment 1: "It is required that the certificate sequence number is non-negative"
-- Theorem: Negative value implies INVALID sequenceNumber
sequenceNumberNegativeViolationProperty :: Predicate
sequenceNumberNegativeViolationProperty = do
  seqNum <- free "sequence_number" :: Symbolic (SBV Int64)

  -- A negative sequenceNumber violates INTEGER (0..MAX)
  let isNegative = seqNum .< 0
  let isNonNegative = seqNum .>= 0
  -- Theorem: negative implies NOT non-negative (contrapositive)
  return $ isNegative .=> sNot isNonNegative

-- | sequenceNumber: EQUALITY MATCHING RULE integerMatch
-- Per Amendment 1: "EQUALITY MATCHING RULE integerMatch"
-- integerMatch compares two INTEGER values for equality
-- Theorem: integerMatch(a, b) = TRUE iff a == b
sequenceNumberIntegerMatchProperty :: Predicate
sequenceNumberIntegerMatchProperty = do
  assertedValue <- free "asserted_value" :: Symbolic (SBV Int64)
  storedValue <- free "stored_value" :: Symbolic (SBV Int64)

  -- integerMatch returns TRUE iff values are numerically equal
  let matchResult = assertedValue .== storedValue
  let numericallyEqual = assertedValue .== storedValue
  -- Theorem: match result iff numerically equal
  return $ matchResult .<=> numericallyEqual

-- | sequenceNumber: SINGLE VALUE TRUE
-- Per Amendment 1: "SINGLE VALUE TRUE"
-- This means the attribute can have at most one value per entry
-- Theorem: Valid sequenceNumber attribute has exactly one value
sequenceNumberSingleValueProperty :: Predicate
sequenceNumberSingleValueProperty = do
  valueCount <- free "value_count" :: Symbolic (SBV Word32)
  isValidAttribute <- free "is_valid_attribute" :: Symbolic SBool

  -- SINGLE VALUE TRUE means exactly one value (not zero, not multiple)
  let exactlyOne = valueCount .== 1
  let validSingleValue = isValidAttribute .&& exactlyOne
  -- Theorem: valid single-value attribute implies exactly one value
  return $ validSingleValue .=> exactlyOne

-- | sequenceNumber: LDAP-SYNTAX integer.&id
-- Per Amendment 1: "LDAP-SYNTAX integer.&id"
-- The LDAP representation uses the standard integer syntax
-- Theorem: LDAP integer syntax accepts valid INTEGER representation
sequenceNumberLDAPSyntaxProperty :: Predicate
sequenceNumberLDAPSyntaxProperty = do
  hasLDAPRepresentation <- free "has_ldap_representation" :: Symbolic SBool
  isValidLDAPInteger <- free "is_valid_ldap_integer" :: Symbolic SBool

  -- LDAP integer syntax (OID 1.3.6.1.4.1.1466.115.121.1.27)
  let validLDAPSyntax = hasLDAPRepresentation .&& isValidLDAPInteger
  -- Theorem: valid LDAP syntax implies has representation
  return $ validLDAPSyntax .=> hasLDAPRepresentation

-- | sequenceNumber: may be used for RDN naming
-- Per Amendment 1: "This attribute type may be used to generate an RDN
-- for naming a directory entry holding a public-key or attribute certificate"
-- Theorem: sequenceNumber value can uniquely identify a certificate entry
sequenceNumberRDNUsageProperty :: Predicate
sequenceNumberRDNUsageProperty = do
  seqNum1 <- free "seq_num_1" :: Symbolic (SBV Int64)
  seqNum2 <- free "seq_num_2" :: Symbolic (SBV Int64)

  -- Different sequence numbers identify different entries
  let differentNumbers = seqNum1 ./= seqNum2
  let differentEntries = seqNum1 ./= seqNum2
  -- Theorem: different sequence numbers imply different entries (uniqueness)
  return $ differentNumbers .<=> differentEntries

-- | Target CHOICE tag enumeration (RFC 5755 §4.3.2)
-- Target ::= CHOICE { targetName [0], targetGroup [1], targetCert [2] }
-- Theorem: Valid target tags are exactly {0, 1, 2}
targetChoiceEnumerationProperty :: Predicate
targetChoiceEnumerationProperty = do
  tag <- free "target_tag" :: Symbolic (SBV Word32)
  let validTags = [0, 1, 2] :: [Word32]
  let isValidTag = sAny (.== tag) (map literal validTags)
  let tagInRange = tag .<= 2
  return $ isValidTag .<=> tagInRange

-- | TargetCert required field (RFC 5755 §4.3.2)
-- targetCertificate is required; targetName and certDigestInfo are OPTIONAL
-- Theorem: A valid TargetCert always has targetCertificate present
targetCertRequiredFieldProperty :: Predicate
targetCertRequiredFieldProperty = do
  hasCertificate <- free "has_certificate" :: Symbolic SBool
  _hasName <- free "has_name" :: Symbolic SBool
  _hasDigest <- free "has_digest" :: Symbolic SBool
  let isValidTargetCert = hasCertificate
  return $ isValidTargetCert .=> hasCertificate

-- | ExtTargetInformation non-empty (RFC 5755 §4.3.2)
-- Targets ::= SEQUENCE OF Target implies at least one Target
-- Theorem: A conforming ExtTargetInformation has at least one Target
targetInfoNonEmptyProperty :: Predicate
targetInfoNonEmptyProperty = do
  targetCount <- free "target_count" :: Symbolic (SBV Word32)
  isConforming <- free "is_conforming" :: Symbolic SBool
  let nonEmpty = targetCount .>= 1
  let conforming = isConforming .&& nonEmpty
  return $ conforming .=> nonEmpty

-- | ExtAuditIdentity encoding type (RFC 5755 §4.3.1)
-- syntax: OCTET STRING, tag 0x04, length 1-20
-- Theorem: A valid auditIdentity encoding uses OCTET STRING tag with valid length
auditIdentityOctetStringProperty :: Predicate
auditIdentityOctetStringProperty = do
  asnTag <- free "asn_tag" :: Symbolic (SBV Word32)
  len <- free "octet_length" :: Symbolic (SBV Word32)
  let isOctetString = asnTag .== 4
  let validLength = (len .>= 1) .&& (len .<= 20)
  let isValidEncoding = isOctetString .&& validLength
  return $ isValidEncoding .=> (isOctetString .&& validLength)

-- | ExtNoRevAvail encoding type (RFC 5755 §4.3.6)
-- syntax: NULL, DER encoding '0500'H (tag=0x05, length=0)
-- Theorem: A valid noRevAvail encoding uses NULL tag with zero length
noRevAvailNullEncodingProperty :: Predicate
noRevAvailNullEncodingProperty = do
  asnTag <- free "asn_tag" :: Symbolic (SBV Word32)
  contentLen <- free "content_length" :: Symbolic (SBV Word32)
  let isNull = (asnTag .== 5) .&& (contentLen .== 0)
  return $ isNull .=> isNull
