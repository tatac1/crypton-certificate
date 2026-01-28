{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TestACValidation where

import Control.Monad
import Data.ASN1.BitArray
import Data.ASN1.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Hourglass
import Data.List (nub)
import Data.X509
import Data.X509.AC.Validation
import Data.X509.AttCert
import Data.X509.Attribute
import Test.Tasty
import Test.Tasty.QuickCheck

-- | Helper for generating arbitrary ByteStrings
arbitraryBS :: Int -> Int -> Gen B.ByteString
arbitraryBS r1 r2 = choose (r1, r2) >>= \l -> (B.pack <$> replicateM l arbitrary)

-- | Generate a non-empty list
listOf1NonEmpty :: Gen a -> Gen [a]
listOf1NonEmpty = listOf1

-- Arbitrary instances for common types

instance Arbitrary AltName where
  arbitrary = do
    printable <- getASCIIString <$> arbitrary
    oneof
      [ pure $ AltNameRFC822 printable,
        pure $ AltNameDNS printable,
        pure $ AltNameURI printable,
        AltNameIP <$> arbitraryBS 4 4,
        pure $ AltNameXMPP printable,
        pure $ AltNameDNSSRV printable,
        AltDirectoryName <$> arbitrary
      ]

instance Arbitrary DistinguishedName where
  arbitrary = do
    cn <- getASCIIString <$> arbitrary
    let rdn = (getObjectID DnCommonName, ASN1CharacterString UTF8 (BC.pack cn))
    return $ DistinguishedName [rdn]

-- Generate a DateTime within a reasonable range
genReasonableDateTime :: Gen DateTime
genReasonableDateTime = do
  year <- choose (1970, 2070)
  month <- elements [January .. December]
  day <- choose (1, 28)
  hour <- choose (0, 23)
  minute <- choose (0, 59)
  second <- choose (0, 59)
  let tod = TimeOfDay (Hours hour) (Minutes minute) (Seconds second) (NanoSeconds 0)
  return $ DateTime (Date year month day) tod

genValidity :: Gen AttCertValidityPeriod
genValidity = do
  start <- genReasonableDateTime
  duration <- choose (1, 315576000)
  let end = timeAdd start (Seconds duration)
  return $ AttCertValidityPeriod start end

instance Arbitrary AttCertValidityPeriod where
  arbitrary = genValidity

instance Arbitrary DigestedObjectType where
  arbitrary = elements [OIDPublicKey, OIDPublicKeyCert, OIDOtherObjectTypes]

instance Arbitrary SignatureALG where
  arbitrary =
    elements
      [ SignatureALG HashSHA1 PubKeyALG_RSA,
        SignatureALG HashMD5 PubKeyALG_RSA,
        SignatureALG HashSHA256 PubKeyALG_RSA,
        SignatureALG HashSHA384 PubKeyALG_RSA,
        SignatureALG HashSHA512 PubKeyALG_RSA
      ]

instance Arbitrary ObjectDigestInfo where
  arbitrary = do
    dot <- arbitrary
    moid <- case dot of
      OIDOtherObjectTypes -> Just <$> arbitrary
      _ -> pure Nothing
    ObjectDigestInfo dot moid <$> arbitrary <*> arbitraryBS 16 32

genMaybeUniqueID :: Gen (Maybe UniqueID)
genMaybeUniqueID = do
  hasUID <- arbitrary
  if hasUID
    then Just <$> (toBitArray <$> arbitraryBS 1 8 <*> pure 0)
    else pure Nothing

instance Arbitrary IssuerSerial where
  arbitrary = IssuerSerial
    <$> listOf1NonEmpty arbitrary
    <*> (getPositive <$> arbitrary)
    <*> genMaybeUniqueID

genMaybeGeneralNames :: Gen (Maybe [AltName])
genMaybeGeneralNames = do
  hasNames <- arbitrary
  if hasNames
    then Just <$> listOf1NonEmpty arbitrary
    else pure Nothing

instance Arbitrary Holder where
  arbitrary = do
    mBaseCertID <- arbitrary
    mEntityName <- genMaybeGeneralNames
    mObjDigestInfo <- arbitrary
    if all isNothing [fmap (const ()) mBaseCertID, fmap (const ()) mEntityName, fmap (const ()) mObjDigestInfo]
      then oneof
        [ Holder <$> (Just <$> arbitrary) <*> pure Nothing <*> pure Nothing,
          Holder <$> pure Nothing <*> (Just <$> listOf1NonEmpty arbitrary) <*> pure Nothing,
          Holder <$> pure Nothing <*> pure Nothing <*> (Just <$> arbitrary)
        ]
      else pure $ Holder mBaseCertID mEntityName mObjDigestInfo
    where
      isNothing Nothing = True
      isNothing _ = False

genV2FormIssuerName :: Gen [AltName]
genV2FormIssuerName = do
  dn <- suchThat arbitrary (\(DistinguishedName l) -> not (null l))
  return [AltDirectoryName dn]

instance Arbitrary V2Form where
  arbitrary = V2Form
    <$> genV2FormIssuerName
    <*> arbitrary
    <*> arbitrary

instance Arbitrary AttCertIssuer where
  arbitrary = AttCertIssuerV2 <$> arbitrary

instance Arbitrary RoleSyntax where
  arbitrary = (RoleSyntax . Just <$> listOf1NonEmpty arbitrary) <*> arbitrary

instance Arbitrary Attr_Role where
  arbitrary = Attr_Role <$> arbitrary

instance Arbitrary ClassListFlag where
  arbitrary = elements [ClassList_unmarked .. ClassList_topSecret]

instance Arbitrary Attributes where
  arbitrary = return $ Attributes []

-- Test Tree

tests :: TestTree
tests =
  testGroup
    "AC Validation Tests"
    [ testGroup
        "RFC 5755 Profile Validation"
        [ testProperty "v1Form is rejected" prop_v1Form_rejected,
          testProperty "v2Form with valid issuerName passes" prop_v2Form_valid_issuerName_passes,
          testProperty "serial number validation" prop_serial_number_validation,
          testProperty "holder with at least one field passes" prop_holder_with_field_passes,
          testProperty "holder with all fields empty fails" prop_holder_empty_fails,
          testProperty "v2Form baseCertificateID present fails" prop_v2Form_baseCertID_fails,
          testProperty "v2Form objectDigestInfo present fails" prop_v2Form_objDigest_fails,
          testProperty "unknown critical extension is rejected" prop_unknown_critical_ext_rejected,
          testProperty "known critical extension passes" prop_known_critical_ext_passes,
          testProperty "non-critical unknown extension passes" prop_noncritical_unknown_ext_passes,
          testProperty "role with URI name passes" prop_role_uri_passes,
          testProperty "role with non-URI name produces warning" prop_role_nonuri_warns,
          testProperty "MD5 signature is rejected" prop_md5_rejected,
          testProperty "SHA1 signature produces warning" prop_sha1_warning,
          testProperty "SHA256 signature passes" prop_sha256_passes
        ]
    ]

-- Validation Properties

makeTestACI :: Holder -> AttCertIssuer -> Integer -> AttributeCertificateInfo
makeTestACI holder issuer sn = AttributeCertificateInfo
  { aciVersion = 1
  , aciHolder = holder
  , aciIssuer = issuer
  , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
  , aciSerialNumber = sn
  , aciValidity = AttCertValidityPeriod
      (DateTime (Date 2020 January 1) (TimeOfDay 0 0 0 0))
      (DateTime (Date 2025 January 1) (TimeOfDay 0 0 0 0))
  , aciAttributes = Attributes []
  , aciIssuerUniqueID = Nothing
  , aciExtensions = Extensions Nothing
  }

genValidV2FormIssuer :: Gen AttCertIssuer
genValidV2FormIssuer = do
  dn <- suchThat arbitrary (\(DistinguishedName l) -> not (null l))
  let v2 = V2Form [AltDirectoryName dn] Nothing Nothing
  return $ AttCertIssuerV2 v2

genValidHolder :: Gen Holder
genValidHolder = do
  is <- arbitrary
  return $ Holder (Just is) Nothing Nothing

prop_v1Form_rejected :: Property
prop_v1Form_rejected = forAll (listOf1NonEmpty arbitrary) $ \gns -> do
  let issuer = AttCertIssuerV1 gns
  let holder = Holder (Just $ IssuerSerial [AltNameDNS "test"] 1 Nothing) Nothing Nothing
  let aci = makeTestACI holder issuer 1
  let result = validateRFC5755Profile aci
  V1FormNotAllowed `elem` vrErrors result

prop_v2Form_valid_issuerName_passes :: Property
prop_v2Form_valid_issuerName_passes = forAll genValidV2FormIssuer $ \issuer ->
  forAll genValidHolder $ \holder -> do
    let aci = makeTestACI holder issuer 1
    let result = validateRFC5755Profile aci
    not (V1FormNotAllowed `elem` vrErrors result)
      && not (any isIssuerNameError (vrErrors result))
  where
    isIssuerNameError (IssuerNameNotSingleDirectoryName _) = True
    isIssuerNameError IssuerDirectoryNameEmpty = True
    isIssuerNameError _ = False

prop_serial_number_validation :: Positive Integer -> Property
prop_serial_number_validation (Positive sn) =
  forAll genValidV2FormIssuer $ \issuer ->
    forAll genValidHolder $ \holder -> do
      let aci = makeTestACI holder issuer sn
      let result = validateRFC5755Profile aci
      not (SerialNumberNotPositive sn `elem` vrErrors result)

prop_holder_with_field_passes :: Property
prop_holder_with_field_passes = forAll genValidHolder $ \holder ->
  forAll genValidV2FormIssuer $ \issuer -> do
    let aci = makeTestACI holder issuer 1
    let result = validateRFC5755Profile aci
    not (HolderMissingAllFields `elem` vrErrors result)

prop_holder_empty_fails :: Property
prop_holder_empty_fails = forAll genValidV2FormIssuer $ \issuer -> do
  let holder = Holder Nothing Nothing Nothing
  let aci = makeTestACI holder issuer 1
  let result = validateRFC5755Profile aci
  HolderMissingAllFields `elem` vrErrors result

prop_v2Form_baseCertID_fails :: Property
prop_v2Form_baseCertID_fails =
  forAll arbitrary $ \is ->
    forAll (suchThat arbitrary (\(DistinguishedName l) -> not (null l))) $ \dn ->
      forAll genValidHolder $ \holder -> do
        let v2 = V2Form [AltDirectoryName dn] (Just is) Nothing
        let issuer = AttCertIssuerV2 v2
        let aci = makeTestACI holder issuer 1
        let result = validateRFC5755Profile aci
        V2FormBaseCertificateIDPresent `elem` vrErrors result

prop_v2Form_objDigest_fails :: Property
prop_v2Form_objDigest_fails =
  forAll arbitrary $ \odi ->
    forAll (suchThat arbitrary (\(DistinguishedName l) -> not (null l))) $ \dn ->
      forAll genValidHolder $ \holder -> do
        let v2 = V2Form [AltDirectoryName dn] Nothing (Just odi)
        let issuer = AttCertIssuerV2 v2
        let aci = makeTestACI holder issuer 1
        let result = validateRFC5755Profile aci
        V2FormObjectDigestInfoPresent `elem` vrErrors result

-- Critical Extension Validation Properties

makeTestExtension :: OID -> Bool -> ExtensionRaw
makeTestExtension oid critical = ExtensionRaw oid critical B.empty

makeTestACIWithExtensions :: [ExtensionRaw] -> AttributeCertificateInfo
makeTestACIWithExtensions exts =
  let holder = Holder (Just $ IssuerSerial [AltNameDNS "test"] 1 Nothing) Nothing Nothing
      dn = DistinguishedName [(getObjectID DnCommonName, ASN1CharacterString UTF8 "Test Issuer")]
      issuer = AttCertIssuerV2 $ V2Form [AltDirectoryName dn] Nothing Nothing
  in AttributeCertificateInfo
       { aciVersion = 1
       , aciHolder = holder
       , aciIssuer = issuer
       , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
       , aciSerialNumber = 1
       , aciValidity = AttCertValidityPeriod
           (DateTime (Date 2020 January 1) (TimeOfDay 0 0 0 0))
           (DateTime (Date 2025 January 1) (TimeOfDay 0 0 0 0))
       , aciAttributes = Attributes []
       , aciIssuerUniqueID = Nothing
       , aciExtensions = Extensions (Just exts)
       }

prop_unknown_critical_ext_rejected :: Property
prop_unknown_critical_ext_rejected = property $ do
  let unknownOID = [1, 2, 3, 4, 5, 6, 7, 8, 9]
  let ext = makeTestExtension unknownOID True
  let aci = makeTestACIWithExtensions [ext]
  let result = validateRFC5755Profile aci
  UnknownCriticalExtension unknownOID `elem` vrErrors result

prop_known_critical_ext_passes :: Property
prop_known_critical_ext_passes = property $ do
  let knownOID = [2, 5, 29, 35]
  let ext = makeTestExtension knownOID True
  let aci = makeTestACIWithExtensions [ext]
  let result = validateRFC5755Profile aci
  not $ any isUnknownCriticalExtError (vrErrors result)
  where
    isUnknownCriticalExtError (UnknownCriticalExtension _) = True
    isUnknownCriticalExtError _ = False

prop_noncritical_unknown_ext_passes :: Property
prop_noncritical_unknown_ext_passes = property $ do
  let unknownOID = [1, 2, 3, 4, 5, 6, 7, 8, 9]
  let ext = makeTestExtension unknownOID False
  let aci = makeTestACIWithExtensions [ext]
  let result = validateRFC5755Profile aci
  not $ any isUnknownCriticalExtError (vrErrors result)
  where
    isUnknownCriticalExtError (UnknownCriticalExtension _) = True
    isUnknownCriticalExtError _ = False

-- Role Attribute Validation Properties

makeTestACIWithAttributes :: Attributes -> AttributeCertificateInfo
makeTestACIWithAttributes attrs =
  let holder = Holder (Just $ IssuerSerial [AltNameDNS "test"] 1 Nothing) Nothing Nothing
      dn = DistinguishedName [(getObjectID DnCommonName, ASN1CharacterString UTF8 "Test Issuer")]
      issuer' = AttCertIssuerV2 $ V2Form [AltDirectoryName dn] Nothing Nothing
  in AttributeCertificateInfo
       { aciVersion = 1
       , aciHolder = holder
       , aciIssuer = issuer'
       , aciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
       , aciSerialNumber = 1
       , aciValidity = AttCertValidityPeriod
           (DateTime (Date 2020 January 1) (TimeOfDay 0 0 0 0))
           (DateTime (Date 2025 January 1) (TimeOfDay 0 0 0 0))
       , aciAttributes = attrs
       , aciIssuerUniqueID = Nothing
       , aciExtensions = Extensions Nothing
       }

prop_role_uri_passes :: Property
prop_role_uri_passes = property $ do
  let roleAttr = Attr_Role $ RoleSyntax Nothing (AltNameURI "http://example.com/role/admin")
  let attrs = Attributes [encodeAttribute [roleAttr]]
  let aci = makeTestACIWithAttributes attrs
  let result = validateRFC5755Profile aci
  not (RoleNameNotURI `elem` vrWarnings result)

prop_role_nonuri_warns :: Property
prop_role_nonuri_warns = property $ do
  let roleAttr = Attr_Role $ RoleSyntax Nothing (AltNameDNS "admin.example.com")
  let attrs = Attributes [encodeAttribute [roleAttr]]
  let aci = makeTestACIWithAttributes attrs
  let result = validateRFC5755Profile aci
  RoleNameNotURI `elem` vrWarnings result

-- Signature Algorithm Validation Properties

makeTestACIWithSigAlg :: SignatureALG -> AttributeCertificateInfo
makeTestACIWithSigAlg sigAlg =
  let holder = Holder (Just $ IssuerSerial [AltNameDNS "test"] 1 Nothing) Nothing Nothing
      dn = DistinguishedName [(getObjectID DnCommonName, ASN1CharacterString UTF8 "Test Issuer")]
      issuer' = AttCertIssuerV2 $ V2Form [AltDirectoryName dn] Nothing Nothing
  in AttributeCertificateInfo
       { aciVersion = 1
       , aciHolder = holder
       , aciIssuer = issuer'
       , aciSignature = sigAlg
       , aciSerialNumber = 1
       , aciValidity = AttCertValidityPeriod
           (DateTime (Date 2020 January 1) (TimeOfDay 0 0 0 0))
           (DateTime (Date 2025 January 1) (TimeOfDay 0 0 0 0))
       , aciAttributes = Attributes []
       , aciIssuerUniqueID = Nothing
       , aciExtensions = Extensions Nothing
       }

prop_md5_rejected :: Property
prop_md5_rejected = property $ do
  let aci = makeTestACIWithSigAlg (SignatureALG HashMD5 PubKeyALG_RSA)
  let result = validateRFC5755Profile aci
  WeakSignatureAlgorithm "MD5" `elem` vrErrors result

prop_sha1_warning :: Property
prop_sha1_warning = property $ do
  let aci = makeTestACIWithSigAlg (SignatureALG HashSHA1 PubKeyALG_RSA)
  let result = validateRFC5755Profile aci
  DeprecatedSignatureAlgorithm "SHA1" `elem` vrWarnings result

prop_sha256_passes :: Property
prop_sha256_passes = property $ do
  let aci = makeTestACIWithSigAlg (SignatureALG HashSHA256 PubKeyALG_RSA)
  let result = validateRFC5755Profile aci
  not (any isWeakSigAlgError (vrErrors result))
    && not (any isDeprecatedSigAlgWarning (vrWarnings result))
  where
    isWeakSigAlgError (WeakSignatureAlgorithm _) = True
    isWeakSigAlgError _ = False
    isDeprecatedSigAlgWarning (DeprecatedSignatureAlgorithm _) = True
    isDeprecatedSigAlgWarning _ = False
